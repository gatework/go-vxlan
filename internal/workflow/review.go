package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/gatework/go-netops/assess"
	vxlan "github.com/gatework/go-vxlan"
	changepkg "github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/configuration"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/report"
	"github.com/gatework/go-vxlan/rules"
)

// PlanSchemaVersion is the version of plan.json written by review.
const PlanSchemaVersion = 3

// Queries is the selected profile's command catalog: collection commands by
// dimension and review-only verification commands by scope.
type Queries interface {
	Command(string) string
	VerificationCommands(scope string) []string
}

// ReviewOptions binds checked evidence and a command catalog to a review run.
type ReviewOptions struct {
	Sources []report.Source
	Policy  vxlan.Record
	// Rules tunes the risk assessment; the zero value runs every rule with
	// its defaults.
	Rules assess.Policy
	// Baseline is the frozen intent to report drift from; nil skips it.
	Baseline *fabric.Baseline
	// Previous are the sources of an earlier batch to report changes from.
	Previous            []report.Source
	Queries             Queries
	Scripts, Standalone bool
}

// Review assesses the sources, derives executable increments and publishes
// assessment.json, plan.json, per-device reports, candidate scripts and the
// summary. It never contacts devices.
func Review(ctx context.Context, r *report.Report, options ReviewOptions) (vxlan.Record, error) {
	sources, policy, scripts, standalone := options.Sources, options.Policy, options.Scripts, options.Standalone
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	assessment, model, err := assessSources(ctx, sources, policy, options)
	if err != nil {
		return nil, err
	}
	increments := map[string][]rules.Increment{}
	if options.Queries != nil {
		for _, f := range model.Fabrics {
			for _, inc := range rules.Increments(f, options.Queries) {
				increments[inc.Host] = append(increments[inc.Host], inc)
			}
		}
	}
	entries, events := []any{}, []string{}
	changes := vxlan.Record{}
	for _, src := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		device := record.Map(src.Document["device"])
		host := record.String(device["host"])
		sourceHash := fmt.Sprintf("%x", sha256.Sum256(src.Body))
		name := report.Basename(device)
		findings := deviceFindings(assessment, host)
		entry := vxlan.Record{"device": device, "counts": severityCounts(findings), "basename": name, "report": "devices/" + name + ".txt",
			"source": src.Path, "source_sha256": sourceHash, "script": nil, "script_sha256": nil, "plans": []string{}}
		var planned []plannedIncrement
		if config := configuration.CompleteConfig(src.Document); scripts && config != nil {
			expected, err := vxlan.Fingerprint(config)
			if err != nil {
				return nil, err
			}
			for _, inc := range increments[host] {
				id, item, err := planItem(name, device, expected, src.Path, sourceHash, inc)
				if err != nil {
					return nil, err
				}
				changes[id] = item
				entry["plans"] = append(record.Texts(entry["plans"]), id)
				planned = append(planned, plannedIncrement{id, inc})
			}
		}
		if len(planned) > 0 {
			body := []byte(candidateScript(planned))
			entry["script"] = "scripts/" + name + ".cfg"
			entry["script_sha256"] = fmt.Sprintf("%x", sha256.Sum256(body))
			if err := r.Publish(ctx, record.String(entry["script"]), body); err != nil {
				return nil, err
			}
		}
		if err := r.Publish(ctx, record.String(entry["report"]), []byte(deviceReport(device, entry, findings, planned))); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
		event, err := json.Marshal(vxlan.Record{"event": "device_reviewed", "host": host, "source_sha256": sourceHash, "counts": entry["counts"], "report": entry["report"], "script": entry["script"], "executed": false})
		if err != nil {
			return nil, err
		}
		events = append(events, string(event))
	}
	plan := vxlan.Record{"schema_version": PlanSchemaVersion, "platform": "cisco_nxos", "mode": "review", "assessment": "assessment.json", "devices": entries, "changes": changes}
	body, err := report.EncodeJSON(plan)
	if err != nil {
		return nil, err
	}
	assessmentBody, err := json.MarshalIndent(assessment, "", "  ")
	if err != nil {
		return nil, err
	}
	assessmentBody = append(assessmentBody, '\n')
	riskCounts := map[string]int{}
	for severity, n := range assessment.Counts {
		riskCounts[severity.String()] = n
	}
	summary := vxlan.Record{"assessment": "assessment.json", "risk_counts": riskCounts, "risk_highest": assessment.Highest.String(), "assessment_incomplete": assessment.Incomplete,
		"layout_version": 4, "mode": "review", "status": "incomplete", "review_only": true, "devices": len(entries), "increments": len(changes),
		"reports": entries, "plan": "plan.json", "plan_sha256": fmt.Sprintf("%x", sha256.Sum256(body))}
	if len(sources) > 0 {
		summary["source_batch"] = filepath.Dir(filepath.Dir(sources[0].Path))
	}
	if standalone {
		if e := r.PublishJSON(ctx, "summary.json", summary); e != nil {
			return nil, e
		}
	}
	for _, artifact := range []struct {
		name string
		body []byte
	}{{"assessment.json", assessmentBody}, {"plan.json", body}, {"plan.json.sha256", []byte(record.String(summary["plan_sha256"]) + "\n")}, {"events.jsonl", []byte(strings.Join(events, "\n") + "\n")}} {
		if e := r.Publish(ctx, artifact.name, artifact.body); e != nil {
			return nil, e
		}
	}
	if standalone {
		if e := r.Publish(ctx, "summary.txt", []byte(summaryText(assessment, len(entries), len(changes)))); e != nil {
			return nil, e
		}
		checkpoint, err := report.EncodeJSON(summary)
		if err != nil {
			return nil, err
		}
		summary["status"] = "complete"
		if e := r.PublishJSON(ctx, "summary.json", summary); e != nil {
			if r.Publish(context.WithoutCancel(ctx), "summary.json", checkpoint) != nil {
				r.Invalidate()
			}
			return nil, e
		}
	}
	summary["status"] = "complete"
	return summary, nil
}

// BuildModel builds the typed fabric model from report sources and an
// optional fabric membership policy record.
func BuildModel(sources []report.Source, policy vxlan.Record) (*fabric.Model, error) {
	devices := make([]*fabric.Device, 0, len(sources))
	for _, src := range sources {
		d, err := fabric.EncodeDocument(src.Document)
		if err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	var membership *fabric.Policy
	if policy != nil {
		body, err := json.Marshal(policy)
		if err != nil {
			return nil, err
		}
		p, err := fabric.DecodePolicy(body)
		if err != nil {
			return nil, err
		}
		membership = &p
	}
	return fabric.Build(devices, membership)
}

// DeriveBaseline proposes a baseline from a batch's current majority values.
func DeriveBaseline(ctx context.Context, sources []report.Source, policy vxlan.Record) (fabric.Baseline, error) {
	if err := ctx.Err(); err != nil {
		return fabric.Baseline{}, err
	}
	if policy == nil {
		return fabric.Baseline{}, errors.New("需要 Fabric 策略以确定成员与角色")
	}
	model, err := BuildModel(sources, policy)
	if err != nil {
		return fabric.Baseline{}, err
	}
	return rules.DeriveBaseline(model), nil
}

// planItem renders one executable increment as a plan.json change entry.
// The id and fields are those the apply workflow authenticates.
func planItem(name string, device vxlan.Record, expected, source, sourceHash string, inc rules.Increment) (string, vxlan.Record, error) {
	rec, err := changepkg.Record(inc.Change)
	if err != nil {
		return "", nil, err
	}
	change, err := vxlan.ProjectRecord(rec)
	if err != nil {
		return "", nil, err
	}
	parts := []string{name, string(inc.Change.Kind()), fmt.Sprintf("vlan%d", int(record.NumberFloat(change["vlan"])))}
	if direction := record.String(change["direction"]); direction != "" {
		parts = append(parts, direction)
	}
	digest, err := vxlan.Fingerprint(change)
	if err != nil {
		return "", nil, err
	}
	id := strings.Join(append(parts, digest[:12]), "--")
	return id, vxlan.Record{"schema_version": 1, "platform": "cisco_nxos", "device": device, "expected_config_sha256": expected,
		"source": source, "source_sha256": sourceHash, "change": change, "commands": inc.Script, "rollback": inc.Undo,
		"scope": inc.Scope, "title": inc.Title, "prerequisites": inc.Prerequisites, "impact": inc.Impact, "verify": inc.Verify}, nil
}

// assessSources runs the schema 3 rule catalogs over the typed model built
// from the same sources the legacy review reads.
func assessSources(ctx context.Context, sources []report.Source, policy vxlan.Record, options ReviewOptions) (rules.Report, *fabric.Model, error) {
	model, err := BuildModel(sources, policy)
	if err != nil {
		return rules.Report{}, nil, err
	}
	inputs := rules.Inputs{Baseline: options.Baseline}
	if options.Baseline != nil && policy == nil {
		return rules.Report{}, nil, errors.New("基线比对需要 Fabric 策略")
	}
	if len(options.Previous) > 0 {
		// Previous devices keep their roles from the same policy.
		if inputs.Previous, err = BuildModel(options.Previous, policy); err != nil {
			return rules.Report{}, nil, err
		}
	}
	var commands rules.Commands
	if options.Queries != nil {
		commands = options.Queries
	}
	assessor, err := rules.NewAssessor(options.Rules, commands)
	if err != nil {
		return rules.Report{}, nil, err
	}
	report, err := assessor.AssessWith(ctx, model, inputs)
	return report, model, err
}
