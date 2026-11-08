package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	vxlan "github.com/gatework/go-vxlan"
	changepkg "github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/configuration"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/report"
	"github.com/gatework/go-vxlan/review"
)

// ReviewOptions binds checked evidence and a command catalog to a review run.
type ReviewOptions struct {
	Sources             []report.Source
	Policy              vxlan.Record
	Queries             review.QueryCatalog
	Scripts, Standalone bool
}

// Review generates diagnostics and selected executable plans from source evidence.
func Review(ctx context.Context, r *report.Report, options ReviewOptions) (vxlan.Record, error) {
	sources, policy, scripts, standalone := options.Sources, options.Policy, options.Scripts, options.Standalone
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	documents := []vxlan.Record{}
	for _, s := range sources {
		documents = append(documents, s.Document)
	}
	var fabric vxlan.Record
	if policy != nil {
		audit, e := review.ReviewFabric(documents, policy, options.Queries)
		if e != nil {
			return nil, e
		}
		fabric, e = vxlan.ProjectRecord(audit)
		if e != nil {
			return nil, e
		}
	}
	entries, audits, events := []any{}, []any{}, []string{}
	changes := vxlan.Record{}
	totals := vxlan.Record{}
	for _, src := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		device := record.Map(src.Document["device"])
		additions := []vxlan.Record{}
		for _, x := range record.List(record.Map(fabric["device_items"])[record.String(device["host"])]) {
			additions = append(additions, record.Map(x))
		}
		advice, err := review.Advice(src.Document, options.Queries, scripts, additions)
		if err != nil {
			return nil, err
		}
		sourceHash := fmt.Sprintf("%x", sha256.Sum256(src.Body))
		advice["source"], advice["source_sha256"] = src.Path, sourceHash
		name := report.Basename(device)
		entry := vxlan.Record{"device": device, "counts": advice["counts"], "basename": name, "report": "devices/" + name + ".txt", "source": src.Path, "source_sha256": sourceHash, "script": nil, "script_sha256": nil, "plans": []string{}}
		config := configuration.CompleteConfig(src.Document)
		for _, x := range record.List(advice["items"]) {
			item := record.Map(x)
			if scripts && config != nil && item["status"] == "candidate" && item["change"] != nil {
				plan := changepkg.CandidateChangePlan(record.Map(item["change"]), config)
				if plan != nil {
					change := plan.Change()
					parts := []string{name, record.String(change["kind"]), fmt.Sprintf("vlan%d", int(record.NumberFloat(change["vlan"])))}
					if direction := record.String(change["direction"]); direction != "" {
						parts = append(parts, direction)
					}
					digest, err := vxlan.Fingerprint(change)
					if err != nil {
						return nil, err
					}
					expected, err := vxlan.Fingerprint(config)
					if err != nil {
						return nil, err
					}
					parts = append(parts, digest[:12])
					id := strings.Join(parts, "--")
					changes[id] = vxlan.Record{"schema_version": 1, "platform": "cisco_nxos", "device": device, "expected_config_sha256": expected, "source": src.Path, "source_sha256": sourceHash, "change": change, "commands": plan.Commands(), "rollback": plan.Rollback(), "scope": item["scope"], "title": item["title"], "prerequisites": item["prerequisites"], "impact": item["impact"], "verify": item["verify"]}
					item["plan_id"] = id
					entry["plans"] = append(record.Texts(entry["plans"]), id)
				}
			}
		}
		entry, err = r.PublishReviewDevice(ctx, advice, entry, scripts)
		if err != nil {
			return nil, err
		}
		for k, v := range record.Map(advice["counts"]) {
			n, _ := totals[k].(int)
			totals[k] = n + int(record.NumberFloat(v))
		}
		entries = append(entries, entry)
		audits = append(audits, advice)
		event, err := json.Marshal(vxlan.Record{"event": "device_reviewed", "host": device["host"], "source_sha256": sourceHash, "counts": advice["counts"], "report": entry["report"], "script": entry["script"], "executed": false})
		if err != nil {
			return nil, err
		}
		events = append(events, string(event))
	}
	auditPublic := record.MergeLayers(fabric)
	delete(auditPublic, "device_items")
	var fabricValue any
	if fabric != nil {
		fabricValue = auditPublic
	}
	plan := vxlan.Record{"schema_version": 2, "platform": "cisco_nxos", "mode": "review", "devices": entries, "audits": audits, "changes": changes, "fabric": fabricValue}
	body, err := report.EncodeJSON(plan)
	if err != nil {
		return nil, err
	}
	summary := vxlan.Record{"layout_version": 3, "mode": "review", "status": "incomplete", "review_only": true, "devices": len(entries), "counts": totals, "reports": entries, "plan": "plan.json", "plan_sha256": fmt.Sprintf("%x", sha256.Sum256(body)), "fabric_findings": len(record.List(fabric["findings"]))}
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
	}{{"plan.json", body}, {"plan.json.sha256", []byte(record.String(summary["plan_sha256"]) + "\n")}, {"events.jsonl", []byte(strings.Join(events, "\n") + "\n")}} {
		if e := r.Publish(ctx, artifact.name, artifact.body); e != nil {
			return nil, e
		}
	}
	if standalone {
		if e := r.PublishReviewSummary(ctx, summary, auditPublic, fabric != nil); e != nil {
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
