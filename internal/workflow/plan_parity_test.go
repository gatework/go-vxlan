package workflow_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gatework/go-netops/evidence"
	vxlan "github.com/gatework/go-vxlan"
	changepkg "github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/configuration"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/internal/workflow"
	"github.com/gatework/go-vxlan/report"
	"github.com/gatework/go-vxlan/review"
	"github.com/gatework/go-vxlan/vendors"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

// legacyPlans is the legacy derivation of plan.json changes, kept as the
// oracle for the typed derivation: fabric review candidates combined with
// device advice, made executable by CandidateChangePlan.
func legacyPlans(t *testing.T, sources []report.Source, policy vxlan.Record, queries review.QueryCatalog) (map[string]any, map[string][]string) {
	t.Helper()
	var documents []vxlan.Record
	for _, s := range sources {
		documents = append(documents, s.Document)
	}
	items := vxlan.Record{}
	if policy != nil {
		audit, err := review.ReviewFabric(documents, policy, queries)
		if err != nil {
			t.Fatal(err)
		}
		projected, _ := vxlan.ProjectRecord(audit)
		items = record.Map(projected["device_items"])
	}
	changes, plans := map[string]any{}, map[string][]string{}
	for _, src := range sources {
		device := record.Map(src.Document["device"])
		var additions []vxlan.Record
		for _, x := range record.List(items[record.String(device["host"])]) {
			additions = append(additions, record.Map(x))
		}
		advice, err := review.Advice(src.Document, queries, true, additions)
		if err != nil {
			t.Fatal(err)
		}
		sourceHash := fmt.Sprintf("%x", sha256.Sum256(src.Body))
		name := report.Basename(device)
		config := configuration.CompleteConfig(src.Document)
		for _, x := range record.List(advice["items"]) {
			item := record.Map(x)
			if config == nil || item["status"] != "candidate" || item["change"] == nil {
				continue
			}
			plan := changepkg.CandidateChangePlan(record.Map(item["change"]), config)
			if plan == nil {
				continue
			}
			change := plan.Change()
			parts := []string{name, record.String(change["kind"]), fmt.Sprintf("vlan%d", int(record.NumberFloat(change["vlan"])))}
			if d := record.String(change["direction"]); d != "" {
				parts = append(parts, d)
			}
			digest, _ := vxlan.Fingerprint(change)
			expected, _ := vxlan.Fingerprint(config)
			id := strings.Join(append(parts, digest[:12]), "--")
			changes[id] = vxlan.Record{"schema_version": 1, "platform": "cisco_nxos", "device": device, "expected_config_sha256": expected,
				"source": src.Path, "source_sha256": sourceHash, "change": change, "commands": plan.Commands(), "rollback": plan.Rollback(),
				"scope": item["scope"], "title": item["title"], "prerequisites": item["prerequisites"], "impact": item["impact"], "verify": item["verify"]}
			plans[name] = append(plans[name], id)
		}
	}
	return changes, plans
}

func canonical(t *testing.T, v any) string {
	t.Helper()
	projected, err := vxlan.ProjectRecord(vxlan.Record{"v": v})
	if err != nil {
		t.Fatal(err)
	}
	body, err := evidence.Canonical(projected["v"])
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func comparePlans(t *testing.T, label string, sources []report.Source, policy vxlan.Record) int {
	t.Helper()
	profile, err := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
	if err != nil {
		t.Fatal(err)
	}
	wantChanges, wantPlans := legacyPlans(t, sources, policy, profile)
	r, err := report.New(filepath.Join(t.TempDir(), "review"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.Review(t.Context(), r, workflow.ReviewOptions{Sources: sources, Policy: policy, Queries: profile, Scripts: true, Standalone: true}); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	body, err := os.ReadFile(filepath.Join(r.Directory, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := vxlan.DecodeDocument(body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := canonical(t, plan["changes"]), canonical(t, wantChanges); got != want {
		t.Errorf("%s: plan.json changes differ from the legacy derivation\n got  %.600s\n want %.600s", label, got, want)
	}
	for _, e := range record.Rows(plan["devices"]) {
		name := record.String(e["basename"])
		if got := record.Texts(e["plans"]); !slices.Equal(got, wantPlans[name]) && !(len(got) == 0 && len(wantPlans[name]) == 0) {
			t.Errorf("%s %s: plans %v want %v", label, name, got, wantPlans[name])
		}
	}
	// Every typed plan must still be accepted by the execution plan parser.
	for id := range record.Map(plan["changes"]) {
		if _, err := changepkg.NewExecutionPlan(body, id); err != nil {
			t.Errorf("%s: execution plan rejects %s: %v", label, id, err)
		}
	}
	return len(wantChanges)
}

func TestPlanChangesMatchLegacyOnFixtures(t *testing.T) {
	files, _ := filepath.Glob("../../testdata/domain/*.json")
	total := 0
	for _, f := range files {
		body, _ := os.ReadFile(f)
		fixture, err := vxlan.DecodeDocument(body)
		if err != nil || fixture["name"] != "fabric" || fixture["error"] != nil || fixture["expected"] == nil {
			continue
		}
		input := record.Map(fixture["input"])
		var sources []report.Source
		for _, doc := range record.Rows(input["documents"]) {
			b, _ := json.Marshal(doc)
			sources = append(sources, report.Source{Path: "fixture.json", Body: b, Document: doc})
		}
		total += comparePlans(t, filepath.Base(f), sources, record.Map(input["policy"]))
	}
	if total == 0 {
		t.Fatal("no executable plans in fixtures")
	}
	t.Logf("executable plans compared: %d", total)
}

var realName = regexp.MustCompile(`^([A-Z0-9]+)-(LEF|BDR|SPN)\d+-(\d+\.\d+\.\d+\.\d+)\.txt$`)

func TestPlanChangesMatchLegacyOnRealCorpus(t *testing.T) {
	dir := os.Getenv("VXLAN_REAL_CORPUS")
	if dir == "" {
		t.Skip("set VXLAN_REAL_CORPUS to a directory of NX-OS running-config captures")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.txt"))
	type site struct {
		sources []report.Source
		roles   map[string][]any
	}
	sites := map[string]*site{}
	for _, f := range files {
		m := realName.FindStringSubmatch(filepath.Base(f))
		if m == nil {
			continue
		}
		body, _ := os.ReadFile(f)
		text := string(body)
		if i := strings.Index(text, "!Command: show running-config"); i >= 0 {
			text = text[i:]
		}
		o, err := nxos.ParseConfigChecked(text, true)
		if err != nil {
			t.Fatal(err)
		}
		doc, _ := vxlan.ProjectRecord(vxlan.Record{"device": vxlan.Record{"host": m[3], "name": m[3]}, "snapshot": vxlan.Record{"dimensions": vxlan.Record{"configuration": o}}})
		b, _ := json.Marshal(doc)
		s := sites[m[1]]
		if s == nil {
			s = &site{roles: map[string][]any{}}
			sites[m[1]] = s
		}
		s.sources = append(s.sources, report.Source{Path: filepath.Base(f), Body: b, Document: doc})
		role := map[string]string{"LEF": "leaves", "BDR": "borders", "SPN": "spines"}[m[2]]
		s.roles[role] = append(s.roles[role], m[3])
	}
	total := 0
	for name, s := range sites {
		policy := vxlan.Record{"fabrics": vxlan.Record{name: vxlan.Record{}}}
		for role, hosts := range s.roles {
			record.Map(record.Map(policy["fabrics"])[name])[role] = hosts
		}
		projected, _ := vxlan.ProjectRecord(policy)
		total += comparePlans(t, fmt.Sprintf("site with %d devices", len(s.sources)), s.sources, projected)
	}
	t.Logf("real executable plans compared: %d", total)
}
