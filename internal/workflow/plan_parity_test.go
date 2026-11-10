package workflow_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gatework/go-netops/evidence"
	vxlan "github.com/gatework/go-vxlan"
	changepkg "github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/internal/workflow"
	"github.com/gatework/go-vxlan/report"
	"github.com/gatework/go-vxlan/vendors"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

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

type frozenPlans struct {
	Changes map[string]any      `json:"changes"`
	Plans   map[string][]string `json:"plans"`
}

func comparePlans(t *testing.T, label string, sources []report.Source, policy vxlan.Record, frozen frozenPlans) int {
	t.Helper()
	profile, err := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
	if err != nil {
		t.Fatal(err)
	}
	wantChanges, wantPlans := frozen.Changes, frozen.Plans
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

// TestPlanChangesMatchLegacyOnFixtures compares plan.json with the frozen
// legacy derivation (testdata/typed/plan-oracle.json).
func TestPlanChangesMatchLegacyOnFixtures(t *testing.T) {
	oracleBody, err := os.ReadFile("../../testdata/typed/plan-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle map[string]frozenPlans
	if err := json.Unmarshal(oracleBody, &oracle); err != nil {
		t.Fatal(err)
	}
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
		frozen, ok := oracle[filepath.Base(f)]
		if !ok {
			t.Fatalf("%s: no frozen plans", filepath.Base(f))
		}
		total += comparePlans(t, filepath.Base(f), sources, record.Map(input["policy"]), frozen)
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
		total += executablePlans(t, s.sources, projected)
	}
	t.Logf("real executable plans checked: %d", total)
}

// executablePlans reviews real sources and requires every plan to be
// accepted by the execution plan parser.
func executablePlans(t *testing.T, sources []report.Source, policy vxlan.Record) int {
	t.Helper()
	profile, err := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
	if err != nil {
		t.Fatal(err)
	}
	r, err := report.New(filepath.Join(t.TempDir(), "review"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.Review(t.Context(), r, workflow.ReviewOptions{Sources: sources, Policy: policy, Queries: profile, Scripts: true, Standalone: true}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(r.Directory, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := vxlan.DecodeDocument(body)
	if err != nil {
		t.Fatal(err)
	}
	for id := range record.Map(plan["changes"]) {
		if _, err := changepkg.NewExecutionPlan(body, id); err != nil {
			t.Errorf("execution plan rejects %s: %v", id, err)
		}
	}
	return len(record.Map(plan["changes"]))
}
