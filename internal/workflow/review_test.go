package workflow_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gatework/go-netops/assess"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/internal/workflow"
	"github.com/gatework/go-vxlan/parser"
	"github.com/gatework/go-vxlan/report"
	"github.com/gatework/go-vxlan/review"
	"github.com/gatework/go-vxlan/rules"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

func TestFabricReviewUsesSelectedVerificationQueries(t *testing.T) {
	// Existing Ruby fixture: one peer lacks the shared anycast gateway address.
	body, err := os.ReadFile("../../testdata/domain/a9109db86d4a3e08663ac2d7c68b40bc4c358bc1d8446f3cea6ff20220a63008.json")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := vxlan.DecodeDocument(body)
	if err != nil {
		t.Fatal(err)
	}
	input := record.Map(fixture["input"])
	sources := []report.Source{}
	for _, document := range record.Rows(input["documents"]) {
		body, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, report.Source{Path: "fixture.json", Body: body, Document: document})
	}
	for _, test := range []struct {
		name      string
		commands  []string
		noCatalog bool
	}{
		{name: "selected_profile", commands: []string{"show fabric configuration", "show fabric gateways"}},
		{name: "missing_scope"},
		{name: "missing_catalog", noCatalog: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := nxos.ProfileSpec()
			spec.Verification = nil
			if len(test.commands) > 0 {
				spec.Verification = map[string][]string{"fabric": test.commands}
			}
			registry, err := parser.NewRegistry(map[string]parser.ProfileSpec{"cisco_nxos": spec})
			if err != nil {
				t.Fatal(err)
			}
			profile, err := registry.Fetch("cisco_nxos", "")
			if err != nil {
				t.Fatal(err)
			}
			var queries review.QueryCatalog = profile
			if test.noCatalog {
				queries = nil
			}
			r, err := report.New(filepath.Join(t.TempDir(), "review"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = workflow.Review(t.Context(), r, workflow.ReviewOptions{
				Sources: sources, Policy: record.Map(input["policy"]), Queries: queries,
				Scripts: true, Standalone: true,
			})
			if err != nil {
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
			found := 0
			for _, audit := range record.Rows(plan["audits"]) {
				for _, item := range record.Rows(audit["items"]) {
					if item["category"] != "fabric" {
						continue
					}
					found++
					if !slices.Equal(record.StringSlice(item["verify"]), test.commands) {
						t.Fatalf("fabric verification ignored selected profile: %v", item["verify"])
					}
					if len(test.commands) == 0 {
						if item["status"] != "blocked" || item["change"] != nil || len(record.List(item["commands"])) != 0 || len(record.List(item["rollback"])) != 0 || len(record.List(item["blockers"])) == 0 {
							t.Fatalf("missing verification authorized change: %v", item)
						}
					} else if item["status"] != "candidate" {
						t.Fatalf("valid verification blocked existing candidate: %v", item)
					}
				}
			}
			if found != 1 {
				t.Fatalf("fabric findings changed: %d", found)
			}
			changes := record.Map(plan["changes"])
			if len(test.commands) == 0 && len(changes) != 0 {
				t.Fatal("missing verification created executable plans")
			}
			if len(test.commands) > 0 {
				if len(changes) != 1 {
					t.Fatalf("candidate plan count: %d", len(changes))
				}
				for _, change := range changes {
					if !slices.Equal(record.StringSlice(record.Map(change)["verify"]), test.commands) {
						t.Fatal("plan verification differs from advice")
					}
				}
			}
		})
	}
}

func TestReviewPublishesSchema3Assessment(t *testing.T) {
	body, err := os.ReadFile("../../testdata/domain/a9109db86d4a3e08663ac2d7c68b40bc4c358bc1d8446f3cea6ff20220a63008.json")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := vxlan.DecodeDocument(body)
	if err != nil {
		t.Fatal(err)
	}
	input := record.Map(fixture["input"])
	var sources []report.Source
	for _, document := range record.Rows(input["documents"]) {
		b, _ := json.Marshal(document)
		sources = append(sources, report.Source{Path: "fixture.json", Body: b, Document: document})
	}
	r, err := report.New(filepath.Join(t.TempDir(), "review"))
	if err != nil {
		t.Fatal(err)
	}
	off := false
	summary, err := workflow.Review(t.Context(), r, workflow.ReviewOptions{
		Sources: sources, Policy: record.Map(input["policy"]), Standalone: true,
		Rules: assess.Policy{Rules: map[assess.RuleID]assess.RulePolicy{"vxlan.fabric_spine_l2": {Enabled: &off}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(r.Directory, "assessment.json"))
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(r.Directory, "assessment.json"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("assessment mode %v", info.Mode())
	}
	var got rules.Report
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 3 || len(got.Devices) != len(sources) || len(got.Fabrics) != 1 {
		t.Fatalf("assessment shape: %+v", got)
	}
	disabled := false
	for _, o := range got.Fabrics[0].Assessment.Rules {
		if o.Rule == "vxlan.fabric_spine_l2" && o.State == assess.RuleDisabled {
			disabled = true
		}
	}
	if !disabled || summary["assessment"] != "assessment.json" {
		t.Fatalf("rule policy or summary link missing: %v", summary)
	}
	if _, err := workflow.Review(t.Context(), r, workflow.ReviewOptions{Sources: sources, Rules: assess.Policy{Rules: map[assess.RuleID]assess.RulePolicy{"vxlan.typo": {}}}}); err == nil {
		t.Fatal("unknown rule in policy accepted")
	}
}
