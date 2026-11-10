package rules_test

import (
	"encoding/json"

	"fmt"
	"github.com/gatework/go-netops/assess"
	"maps"
	"slices"
	"testing"

	"github.com/gatework/go-netops/evidence"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/rules"
	"github.com/gatework/go-vxlan/vendors"
)

// legacyCandidates lists executable changes the legacy fabric review proposes,
// as "host canonical-change" keys.
func legacyCandidates(t *testing.T, legacy vxlan.Record) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for host, items := range record.Map(legacy["device_items"]) {
		for _, item := range record.Rows(items) {
			if item["status"] == "candidate" && item["change"] != nil {
				body, err := evidence.Canonical(item["change"])
				if err != nil {
					t.Fatal(err)
				}
				out[host+" "+string(body)] = true
			}
		}
	}
	return out
}

func typedCandidates(t *testing.T, m *fabric.Model, verify rules.Verifier) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range m.Fabrics {
		for _, inc := range rules.Increments(f, verify) {
			rec, err := change.Record(inc.Change)
			if err != nil {
				t.Fatal(err)
			}
			body, err := evidence.Canonical(rec)
			if err != nil {
				t.Fatal(err)
			}
			out[inc.Host+" "+string(body)] = true
		}
	}
	return out
}

func profile(t *testing.T) rules.Verifier {
	t.Helper()
	p, err := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIncrementsMatchLegacyFixtures(t *testing.T) {
	verify := profile(t)
	total := 0
	for file, fx := range fixtures(t, "fabric") {
		if fx.Error != nil || len(fx.Expected) == 0 || string(fx.Expected) == "null" {
			continue
		}
		var expected vxlan.Record
		if err := json.Unmarshal(fx.Expected, &expected); err != nil {
			t.Fatal(err)
		}
		want := legacyCandidates(t, expected)
		var input struct {
			Documents []json.RawMessage `json:"documents"`
			Policy    json.RawMessage   `json:"policy"`
		}
		_ = json.Unmarshal(fx.Input, &input)
		policy, _ := fabric.DecodePolicy(input.Policy)
		var devices []*fabric.Device
		for _, raw := range input.Documents {
			d, err := fabric.DecodeDocument(raw)
			if err != nil {
				t.Fatal(err)
			}
			devices = append(devices, d)
		}
		m, err := fabric.Build(devices, &policy)
		if err != nil {
			t.Fatal(err)
		}
		got := typedCandidates(t, m, verify)
		if !maps.Equal(got, want) {
			t.Errorf("%s:\n got  %v\n want %v", file, slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want)))
		}
		total += len(want)
		a, err := rules.NewAssessor(assess.Policy{}, verify.(rules.Commands))
		if err != nil {
			t.Fatal(err)
		}
		report, err := a.Assess(t.Context(), m)
		if err != nil {
			t.Fatal(err)
		}
		candidates := 0
		for _, fa := range report.Fabrics {
			for _, f := range fa.Assessment.Findings {
				if f.Rule == rules.IncrementRuleID {
					if f.Remediation == nil || f.Remediation.Status != assess.RemediationCandidate || len(f.Remediation.Commands) == 0 {
						t.Fatalf("%s: increment finding without candidate remediation: %+v", file, f)
					}
					candidates++
				}
			}
		}
		if candidates != len(got) {
			t.Errorf("%s: %d increment findings for %d increments", file, candidates, len(got))
		}
		// Without verification commands nothing may become executable.
		if n := len(typedCandidates(t, m, nil)); n != 0 {
			t.Errorf("%s: %d increments without verification commands", file, n)
		}
	}
	if total == 0 {
		t.Fatal("no legacy candidates in fixtures")
	}
	t.Logf("legacy executable candidates reproduced: %d", total)
}

var _ = fmt.Sprint
