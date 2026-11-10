package rules_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gatework/go-netops/assess"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/review"
	"github.com/gatework/go-vxlan/rules"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

// Real corpus files are named SITE-ROLE##-ADDRESS.txt, ROLE in LEF/BDR/SPN.
var realName = regexp.MustCompile(`^([A-Z0-9]+)-(LEF|BDR|SPN)\d+-(\d+\.\d+\.\d+\.\d+)\.txt$`)

type realFabric struct {
	documents []vxlan.Record
	policy    fabric.Policy
}

// realFabrics builds one fabric per site from VXLAN_REAL_CORPUS, or skips.
func realFabrics(t *testing.T) map[string]*realFabric {
	t.Helper()
	dir := os.Getenv("VXLAN_REAL_CORPUS")
	if dir == "" {
		t.Skip("set VXLAN_REAL_CORPUS to a directory of NX-OS running-config captures")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.txt"))
	out := map[string]*realFabric{}
	for _, f := range files {
		m := realName.FindStringSubmatch(filepath.Base(f))
		if m == nil {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		if i := strings.Index(text, "!Command: show running-config"); i >= 0 {
			text = text[i:]
		}
		o, err := nxos.ParseConfigChecked(text, true)
		if err != nil {
			t.Fatal(err)
		}
		site, role, host := m[1], m[2], m[3]
		rf := out[site]
		if rf == nil {
			rf = &realFabric{policy: fabric.Policy{Fabrics: map[string]fabric.Membership{site: {}}}}
			out[site] = rf
		}
		member := rf.policy.Fabrics[site]
		switch role {
		case "LEF":
			member.Leaves = append(member.Leaves, host)
		case "BDR":
			member.Borders = append(member.Borders, host)
		case "SPN":
			member.Spines = append(member.Spines, host)
		}
		rf.policy.Fabrics[site] = member
		projected, err := vxlan.ProjectRecord(vxlan.Record{"device": vxlan.Record{"host": host, "name": host},
			"snapshot": vxlan.Record{"dimensions": vxlan.Record{"configuration": o}}})
		if err != nil {
			t.Fatal(err)
		}
		rf.documents = append(rf.documents, projected)
	}
	if len(out) == 0 {
		t.Skip("no SITE-ROLE##-ADDRESS.txt files in corpus")
	}
	return out
}

func TestRealFabricsMatchLegacyReview(t *testing.T) {
	assessor, err := rules.NewAssessor(assess.Policy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	totals := map[string]int{}
	newRules := map[assess.RuleID]int{}
	for _, site := range slices.Sorted(maps.Keys(realFabrics(t))) {
		rf := realFabrics(t)[site]
		body, _ := json.Marshal(rf.policy)
		var legacyPolicy vxlan.Record
		_ = json.Unmarshal(body, &legacyPolicy)
		legacy, err := review.ReviewFabric(rf.documents, record.Copy(legacyPolicy).(vxlan.Record), nil)
		if err != nil {
			t.Fatalf("%s legacy: %v", site, err)
		}
		want := map[string]bool{}
		for _, f := range record.Rows(legacy["findings"]) {
			code := record.String(f["code"])
			if ported[code] {
				vni := "-"
				if f["vni"] != nil {
					vni = fmt.Sprint(f["vni"])
				}
				want[code+"@"+vni] = true
			}
		}
		for _, items := range record.Map(legacy["device_items"]) {
			for _, item := range record.Rows(items) {
				if item["code"] == "fabric_vlan_mapping_missing" {
					_, after, _ := strings.Cut(record.String(item["scope"]), "VNI ")
					want["fabric_vlan_mapping_missing@"+after] = true
				}
			}
		}
		var devices []*fabric.Device
		for _, doc := range rf.documents {
			d, err := fabric.EncodeDocument(doc)
			if err != nil {
				t.Fatal(err)
			}
			devices = append(devices, d)
		}
		model, err := fabric.Build(devices, &rf.policy)
		if err != nil {
			t.Fatal(err)
		}
		report, err := assessor.Assess(t.Context(), model)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, fa := range report.Fabrics {
			for _, f := range fa.Assessment.Findings {
				if code := legacyCode(f); ported[code] {
					got[code+"@"+subjectVNI(f.Subject)] = true
				} else {
					newRules[f.Rule]++
				}
			}
		}
		for _, d := range report.Devices {
			for _, f := range d.Assessment.Findings {
				newRules[f.Rule]++
			}
		}
		for k := range want {
			code, _, _ := strings.Cut(k, "@")
			totals[code]++
		}
		missing, extra := diff(want, got), diff(got, want)
		if len(missing)+len(extra) > 0 {
			t.Errorf("fabric %d: typed rules differ from legacy\n missing %v\n extra   %v", len(rf.documents), missing, extra)
		}
		t.Logf("fabric with %d devices: %d legacy (code@vni) findings reproduced", len(rf.documents), len(want))
	}
	t.Logf("legacy finding counts by code: %v", totals)
	t.Logf("typed-only findings by rule: %v", newRules)
}

func diff(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

func TestRealFabricsBaselineAndSelfComparison(t *testing.T) {
	a, err := rules.NewAssessor(assess.Policy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	byRule := map[assess.RuleID]int{}
	for _, rf := range realFabrics(t) {
		var devices []*fabric.Device
		for _, doc := range rf.documents {
			d, _ := fabric.EncodeDocument(doc)
			devices = append(devices, d)
		}
		m, _ := fabric.Build(devices, &rf.policy)
		derived := rules.DeriveBaseline(m)
		body, err := derived.Encode()
		if err != nil {
			t.Fatal(err)
		}
		b, err := fabric.DecodeBaseline(body)
		if err != nil {
			t.Fatalf("derived baseline does not round-trip: %v", err)
		}
		r, err := a.AssessWith(t.Context(), m, rules.Inputs{Baseline: &b, Previous: m})
		if err != nil {
			t.Fatal(err)
		}
		for _, fa := range r.Baseline {
			for _, f := range fa.Assessment.Findings {
				byRule[f.Rule]++
			}
		}
		for _, c := range r.Changes {
			if n := len(c.Assessment.Findings); n != 0 {
				t.Errorf("self comparison reported %d changes", n)
			}
		}
	}
	t.Logf("drift from derived (majority) baselines by rule: %v", byRule)
}
