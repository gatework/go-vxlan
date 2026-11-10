package rules_test

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gatework/go-netops/assess"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/fabric"
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

// The real corpus must yield only increments the execution plan parser and
// the typed checks accept; legacy parity was proven before the legacy review
// was retired (55 identical plans).
func TestRealFabricIncrementsAreEligible(t *testing.T) {
	verify := profile(t)
	total := 0
	for _, rf := range realFabrics(t) {
		var devices []*fabric.Device
		for _, doc := range rf.documents {
			d, _ := fabric.EncodeDocument(doc)
			devices = append(devices, d)
		}
		m, _ := fabric.Build(devices, &rf.policy)
		byHost := map[string]*fabric.Device{}
		for _, d := range m.Devices {
			byHost[d.Host] = d
		}
		for _, f := range m.Fabrics {
			for _, inc := range rules.Increments(f, verify) {
				if err := inc.Change.Eligible(byHost[inc.Host].Configuration); err != nil {
					t.Errorf("increment not eligible on its device: %v", err)
				}
				total++
			}
		}
	}
	t.Logf("real executable increments: %d", total)
}
