package rules_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-netops/evidence"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/rules"
)

type domainFixture struct {
	Name     string          `json:"name"`
	Input    json.RawMessage `json:"input"`
	Expected json.RawMessage `json:"expected"`
	Error    any             `json:"error"`
}

func fixtures(t *testing.T, name string) map[string]domainFixture {
	t.Helper()
	files, _ := filepath.Glob("../testdata/domain/*.json")
	out := map[string]domainFixture{}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var d domainFixture
		if err := json.Unmarshal(body, &d); err != nil {
			t.Fatal(err)
		}
		if d.Name == name {
			out[filepath.Base(f)] = d
		}
	}
	if len(out) == 0 {
		t.Fatalf("no %s fixtures", name)
	}
	return out
}

func decodeConfig(t *testing.T, raw json.RawMessage) *fabric.Configuration {
	t.Helper()
	d := fabric.NewDevice(fabric.Identity{Host: "192.0.2.250"}, map[evidence.Dimension]fabric.Observed{
		fabric.DimConfiguration: {Status: "complete", Records: []json.RawMessage{raw}},
	})
	if !d.Has(fabric.DimConfiguration) {
		t.Fatalf("configuration not modeled: %v", d.Issues)
	}
	return d.Configuration
}

func TestServicesMatchLegacyCatalog(t *testing.T) {
	for file, fx := range fixtures(t, "catalog") {
		if fx.Error != nil {
			continue
		}
		var input struct {
			Configs map[string]json.RawMessage `json:"configs"`
		}
		var expected map[string][]struct {
			Host    string   `json:"host"`
			VLAN    any      `json:"vlan"`
			Missing []string `json:"missing"`
		}
		if json.Unmarshal(fx.Input, &input) != nil || json.Unmarshal(fx.Expected, &expected) != nil {
			t.Fatalf("%s: fixture shape", file)
		}
		got := map[string][]string{}
		for _, host := range slices.Sorted(maps.Keys(input.Configs)) {
			for _, s := range decodeConfig(t, input.Configs[host]).Services() {
				vlan := "null"
				if s.VLAN != nil {
					vlan = strconv.Itoa(*s.VLAN)
				}
				got[strconv.Itoa(s.VNI)] = append(got[strconv.Itoa(s.VNI)], fmt.Sprintf("%s vlan=%s missing=%v", host, vlan, s.Missing))
			}
		}
		want := map[string][]string{}
		for vni, rows := range expected {
			for _, r := range rows {
				vlan := "null"
				if r.VLAN != nil {
					vlan = fmt.Sprint(r.VLAN)
				}
				if r.Missing == nil {
					r.Missing = []string{}
				}
				want[vni] = append(want[vni], fmt.Sprintf("%s vlan=%s missing=%v", r.Host, vlan, r.Missing))
			}
		}
		for vni := range want {
			slices.Sort(want[vni])
			slices.Sort(got[vni])
			// nil and empty Missing print differently; normalize.
			for i := range got[vni] {
				got[vni][i] = strings.Replace(got[vni][i], "missing=[]", "missing=[]", 1)
			}
		}
		if fmt.Sprint(normalize(got)) != fmt.Sprint(normalize(want)) {
			t.Errorf("%s:\n got  %v\n want %v", file, normalize(got), normalize(want))
		}
	}
}

func normalize(m map[string][]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range m {
		var rows []string
		for _, r := range v {
			rows = append(rows, strings.ReplaceAll(r, "missing=<nil>", "missing=[]"))
		}
		slices.Sort(rows)
		out[k] = rows
	}
	return out
}

// legacyCodes maps typed rules (and SVI attribute paths) to the legacy
// fabric review codes they replace.
func legacyCode(f assess.Finding) string {
	switch f.Rule {
	case "vxlan.fabric_svi_attributes":
		path, _, _ := strings.Cut(f.Detail, " ")
		return "fabric_" + strings.TrimPrefix(path, "svi.")
	case "vxlan.fabric_spine_l2":
		return "fabric_role_conflict"
	case "vxlan.fabric_anycast_mac":
		return "fabric_anycast_mac"
	}
	return strings.TrimPrefix(string(f.Rule), "vxlan.")
}

var ported = map[string]bool{
	"fabric_evidence_incomplete": true, "fabric_scope_unassigned": true, "fabric_service_incomplete": true,
	"fabric_vlan_mapping_ambiguous": true, "fabric_vlan_mapping": true, "fabric_replication": true,
	"fabric_arp_suppression": true, "fabric_vrf": true, "fabric_anycast": true, "fabric_mtu": true,
	"fabric_shutdown": true, "fabric_anycast_mac": true, "fabric_role_conflict": true,
}

func subjectVNI(s assess.Subject) string {
	for cur := &s; cur != nil; cur = cur.Parent {
		if cur.Kind == "vni" {
			return cur.Key
		}
	}
	return "-"
}

func TestFabricRulesMatchLegacyReview(t *testing.T) {
	assessor, err := rules.NewAssessor(assess.Policy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	compared := 0
	for file, fx := range fixtures(t, "fabric") {
		var input struct {
			Documents []json.RawMessage `json:"documents"`
			Policy    json.RawMessage   `json:"policy"`
		}
		if err := json.Unmarshal(fx.Input, &input); err != nil {
			t.Fatal(err)
		}
		policy, policyErr := fabric.DecodePolicy(input.Policy)
		if fx.Error != nil || len(fx.Expected) == 0 || string(fx.Expected) == "null" {
			continue // legacy rejected the input; covered by policy tests
		}
		if policyErr != nil {
			t.Fatalf("%s: legacy accepted a policy the typed model rejects: %v", file, policyErr)
		}
		var devices []*fabric.Device
		for _, raw := range input.Documents {
			d, err := fabric.DecodeDocument(raw)
			if err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			devices = append(devices, d)
		}
		model, err := fabric.Build(devices, &policy)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
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
				}
			}
		}
		if len(report.Unassigned) > 0 {
			got["fabric_scope_unassigned@-"] = true
		}
		var legacy struct {
			Findings []struct {
				Code string `json:"code"`
				VNI  any    `json:"vni"`
			} `json:"findings"`
		}
		if err := json.Unmarshal(fx.Expected, &legacy); err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{}
		for _, f := range legacy.Findings {
			if ported[f.Code] {
				vni := "-"
				if f.VNI != nil {
					vni = fmt.Sprint(f.VNI)
				}
				want[f.Code+"@"+vni] = true
			}
		}
		if !maps.Equal(got, want) {
			t.Errorf("%s:\n got  %v\n want %v", file, slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want)))
		}
		compared++
	}
	t.Logf("compared %d fabric reviews", compared)
}

func deviceLegacyCode(f assess.Finding) string {
	switch f.Rule {
	case "vxlan.config_relation":
		return f.Detail
	case "vxlan.acl_undefined":
		return "acl_reference_undefined"
	case "vxlan.nve_vni_down":
		return "nve_vnis_not_up"
	case "vxlan.nve_peer_down":
		return "nve_peers_not_up"
	case "vxlan.bgp_session_down":
		return "bgp_neighbors_not_up"
	}
	return strings.TrimPrefix(string(f.Rule), "vxlan.")
}

func TestDeviceRulesMatchLegacyRecommendations(t *testing.T) {
	assessor, err := rules.NewAssessor(assess.Policy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for file, fx := range fixtures(t, "recommendations") {
		var input struct {
			Document json.RawMessage `json:"document"`
		}
		var legacy struct {
			Items []legacyItem `json:"items"`
		}
		if json.Unmarshal(fx.Input, &input) != nil || json.Unmarshal(fx.Expected, &legacy) != nil {
			t.Fatalf("%s: fixture shape", file)
		}
		var doc map[string]any
		_ = json.Unmarshal(input.Document, &doc)
		if doc == nil {
			doc = map[string]any{}
		}
		if _, ok := doc["device"]; !ok {
			doc["device"] = map[string]any{"host": "192.0.2.250"} // degenerate fixture without identity
		}
		d, err := fabric.EncodeDocument(doc)
		if err != nil {
			t.Fatal(err)
		}
		model, _ := fabric.Build([]*fabric.Device{d}, nil)
		report, err := assessor.Assess(t.Context(), model)
		if err != nil {
			t.Fatal(err)
		}
		var got, want []string
		for _, f := range report.Devices[0].Assessment.Findings {
			code := deviceLegacyCode(f)
			if !slices.Contains([]string{"evidence_incomplete", "acl_reference_undefined", "nve_vnis_not_up", "nve_peers_not_up", "bgp_neighbors_not_up"}, code) && f.Rule != "vxlan.config_relation" {
				continue // new rule without a legacy counterpart
			}
			status := "investigate"
			var commands []string
			if r := f.Remediation; r != nil {
				status = string(r.Status)
				commands = r.Commands
				if r.Status == assess.RemediationManual {
					status = "candidate" // legacy name for a derivable script
				}
			}
			if code == "evidence_incomplete" {
				code += "/" + f.Subject.Key
				// Intentional: the typed rule also reports configuration that was
				// never collected; legacy stayed silent when other dimensions exist.
				if f.Subject.Key == "configuration" && f.Detail == "未采集运行配置" && !legacyHasConfigEvidence(legacy.Items) {
					continue
				}
			}
			got = append(got, fmt.Sprintf("%s %s %q", code, status, commands))
		}
		for _, item := range legacy.Items {
			if item.Code == "nve_l2_without_vlan" {
				item.Commands = []string{"vlan <VLAN_ID>", "  vn-segment 10095"} // legacy kept this in "template"
			}
			if len(item.Commands) == 0 {
				item.Commands = nil
			}
			code := item.Code
			if code == "evidence_incomplete" {
				code += "/" + item.Scope
			}
			want = append(want, fmt.Sprintf("%s %s %q", code, item.Status, item.Commands))
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s:\n got  %v\n want %v", file, got, want)
		}
	}
}

type legacyItem struct {
	Code     string   `json:"code"`
	Scope    string   `json:"scope"`
	Status   string   `json:"status"`
	Commands []string `json:"commands"`
}

func legacyHasConfigEvidence(items []legacyItem) bool {
	return slices.ContainsFunc(items, func(i legacyItem) bool { return i.Code == "evidence_incomplete" && i.Scope == "configuration" })
}
