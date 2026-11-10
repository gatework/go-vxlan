package rules_test

import (
	"slices"
	"testing"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-netops/evidence"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/rules"
)

func gatewayFabric() ([]*fabric.Device, *fabric.Policy) {
	devices := []*fabric.Device{vtep("10.0.0.11", "10.1.1.11", 0, 10010), vtep("10.0.0.12", "10.1.1.12", 0, 10010)}
	for _, d := range devices {
		mtu := 9216
		d.Configuration.AnycastMAC = "0001.0001.0001"
		d.Configuration.Interfaces["Vlan100"] = fabric.Interface{VRF: "tenant", Anycast: true, Addresses: []string{"10.10.0.1/24"}, MTU: &mtu}
		d.Configuration.Operations = &fabric.Operations{NTPServers: []fabric.Server{{Address: "192.0.2.10"}}}
	}
	return devices, &fabric.Policy{Fabrics: map[string]fabric.Membership{"dc1": {Leaves: []string{"10.0.0.11", "10.0.0.12"}}}}
}

func baselineFindings(t *testing.T, devices []*fabric.Device, policy *fabric.Policy, b fabric.Baseline) []assess.Finding {
	t.Helper()
	a, err := rules.NewAssessor(assess.Policy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := fabric.Build(devices, policy)
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.AssessWith(t.Context(), m, rules.Inputs{Baseline: &b})
	if err != nil {
		t.Fatal(err)
	}
	return r.Baseline[0].Assessment.Findings
}

func ruleKeys(fs []assess.Finding) map[assess.RuleID][]string {
	out := map[assess.RuleID][]string{}
	for _, f := range fs {
		out[f.Rule] = append(out[f.Rule], f.Subject.String())
	}
	return out
}

func TestBaselineCatchesAgreedButWrongValues(t *testing.T) {
	devices, policy := gatewayFabric()
	mac, mtu := "0002.0002.0002", 9000
	b := fabric.Baseline{SchemaVersion: 1,
		Defaults: fabric.Expectation{AnycastGatewayMAC: &mac, SVIMTU: &mtu, Services: map[int]int{10010: 200},
			Management: &fabric.ManagementExpectation{NTP: []string{"192.0.2.10", "192.0.2.11"}}},
	}
	got := ruleKeys(baselineFindings(t, devices, policy, b))
	for id, n := range map[assess.RuleID]int{"vxlan.baseline_anycast_mac": 2, "vxlan.baseline_svi_mtu": 2, "vxlan.baseline_services": 2, "vxlan.baseline_management": 2} {
		if len(got[id]) != n {
			t.Errorf("%s: %v", id, got[id])
		}
	}
	// Peer consensus sees nothing: both members agree.
	if fs := findings(run(t, devices, policy), "vxlan.fabric_anycast_mac"); len(fs) != 0 {
		t.Fatalf("consensus flagged agreeing members: %v", fs)
	}
}

func TestBaselineOverridesAndValidation(t *testing.T) {
	devices, policy := gatewayFabric()
	wrong, right := "0002.0002.0002", "0001.0001.0001"
	b := fabric.Baseline{SchemaVersion: 1, Defaults: fabric.Expectation{AnycastGatewayMAC: &wrong},
		Fabrics: map[string]fabric.Expectation{"dc1": {AnycastGatewayMAC: &right}}}
	if fs := baselineFindings(t, devices, policy, b); len(fs) != 0 {
		t.Fatalf("fabric override ignored: %v", fs)
	}
	for _, doc := range []string{"schema_version: 2\n", "schema_version: 1\ndefaults: {svi_mtu: 100}\n", "schema_version: 1\nbogus: 1\n",
		"schema_version: 1\ndefaults: {management: {ntp: [not-an-ip]}}\n", "schema_version: 1\ndefaults: {services: {10010: 5000}}\n"} {
		if _, err := fabric.DecodeBaseline([]byte(doc)); err == nil {
			t.Errorf("accepted %q", doc)
		}
	}
}

func TestDeriveBaselineRoundTrip(t *testing.T) {
	devices, policy := gatewayFabric()
	devices = append(devices, vtep("10.0.0.13", "10.1.1.13", 0, 10010))
	devices[2].Configuration.AnycastMAC = "0009.0009.0009" // the outlier
	devices[2].Configuration.Interfaces["Vlan100"] = devices[0].Configuration.Interfaces["Vlan100"]
	policy.Fabrics["dc1"] = fabric.Membership{Leaves: []string{"10.0.0.11", "10.0.0.12", "10.0.0.13"}}
	m, _ := fabric.Build(devices, policy)
	derived := rules.DeriveBaseline(m)
	body, err := derived.Encode()
	if err != nil {
		t.Fatal(err)
	}
	b, err := fabric.DecodeBaseline(body)
	if err != nil {
		t.Fatalf("%v\n%s", err, body)
	}
	e := b.For("dc1")
	if e.AnycastGatewayMAC == nil || *e.AnycastGatewayMAC != "0001.0001.0001" || e.Services[10010] != 100 || len(e.Management.NTP) != 1 {
		t.Fatalf("derived %+v", e)
	}
	got := ruleKeys(baselineFindings(t, devices, policy, b))
	if !slices.Equal(got["vxlan.baseline_anycast_mac"], []string{"fabric:dc1/device:10.0.0.13"}) {
		t.Fatalf("derived baseline should flag only the outlier: %v", got)
	}
}

func TestTemporalChanges(t *testing.T) {
	before := vtep("10.0.0.11", "10.1.1.11", 0, 10010, 10020)
	before.NVEPeers = []fabric.NVEPeer{{PeerIP: "10.1.1.12", State: "Up"}, {PeerIP: "10.1.1.13", State: "Up"}}
	before.Configuration.ConfigDigest = "a"
	after := vtep("10.0.0.11", "10.1.1.11", 0, 10010)
	after.NVEPeers = []fabric.NVEPeer{{PeerIP: "10.1.1.12", State: "Up"}}
	after.Configuration.ConfigDigest = "b"
	gone := vtep("10.0.0.99", "10.1.1.99", 0)
	prev, _ := fabric.Build([]*fabric.Device{before, gone}, nil)
	cur, _ := fabric.Build([]*fabric.Device{after}, nil)
	a, _ := rules.NewAssessor(assess.Policy{}, nil)
	r, err := a.AssessWith(t.Context(), cur, rules.Inputs{Previous: prev})
	if err != nil {
		t.Fatal(err)
	}
	got := ruleKeys(r.Changes[0].Assessment.Findings)
	if !slices.Equal(got["vxlan.change_services"], []string{"device:10.0.0.11/vni:10020"}) ||
		!slices.Equal(got["vxlan.change_nve_peers_lost"], []string{"device:10.0.0.11/nve_peer:10.1.1.13"}) ||
		len(got["vxlan.change_configuration"]) != 1 {
		t.Fatalf("%v", got)
	}
	if !slices.Equal(r.Disappeared, []string{"10.0.0.99"}) || !r.Incomplete {
		t.Fatalf("disappeared device not reported: %+v", r.Disappeared)
	}
	for _, f := range r.Changes[0].Assessment.Findings {
		if f.Rule == "vxlan.change_services" && f.Severity != assess.SeverityHigh {
			t.Fatal("removed service must be high severity")
		}
	}
	// Incomplete evidence on one side: no change is inferred.
	after.Coverage[fabric.DimNVEPeers] = evidence.StatusPartial
	r, _ = a.AssessWith(t.Context(), cur, rules.Inputs{Previous: prev})
	if got := ruleKeys(r.Changes[0].Assessment.Findings); len(got["vxlan.change_nve_peers_lost"]) != 0 {
		t.Fatalf("change inferred from partial evidence: %v", got)
	}
}
