package rules_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-netops/evidence"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/rules"
)

func complete(dims ...evidence.Dimension) evidence.Coverage {
	c := evidence.Coverage{}
	for _, d := range dims {
		c[d] = evidence.StatusComplete
	}
	return c
}

func run(t *testing.T, devices []*fabric.Device, policy *fabric.Policy) rules.Report {
	t.Helper()
	a, err := rules.NewAssessor(assess.Policy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := fabric.Build(devices, policy)
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.Assess(t.Context(), m)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func findings(r rules.Report, id assess.RuleID) []assess.Finding {
	var out []assess.Finding
	for _, d := range r.Devices {
		for _, f := range d.Assessment.Findings {
			if f.Rule == id {
				out = append(out, f)
			}
		}
	}
	for _, fa := range r.Fabrics {
		for _, f := range fa.Assessment.Findings {
			if f.Rule == id {
				out = append(out, f)
			}
		}
	}
	return out
}

func keys(fs []assess.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Subject.Key)
	}
	return out
}

func counter(s string) *fabric.Counter { c := fabric.Counter(s); return &c }

func TestRuntimeDeviceRules(t *testing.T) {
	d := &fabric.Device{
		Identity:      fabric.Identity{Host: "10.0.0.11"},
		Coverage:      complete(fabric.DimConfiguration, fabric.DimOSPF, fabric.DimBGP, fabric.DimVPC, fabric.DimPortChannels),
		Configuration: &fabric.Configuration{ReviewStatus: "complete"},
		OSPFNeighbors: []fabric.OSPFNeighbor{
			{Process: "UNDERLAY", NeighborID: "10.255.0.1", State: "full/-"},
			{Process: "UNDERLAY", NeighborID: "10.255.0.2", State: "2way/drother"},
			{Process: "UNDERLAY", NeighborID: "10.255.0.3", State: "exstart/-", Interface: "Eth1/49"},
		},
		BGPNeighbors: []fabric.BGPNeighbor{
			{VRF: "default", PeerIP: "10.255.0.1", State: "established", PrefixesReceived: counter("42")},
			{VRF: "default", PeerIP: "10.255.0.2", State: "established", PrefixesReceived: counter("0")},
			{VRF: "default", PeerIP: "10.255.0.3", State: "Idle"},
		},
		VPC: &fabric.VPC{DomainID: 10, PeerStatus: "peer adjacency formed ok", KeepaliveStatus: "Suspended as per user request", ConsistencyStatus: "success",
			PeerLinks: []fabric.VPCPeerLink{{ID: "1", Interface: "Po100", State: "up"}},
			Members: []fabric.VPCMember{
				{ID: "10", Interface: "Po10", State: "up", Consistency: "success"},
				{ID: "11", Interface: "Po11", State: "down", Consistency: "Not", Reason: "Consistency Check Not Performed"},
				{ID: "12", Interface: "Po12", State: "up", Consistency: "Not Applicable"},
			}},
		PortChannels: []fabric.PortChannel{
			{Group: 10, Interface: "Po10", Flags: "SU", Members: []fabric.PortChannelMember{{Interface: "Eth1/1", Flags: "P"}, {Interface: "Eth1/2", Flags: "D"}}},
			{Group: 20, Interface: "Po20", Flags: "SD", Members: []fabric.PortChannelMember{{Interface: "Eth1/3", Flags: "D"}}},
		},
	}
	r := run(t, []*fabric.Device{d}, nil)
	for id, want := range map[assess.RuleID][]string{
		"vxlan.ospf_neighbor_not_full":   {"10.255.0.3"},
		"vxlan.bgp_no_prefixes":          {"10.255.0.2"},
		"vxlan.bgp_session_down":         {"10.255.0.3"},
		"vxlan.vpc_peer_unhealthy":       {"keepalive_status"},
		"vxlan.vpc_member_inconsistent":  {"Po11"},
		"vxlan.port_channel_member_down": {"Eth1/2"},
	} {
		if got := keys(findings(r, id)); !slices.Equal(got, want) {
			t.Errorf("%s: got %v want %v", id, got, want)
		}
	}
	if f := findings(r, "vxlan.vpc_peer_unhealthy"); f[0].Severity != assess.SeverityCritical {
		t.Fatalf("vPC keepalive severity %v", f[0].Severity)
	}
}

func TestStateRulesReportObservedFaultsFromPartialTables(t *testing.T) {
	d := &fabric.Device{Identity: fabric.Identity{Host: "10.0.0.11"},
		Coverage:      evidence.Coverage{fabric.DimConfiguration: evidence.StatusComplete, fabric.DimNVEPeers: evidence.StatusPartial},
		Configuration: &fabric.Configuration{ReviewStatus: "complete"},
		NVEPeers:      []fabric.NVEPeer{{PeerIP: "10.1.1.2", State: "Down"}}}
	r := run(t, []*fabric.Device{d}, nil)
	got := findings(r, "vxlan.nve_peer_down")
	if len(got) != 1 || got[0].Detail == "" {
		t.Fatalf("observed fault from partial table: %+v", got)
	}
	if ev := findings(r, "vxlan.evidence_incomplete"); len(ev) != 1 || ev[0].Subject.Key != "nve_peers" {
		t.Fatalf("partial table not reported as incomplete: %+v", ev)
	}
}

func TestNVEShutdown(t *testing.T) {
	shut := true
	d := &fabric.Device{Identity: fabric.Identity{Host: "10.0.0.11"}, Coverage: complete(fabric.DimConfiguration),
		Configuration: &fabric.Configuration{ReviewStatus: "complete", Interfaces: map[string]fabric.Interface{},
			NVE: fabric.NVE{Interface: "nve1", Shutdown: &shut, SourceInterface: "loopback1", Members: map[string]fabric.NVEMember{"10010": {}}}}}
	got := findings(run(t, []*fabric.Device{d}, nil), "vxlan.nve_shutdown")
	if len(got) != 1 || !slices.Equal(got[0].Actual.([]string), []string{"shutdown", "source_interface_undefined"}) {
		t.Fatalf("%+v", got)
	}
}

// vtep builds a leaf with one loopback source address and L2 VNIs.
func vtep(host, source string, domain int, vnis ...int) *fabric.Device {
	no := false
	c := &fabric.Configuration{ReviewStatus: "complete", NVOverlayEVPN: true,
		Interfaces: map[string]fabric.Interface{"loopback1": {Addresses: []string{source + "/32"}}},
		VLANVNIs:   map[string]*int{}, EVPN: map[string]fabric.EVPNInstance{},
		NVE: fabric.NVE{Interface: "nve1", Shutdown: &no, SourceInterface: "loopback1", HostReachability: "bgp", Members: map[string]fabric.NVEMember{}}}
	for i, vni := range vnis {
		v := vni
		key := itoa(vni)
		c.VLANVNIs[itoa(100+i)] = &v
		c.NVE.Members[key] = fabric.NVEMember{Replication: "bgp"}
		c.EVPN[key] = fabric.EVPNInstance{Type: "l2"}
	}
	if domain > 0 {
		c.VPCDomain = &fabric.VPCDomain{ID: domain}
	}
	return &fabric.Device{Identity: fabric.Identity{Host: host}, Configuration: c,
		Coverage: complete(fabric.DimConfiguration, fabric.DimNVEPeers, fabric.DimL2RouteMACs)}
}

func itoa(n int) string { return fmt.Sprint(n) }

func TestNVEPeerMissing(t *testing.T) {
	a := vtep("10.0.0.11", "10.1.1.11", 0, 10010, 10020)
	b := vtep("10.0.0.12", "10.1.1.12", 0, 10010)
	c := vtep("10.0.0.13", "10.1.1.13", 0, 10030) // shares nothing with a or b
	a.NVEPeers = []fabric.NVEPeer{{PeerIP: "10.1.1.12", State: "Down"}}
	b.NVEPeers = []fabric.NVEPeer{{PeerIP: "10.1.1.11", State: "Up"}}
	policy := &fabric.Policy{Fabrics: map[string]fabric.Membership{"dc1": {Leaves: []string{"10.0.0.11", "10.0.0.12", "10.0.0.13"}}}}
	got := findings(run(t, []*fabric.Device{a, b, c}, policy), "vxlan.fabric_nve_peer_missing")
	if len(got) != 1 || got[0].Subject.Key != "10.0.0.12" || got[0].Subject.Parent.Key != "10.0.0.11" {
		t.Fatalf("%+v", got)
	}
}

func TestDuplicateLocalMACExcludesVPCPeers(t *testing.T) {
	a := vtep("10.0.0.11", "10.1.1.10", 10, 10010)
	b := vtep("10.0.0.12", "10.1.1.10", 10, 10010) // vPC peer of a
	c := vtep("10.0.0.13", "10.1.1.13", 0, 10010)
	local := func(mac string) []fabric.L2RouteMAC {
		return []fabric.L2RouteMAC{{TopologyID: 100, MAC: mac, Producer: "Local"}}
	}
	a.L2RouteMACs, b.L2RouteMACs = local("0050.5600.0001"), local("0050.5600.0001")
	c.L2RouteMACs = local("0050.5600.0002")
	policy := &fabric.Policy{Fabrics: map[string]fabric.Membership{"dc1": {Leaves: []string{"10.0.0.11", "10.0.0.12", "10.0.0.13"}}}}
	if got := findings(run(t, []*fabric.Device{a, b, c}, policy), "vxlan.fabric_duplicate_local_mac"); len(got) != 0 {
		t.Fatalf("vPC pair flagged: %+v", got)
	}
	c.L2RouteMACs = local("0050.5600.0001")
	got := findings(run(t, []*fabric.Device{a, b, c}, policy), "vxlan.fabric_duplicate_local_mac")
	if len(got) != 1 || got[0].Subject.Key != "0050.5600.0001" {
		t.Fatalf("%+v", got)
	}
}

func TestConsensusNamesTheOutlier(t *testing.T) {
	mtu := func(n int) *int { return &n }
	devices := []*fabric.Device{vtep("10.0.0.11", "10.1.1.11", 0, 10010), vtep("10.0.0.12", "10.1.1.12", 0, 10010), vtep("10.0.0.13", "10.1.1.13", 0, 10010)}
	for i, d := range devices {
		d.Configuration.AnycastMAC = "0001.0001.0001"
		m := 9216
		if i == 2 {
			m = 1500
			d.Configuration.AnycastMAC = "0002.0002.0002"
		}
		d.Configuration.Interfaces["Vlan100"] = fabric.Interface{VRF: "tenant", Anycast: true, Addresses: []string{"10.10.0.1/24"}, MTU: mtu(m)}
	}
	policy := &fabric.Policy{Fabrics: map[string]fabric.Membership{"dc1": {Leaves: []string{"10.0.0.11", "10.0.0.12", "10.0.0.13"}}}}
	r := run(t, devices, policy)
	for _, id := range []assess.RuleID{"vxlan.fabric_svi_attributes", "vxlan.fabric_anycast_mac"} {
		got := findings(r, id)
		if len(got) != 1 || got[0].Subject.Key != "10.0.0.13" || got[0].Category != assess.CategoryConsistency {
			t.Fatalf("%s: %+v", id, got)
		}
	}
}

func TestPolicyRejectsUnknownRule(t *testing.T) {
	if _, err := rules.NewAssessor(assess.Policy{Rules: map[assess.RuleID]assess.RulePolicy{"vxlan.nope": {}}}, nil); err == nil {
		t.Fatal("unknown rule accepted")
	}
	off := false
	a, err := rules.NewAssessor(assess.Policy{Rules: map[assess.RuleID]assess.RulePolicy{"vxlan.fabric_spine_l2": {Enabled: &off}, "vxlan.bgp_no_prefixes": {Severity: assess.SeverityHigh}}}, nil)
	if err != nil || a == nil {
		t.Fatal(err)
	}
	if len(rules.RuleIDs()) != len(rules.DeviceRules())+len(rules.FabricRules()) {
		t.Fatal("rule ids")
	}
}
