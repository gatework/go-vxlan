package rules_test

import (
	"testing"

	"github.com/gatework/go-netops/assess"

	"github.com/gatework/go-vxlan/fabric"
)

func TestAdditionalRuntimeRules(t *testing.T) {
	d := &fabric.Device{
		Identity: fabric.Identity{Host: "fixture"},
		Coverage: complete(fabric.DimConfiguration, fabric.DimBGP, fabric.DimVPC, fabric.DimOSPF, fabric.DimInterfaces, fabric.DimPortChannels),
		Configuration: &fabric.Configuration{ReviewStatus: "complete", Interfaces: map[string]fabric.Interface{
			"Ethernet1/1":    {Shutdown: new(false), OSPF: "10 area 0", OSPFNetworkType: "point-to-point"},
			"Ethernet1/2":    {Shutdown: new(false), OSPF: "10 area 0", OSPFNetworkType: "broadcast"},
			"Ethernet1/3":    {ChannelGroup: new(10)},
			"port-channel10": {Shutdown: new(false)},
		}},
		BGPSummaries: []fabric.BGPSummary{{VRF: "default", ConfiguredPeers: counter("18446744073709551617"), CapablePeers: counter("18446744073709551616")}},
		OSPFNeighbors: []fabric.OSPFNeighbor{
			{Process: "10", VRF: "default", NeighborID: "192.0.2.1", State: "2way/-", Interface: "Eth1/1"},
			{Process: "10", VRF: "default", NeighborID: "192.0.2.2", State: "2way/drother", Interface: "Eth1/2"},
		},
		VPC:          &fabric.VPC{Attributes: map[string]string{"Per-vlan consistency status": "failed"}},
		Interfaces:   []fabric.InterfaceStatus{{Interface: "Eth1/1", State: "down"}, {Interface: "Eth1/3", State: "down"}},
		PortChannels: []fabric.PortChannel{{Group: 10, Interface: "Po10", Flags: "SD", Members: []fabric.PortChannelMember{{Interface: "Eth1/3", Flags: "D"}}}},
	}
	r := run(t, []*fabric.Device{d}, nil)
	for _, id := range []string{"vxlan.bgp_evpn_capability_gap", "vxlan.ospf_neighbor_not_full", "vxlan.vpc_peer_unhealthy", "vxlan.configured_interface_down", "vxlan.port_channel_member_down"} {
		got := findings(r, assess.RuleID(id))
		if len(got) != 1 {
			t.Fatalf("%s: %+v", id, got)
		}
		if got[0].Remediation != nil {
			t.Fatal("runtime finding generated a remediation")
		}
	}
}
