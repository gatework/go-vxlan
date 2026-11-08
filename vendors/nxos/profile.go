package nxos

import (
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/parser"
)

// The single ordered declaration drives profile selection, read commands and
// parser dispatch. Runtime parsers retain their actual per-command grammar.
func querySpecs() []parser.QuerySpec {
	return []parser.QuerySpec{
		{Dimension: "configuration", Command: "show running-config", Parse: ParseConfigChecked},
		{Dimension: "cdp_neighbors", Command: "show cdp neighbors detail", Parse: runtimeParser("cdp_neighbors")},
		{Dimension: "nve_peers", Command: "show nve peers", Parse: runtimeParser("nve_peers")},
		{Dimension: "nve_vnis", Command: "show nve vni", Parse: runtimeParser("nve_vnis")},
		{Dimension: "bgp_neighbors", Command: "show bgp l2vpn evpn summary", Parse: runtimeParser("bgp_neighbors")},
		{Dimension: "ospf_neighbors", Command: "show ip ospf neighbors", Parse: runtimeParser("ospf_neighbors")},
		{Dimension: "vpc", Command: "show vpc brief", Parse: runtimeParser("vpc")},
		{Dimension: "interfaces", Command: "show interface brief", Parse: runtimeParser("interfaces")},
		{Dimension: "port_channels", Command: "show port-channel summary", Parse: runtimeParser("port_channels")},
		{Dimension: "mac_addresses", Command: "show mac address-table", Parse: runtimeParser("mac_addresses")},
		{Dimension: "l2route_macs", Command: "show l2route evpn mac all", Parse: runtimeParser("l2route_macs")},
		{Dimension: "l2route_mac_ips", Command: "show l2route evpn mac-ip all", Parse: runtimeParser("l2route_mac_ips")},
	}
}

func runtimeParser(dimension string) parser.ParseFunc {
	return func(text string, complete bool) (vxlan.Observation, error) {
		return ParseRuntime(dimension, text, complete)
	}
}

// ProfileSpec returns owned declarations for NX-OS evidence collection.
func ProfileSpec() parser.ProfileSpec {
	return parser.ProfileSpec{
		Queries: querySpecs(),
		Verification: map[string][]string{
			"fabric": {"show running-config", "show nve vni", "show ip interface brief vrf all"},
		},
		Preparation: []string{"terminal length 0", "terminal width 511"}, AbsentReason: absentReason,
	}
}

// DimensionNames returns the default collection order.
func DimensionNames() []string {
	queries := querySpecs()
	names := make([]string, len(queries))
	for i, q := range queries {
		names[i] = q.Dimension
	}
	return names
}

// Commands returns the dimension-to-command index derived from the declarations.
func Commands() map[string]string {
	queries := querySpecs()
	commands := make(map[string]string, len(queries))
	for _, q := range queries {
		commands[q.Dimension] = q.Command
	}
	return commands
}
