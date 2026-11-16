package nxos

import (
	"strings"
	"testing"
)

func TestBGPSummaryScopeIntegrity(t *testing.T) {
	scope := "BGP summary information for VRF BLUE, address family L2VPN EVPN\n"
	summary := "BGP table version is 1, L2VPN EVPN config peers 0, capable peers 0\n"
	header := "Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd\n"
	row := "192.0.2.2 4 65001 10 20 1 0 0 1d 12\n"
	for _, tc := range []struct {
		name, text, issue string
		rows, summaries   int
	}{
		{
			name: "conflicting repeated scope",
			text: scope + summary + "No BGP neighbors\n" + scope +
				strings.Replace(summary, "version is 1", "version is 2", 1) + "No BGP neighbors\n",
			issue: "conflicting_bgp_summary",
		},
		{
			name:  "capable peers missing from body",
			text:  scope + "BGP table version is 1, L2VPN EVPN config peers 2, capable peers 2\n" + header + row,
			issue: "bgp_summary_peer_count_mismatch", rows: 1, summaries: 1,
		},
		{
			name:  "capable count contradicts empty marker",
			text:  scope + "BGP table version is 1, L2VPN EVPN config peers 1, capable peers 1\nNo BGP neighbors\n",
			issue: "bgp_summary_peer_count_mismatch", summaries: 1,
		},
		{
			name: "large capable count does not overflow",
			text: scope + "BGP table version is 1, L2VPN EVPN config peers 18446744073709551616, " +
				"capable peers 18446744073709551616\n" + header + row,
			issue: "bgp_summary_peer_count_mismatch", rows: 1, summaries: 1,
		},
		{
			name: "idle peer can exceed capable count",
			text: scope + "BGP table version is 1, L2VPN EVPN config peers 2, capable peers 1\n" + header + row +
				"192.0.2.3 4 65001 10 20 0 0 0 1d Idle\n",
			rows: 2, summaries: 1,
		},
		{
			name:      "equivalent repeated scope",
			text:      scope + summary + "No BGP neighbors\n" + scope + summary + "No BGP neighbors\n",
			summaries: 1,
		},
		{
			name: "different scopes keep independent counts",
			text: scope + summary + "No BGP neighbors\n" + strings.Replace(scope, "BLUE", "RED", 1) +
				"BGP table version is 1, L2VPN EVPN config peers 1, capable peers 1\n" + header + row,
			rows: 1, summaries: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, err := ParseRuntime("bgp_neighbors", tc.text, true)
			if err != nil {
				t.Fatal(err)
			}
			if o.Complete() != (tc.issue == "") || len(o.Records) != tc.rows || len(o.Evidence) != tc.summaries {
				t.Fatalf("unexpected integrity result: %#v", o)
			}
			if tc.issue != "" {
				found := false
				for _, issue := range o.Issues {
					found = found || issue["code"] == tc.issue
				}
				if !found {
					t.Fatalf("missing %s: %v", tc.issue, o.Issues)
				}
			}
		})
	}
}

func TestPortChannelIdentityIntegrity(t *testing.T) {
	header := "Group Port-Channel Type Protocol Member Ports\n"
	o, err := ParseRuntime("port_channels", header+"1 Po2(SU) Eth LACP Eth1/1(P)\n", true)
	if err != nil {
		t.Fatal(err)
	}
	if o.Complete() || len(o.Records) != 0 {
		t.Fatalf("conflicting group/interface accepted: %#v", o)
	}
	found := false
	for _, issue := range o.Issues {
		found = found || issue["code"] == "port_channel_identity_mismatch" && issue["line"] == 2
	}
	if !found {
		t.Fatal(o.Issues)
	}
	o, err = ParseRuntime("port_channels", header+"01 Po1(SU) Eth LACP Eth1/1(P)\n", true)
	if err != nil || !o.Complete() {
		t.Fatalf("equivalent numeric identities rejected: %#v, %v", o, err)
	}
}
