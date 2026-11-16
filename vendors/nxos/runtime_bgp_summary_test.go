package nxos

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
)

func TestBGPSummaryEvidence(t *testing.T) {
	scope := "BGP summary information for VRF BLUE, address family L2VPN EVPN\n"
	summary := "BGP table version is 123, L2VPN EVPN config peers 2, capable peers 1\n"
	text := scope + summary + "Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd\n" +
		"192.0.2.2 4 65001 10 20 123 0 0 1d 12\n"
	got, err := ParseRuntime("bgp_neighbors", text, true)
	if err != nil {
		t.Fatal(err)
	}
	want := vxlan.Record{"kind": "bgp_summary", "vrf": "BLUE", "address_family": "L2VPN EVPN", "table_version": int64(123), "configured_peers": int64(2), "capable_peers": int64(1), "line": 2}
	if !got.Complete() || len(got.Records) != 1 || !reflect.DeepEqual(got.Evidence, []vxlan.Record{want}) {
		t.Fatalf("summary evidence or neighbor identity changed: %#v", got)
	}
	if got.Records[0]["peer_ip"] != "192.0.2.2" || got.Records[0]["prefixes_received"] != int64(12) {
		t.Fatalf("summary became neighbor data: %v", got.Records)
	}
}

func TestBGPSummaryMultipleEmptyScopes(t *testing.T) {
	text := "BGP summary information for VRF BLUE, address family L2VPN EVPN\n" +
		"BGP table version is 1, L2VPN EVPN config peers 0, capable peers 0\nNo BGP neighbors\n\n" +
		"BGP summary information for VRF RED, address family L2VPN EVPN\n" +
		"BGP table version is 2\nNo BGP neighbors\n"
	got, err := ParseRuntime("bgp_neighbors", text, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete() || len(got.Records) != 0 || len(got.Evidence) != 2 {
		t.Fatalf("lost empty scope evidence: %#v", got)
	}
	if got.Evidence[0]["vrf"] != "BLUE" || got.Evidence[0]["line"] != 2 || got.Evidence[1]["vrf"] != "RED" || got.Evidence[1]["line"] != 6 {
		t.Fatalf("summary scope or physical line changed: %v", got.Evidence)
	}
	if _, exists := got.Evidence[1]["configured_peers"]; exists {
		t.Fatal("invented absent summary counters")
	}
}

func TestBGPSummaryIntegrity(t *testing.T) {
	scope := "BGP summary information for VRF BLUE, address family L2VPN EVPN\n"
	summary := "BGP table version is 1, L2VPN EVPN config peers 1, capable peers 0\n"
	for _, tc := range []struct {
		name, text string
		complete   bool
		summaries  int
	}{
		{name: "equivalent repeated summary", text: scope + summary + summary + "No BGP neighbors\n", complete: true, summaries: 1},
		{name: "case-insensitive summary metadata", text: scope + strings.ToLower(summary) + "No BGP neighbors\n", complete: true, summaries: 1},
		{name: "conflicting summary cannot recover", text: scope + summary + strings.Replace(summary, "version is 1", "version is 2", 1) + summary + "No BGP neighbors\n", complete: false, summaries: 0},
		{name: "unsupported address family", text: strings.Replace(scope, "L2VPN EVPN", "IPv4 Unicast", 1) + summary + "No BGP neighbors\n", complete: false, summaries: 0},
		{name: "summary without completion proof", text: scope + summary, complete: false, summaries: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRuntime("bgp_neighbors", tc.text, true)
			if err != nil {
				t.Fatal(err)
			}
			if got.Complete() != tc.complete || len(got.Evidence) != tc.summaries {
				t.Fatalf("unexpected summary integrity: %#v", got)
			}
		})
	}
}

func TestBGPSummaryExactIntegers(t *testing.T) {
	huge := "18446744073709551616"
	text := "BGP summary information for VRF BLUE, address family L2VPN EVPN\n" +
		"BGP table version is " + huge + ", L2VPN EVPN config peers " + huge + ", capable peers 0\nNo BGP neighbors\n"
	got, err := ParseRuntime("bgp_neighbors", text, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete() || len(got.Evidence) != 1 || got.Evidence[0]["table_version"] != json.Number(huge) || got.Evidence[0]["configured_peers"] != json.Number(huge) {
		t.Fatalf("summary integer lost precision: %#v", got)
	}
}
