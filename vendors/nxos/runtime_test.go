package nxos

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
)

func TestRuntimeRubyGolden(t *testing.T) {
	for _, file := range []string{"golden.json", "upstream-spec.json"} {
		data, err := os.ReadFile("../../testdata/runtime/" + file)
		if err != nil {
			t.Fatal(err)
		}
		var cases []struct {
			ID, Name, Text string
			Complete       bool
			Expected       struct {
				Status          string
				Records, Issues []vxlan.Record
			}
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if err = decoder.Decode(&cases); err != nil {
			t.Fatal(err)
		}
		for _, c := range cases {
			t.Run(c.ID, func(t *testing.T) {
				// Retain the Ruby fixtures, including their known logical-line bugs.
				// Only these explicit Go corrections differ; facts and status do not.
				for issueIndex, line := range runtimePhysicalLineCorrections[c.ID] {
					c.Expected.Issues[issueIndex]["line"] = line
				}
				got, err := ParseRuntime(c.Name, c.Text, c.Complete)
				if err != nil {
					t.Fatal(err)
				}
				// Round trip allows comparisons across Go integer widths and Ruby JSON numbers.
				encoded, _ := json.Marshal(struct {
					Status          string
					Records, Issues []vxlan.Record
				}{got.Status, got.Records, got.Issues})
				var actual any
				decoder := json.NewDecoder(bytes.NewReader(encoded))
				decoder.UseNumber()
				if err := decoder.Decode(&actual); err != nil {
					t.Fatal(err)
				}
				expectedEncoded, _ := json.Marshal(c.Expected)
				var expected any
				decoder = json.NewDecoder(bytes.NewReader(expectedEncoded))
				decoder.UseNumber()
				if err := decoder.Decode(&expected); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(actual, expected) {
					t.Errorf("input: %q\ngot  %s\nwant %s", c.Text, encoded, expectedEncoded)
				}
			})
		}
	}
}
func TestRuntimeUnsupportedDimensions(t *testing.T) {
	for _, name := range []string{"configuration", "unknown", ""} {
		if _, err := ParseRuntime(name, "", true); err == nil {
			t.Errorf("expected error for %q", name)
		}
	}
}
func TestRuntimeInvalidEncoding(t *testing.T) {
	got, err := ParseRuntime("interfaces", "\xff", true)
	if err != nil || got.Status != "partial" || len(got.Records) != 0 || len(got.Issues) != 1 || got.Issues[0]["code"] != "invalid_encoding" {
		t.Fatalf("got %#v, %v", got, err)
	}
}

func TestRuntimeCommandRegistry(t *testing.T) {
	want := []string{"configuration", "cdp_neighbors", "nve_peers", "nve_vnis", "bgp_neighbors", "ospf_neighbors", "vpc", "interfaces", "port_channels", "mac_addresses", "l2route_macs", "l2route_mac_ips"}
	names := DimensionNames()
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("dimension order: %v", names)
	}
	commands := Commands()
	if len(commands) != 12 || commands["configuration"] != "show running-config" || commands["l2route_mac_ips"] != "show l2route evpn mac-ip all" {
		t.Fatalf("commands: %v", commands)
	}
	names[0] = "changed"
	commands["configuration"] = "changed"
	if DimensionNames()[0] != "configuration" || Commands()["configuration"] != "show running-config" {
		t.Fatal("registry aliases mutable state")
	}
}

func TestRuntimePhysicalIssueLines(t *testing.T) {
	cases := []struct {
		name      string
		dimension string
		text      string
		wantLine  int
	}{
		{
			name:      "wrapped nve header",
			dimension: "nve_peers",
			text: "Interface Peer-IP State LearnType Uptime Route\n" +
				"r-Mac\n" +
				"bad row\n",
			wantLine: 3,
		},
		{
			name:      "wrapped bgp header",
			dimension: "bgp_neighbors",
			text: "Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/\n" +
				"PfxRcd\n" +
				"bad row\n",
			wantLine: 3,
		},
		{
			name:      "second bgp scope",
			dimension: "bgp_neighbors",
			text: "BGP summary information for VRF a, address family L2VPN EVPN\n" +
				"No BGP neighbors\n" +
				"BGP summary information for VRF b, address family L2VPN EVPN\n" +
				"bad row\n",
			wantLine: 4,
		},
		{
			name:      "second ospf scope",
			dimension: "ospf_neighbors",
			text: "OSPF Process ID a VRF default\n" +
				"No OSPF neighbors\n" +
				"OSPF Process ID b VRF default\n" +
				"bad row\n",
			wantLine: 4,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, ending := range []string{"\n", "\r\n"} {
				got, err := ParseRuntime(tc.dimension, strings.ReplaceAll(tc.text, "\n", ending), true)
				if err != nil {
					t.Fatal(err)
				}
				if got.Status != "partial" {
					t.Fatalf("status = %s", got.Status)
				}
				found := false
				for _, issue := range got.Issues {
					if issue["code"] == "unparsed_row" {
						found = true
						if issue["line"] != tc.wantLine {
							t.Errorf("line = %v, want %d", issue["line"], tc.wantLine)
						}
					}
				}
				if !found {
					t.Fatalf("missing unparsed_row: %v", got.Issues)
				}
			}
		})
	}
}

// Physical lines checked against the original fixture text. These are the
// documented Go corrections to Ruby's folded-row and per-scope line numbers.
var runtimePhysicalLineCorrections = map[string]map[int]int{
	"bgp/equivalent_identity": {0: 14},
	"nve/broken_wrap":         {0: 3, 1: 4},
	"scope/ospf/0":            {0: 9},
	"scope/ospf/1":            {0: 10},
	"scope/ospf/2":            {0: 10},
	"scope/ospf/3":            {0: 8},
	"scope/ospf/4":            {0: 8},
	"upstream/1586c01b2f302204f99c24e3d0cc8fc7b62314f19fac5972dca0a1c2ef557df4": {0: 3, 1: 4},
	"upstream/56fd0d426ba46e88be40950646f1a1baa9def2134787b96aabc60690b3d7a699": {0: 519},
}

func TestRuntimeExistingStringInputSizes(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
	}{
		{name: "more than default line limit", prefix: strings.Repeat("\n", 200_001)},
		{name: "more than default byte limit", prefix: strings.Repeat(" ", (16<<20)+1) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRuntime("nve_peers", tc.prefix+"No peers\n", true)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Complete() || len(got.Records) != 0 || len(got.Issues) != 0 {
				t.Fatalf("previously accepted string input rejected: %v", got)
			}
		})
	}
}

func TestL2RouteEmptyTableForms(t *testing.T) {
	macHeader := "Topology    Mac Address    Prod   Flags         Seq No     Next-Hops"
	macRuler := "----------- -------------- ------ ------------- ---------- ----------------"
	ipHeader := "Topology    Mac Address    Host IP         Prod   Flags         Seq No     Next-Hops"
	ipRuler := "----------- -------------- --------------- ------ ---------- ---------------"
	for _, tc := range []struct {
		name, dimension, text           string
		transportComplete, wantComplete bool
	}{
		{"mac zero rows", "l2route_macs", macHeader + "\n" + macRuler + "\n", true, true},
		{"legacy mac-ip zero rows", "l2route_mac_ips", ipHeader + "\n" + ipRuler + "\n", true, true},
		{"mac-ip zero rows", "l2route_mac_ips", ipHeader + "\n----------- -------------- --------------- ------ ---------- ---------- ----------------\n", true, true},
		{"missing ruler", "l2route_macs", macHeader + "\n", true, false},
		{"truncated ruler", "l2route_macs", macHeader + "\n----------- -------------- ------ ------------- ---------- --\n", true, false},
		{"truncated legacy ruler", "l2route_mac_ips", ipHeader + "\n" + strings.TrimSuffix(ipRuler, "---") + "\n", true, false},
		{"empty response", "l2route_macs", "\n", true, false},
		{"unknown header", "l2route_macs", strings.Replace(macHeader, "Prod", "Unknown", 1) + "\n" + macRuler + "\n", true, false},
		{"unknown tail", "l2route_macs", macHeader + "\n" + macRuler + "\nunknown\n", true, false},
		{"incomplete transport", "l2route_macs", macHeader + "\n" + macRuler + "\n", false, false},
		{"contradictory total", "l2route_macs", macHeader + "\n" + macRuler + "\nTotal routes: 1\n", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, ending := range []string{"\n", "\r\n"} {
				o, err := ParseRuntime(tc.dimension, strings.ReplaceAll(tc.text, "\n", ending), tc.transportComplete)
				if err != nil || o.Complete() != tc.wantComplete || len(o.Records) != 0 {
					t.Fatalf("got %#v, error %v", o, err)
				}
			}
		})
	}
}
