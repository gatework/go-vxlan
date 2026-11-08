package nxos

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
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
