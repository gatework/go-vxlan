package vxlan

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func parseSource(t *testing.T, text string) (Observation, *ConfigurationDocument) {
	t.Helper()
	p := &ConfigurationParser{}
	o, err := p.Parse(text, true)
	if err != nil {
		t.Fatal(err)
	}
	return o, p.Document()
}
func oneCapture(t *testing.T, d *ConfigurationDocument, path ...any) SourceCapture {
	t.Helper()
	c := d.CapturesFor(path...)
	if len(c) != 1 {
		t.Fatalf("path %v: %d captures", path, len(c))
	}
	return c[0]
}
func TestSourceExactInterface(t *testing.T) {
	source := "hostname LEAF\r\ninterface Vlan10\r\n  description Users\r\n  vrf member BLUE\r\n  ip address 10.0.10.1/24\r\n! retained comment\r\n\r\ninterface Ethernet1/1\r\n  no shutdown\r\nend\r\n"
	o, d := parseSource(t, source)
	c := oneCapture(t, d, "interfaces", "Vlan10")
	if !o.Complete() || !c.Complete() || d.Position() != d.Size() || d.Size() != 10 {
		t.Fatalf("%v %v", o, d)
	}
	if c.Content() != strings.TrimPrefix(strings.Split(source, "interface Ethernet1/1")[0], "hostname LEAF\r\n") {
		t.Fatal("source bytes changed")
	}
	first, last := c.Block().LineRange()
	if first != 2 || last != 7 {
		t.Fatalf("range %d..%d", first, last)
	}
	children := c.Block().Children()
	if len(children) != 3 || children[0].Line() != 3 || children[2].Line() != 5 {
		t.Fatal(children)
	}
	if !reflect.DeepEqual(c.Data(), cfgMap(o.Records[0]["interfaces"])["Vlan10"]) {
		t.Fatal("projection mismatch")
	}
	o.Records[0]["interfaces"].(Record)["Vlan10"].(Record)["description"] = "Changed"
	c.Data().(Record)["description"] = "Also changed"
	if c.Data().(Record)["description"] != "Users" {
		t.Fatal("capture aliases returned data")
	}
}
func TestSourcePureCR(t *testing.T) {
	source := "hostname LEAF\r! comment\r\rinterface Vlan10\r  description Users\r  ip address 10.0.10.1/24"
	o, d := parseSource(t, source)
	normalized := ParseConfig(strings.ReplaceAll(source, "\r", "\n"), true)
	if !reflect.DeepEqual(o.Records, normalized.Records) || d.Content() != source {
		t.Fatal("source/digest mismatch")
	}
	c := oneCapture(t, d, "interfaces", "Vlan10")
	a, b := c.Block().LineRange()
	if a != 4 || b != 6 || c.Content() != "interface Vlan10\r  description Users\r  ip address 10.0.10.1/24" {
		t.Fatal(c)
	}
}
func TestSourceNestedPaths(t *testing.T) {
	text := "hostname LEAF\ninterface nve1\n  source-interface Loopback0\n  member vni 10110\n    ingress-replication protocol bgp\n    suppress-arp\nrouter bgp 65000\n  template peer SPINES\n    remote-as 65000\n  neighbor 192.0.2.1\n    inherit peer SPINES\n    address-family l2vpn evpn\n      send-community extended\n"
	o, d := parseSource(t, text)
	paths := [][]any{{"nve", "members", "10110"}, {"bgp", "templates", "SPINES"}, {"bgp", "neighbors", "192.0.2.1"}, {"bgp", "neighbors", "192.0.2.1", "address_families", "l2vpn evpn"}}
	for _, p := range paths {
		c := oneCapture(t, d, p...)
		v := any(o.Records[0])
		for _, k := range p {
			v = v.(Record)[k.(string)]
		}
		if !c.Complete() || !reflect.DeepEqual(c.Data(), v) {
			t.Fatal(c, p)
		}
	}
	if oneCapture(t, d, paths[0]...).Content() != "  member vni 10110\n    ingress-replication protocol bgp\n    suppress-arp\n" {
		t.Fatal("nested range")
	}
}
func TestSourceFlattenedAF(t *testing.T) {
	o, d := parseSource(t, "hostname LEAF\nvrf context BLUE\n  address-family ipv4 unicast\n    route-target both auto evpn\n    export vrf default 100 map SHARED allow-vpn\n")
	for _, key := range []string{"route_targets", "exports"} {
		c := oneCapture(t, d, "vrfs", "BLUE", key, 0)
		v := cfgRows(cfgMap(cfgMap(o.Records[0]["vrfs"])["BLUE"])[key])[0]
		if c.Block().Line() != 3 || !reflect.DeepEqual(c.Data(), v) || !strings.Contains(c.Content(), "export vrf default") {
			t.Fatal(c)
		}
	}
}
func TestSourceStates(t *testing.T) {
	cases := []struct {
		name, text string
		states     []LineState
	}{
		{"unsupported", "hostname LEAF\ninterface Vlan10\n  description Users\n  switchport\n  ip address dhcp extra\n! comment\nusername admin password SECRET\n", []LineState{LineParsed, LineParsed, LineParsed, LineParsed, LineUnsupported, LineIgnored, LineIgnored}},
		{"invalid child", "hostname LEAF\ninterface Vlan10\n  ip address 999.0.0.1/24\n  description Not visited\ninterface Ethernet1/1\n  no shutdown\n", []LineState{LineParsed, LineParsed, LineInvalid, LinePending, LineParsed, LineParsed}},
		{"misplaced", "hostname LEAF\ninterface Vlan10\n  vrf member BLUE\n    ip address 10.0.10.1/24\n", []LineState{LineParsed, LineParsed, LineParsed, LineUnsupported}},
		{"duplicate", "hostname LEAF\ninterface Vlan10\n  no shutdown\ninterface Vlan10\n  shutdown\n", []LineState{LineParsed, LineInvalid, LineParsed, LineInvalid, LinePending}},
		{"pagination", "hostname LEAF\ninterface Vlan10\n  description Users\n  --More--\n  no shutdown\n", []LineState{LineParsed, LineParsed, LineParsed, LineInvalid, LineParsed}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			o, d := parseSource(t, tt.text)
			if o.Complete() || !reflect.DeepEqual(d.States(), tt.states) {
				t.Fatalf("%v want %v, issues %v", d.States(), tt.states, o.Issues)
			}
			for _, c := range d.CapturesFor("interfaces", "Vlan10") {
				if c.Complete() {
					t.Fatal("incomplete capture claimed complete")
				}
			}
			if tt.name == "invalid child" && len(d.CapturesFor("interfaces", "Vlan10")) != 0 {
				t.Fatal("captured rejected scope")
			}
		})
	}
}
func TestSourcePrivacyAndIsolation(t *testing.T) {
	p := &ConfigurationParser{}
	_, err := p.Parse("hostname LEAF\ninterface Vlan10\n  description SECRET\nusername admin password SECRET\n", true)
	if err != nil {
		t.Fatal(err)
	}
	d := p.Document()
	c := oneCapture(t, d, "interfaces", "Vlan10")
	for _, v := range []any{p, *p, d, *d, []ConfigurationDocument{*d}, d.Roots(), d.Lines(), d.Captures(), c, c.Block()} {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(b), "SECRET") || strings.Contains(fmt.Sprintf("%v %+v %#v", v, v, v), "SECRET") {
			t.Fatalf("source leak: %T", v)
		}
	}
	p.Parse("hostname NEW\n", true)
	if len(p.Document().CapturesFor("interfaces", "Vlan10")) != 0 || !strings.Contains(c.Content(), "SECRET") {
		t.Fatal("parse isolation")
	}
	for _, text := range []string{"hostname bad\x00\n", "hostname \xff\n"} {
		if _, e := p.Parse(text, true); e == nil || p.Document() != nil {
			t.Fatal("invalid input did not clear document")
		}
		if _, e := ParseConfigChecked(text, true); e == nil {
			t.Fatal("checked parse admitted invalid input")
		}
		if ParseConfig(text, true).Status != "partial" {
			t.Fatal("compat parser must return partial")
		}
	}
}
func TestSourceFinalFeatureAndPolicyPaths(t *testing.T) {
	_, d := parseSource(t, "hostname LEAF\nfeature ospf\nfeature bgp\nfeature ospf\nip prefix-list BLUE seq 30 permit 10.3.0.0/16\nip prefix-list BLUE seq 10 permit 10.1.0.0/16\nip prefix-list BLUE seq 30 deny 10.3.0.0/16\nip prefix-list BLUE seq 20 permit 10.2.0.0/16\n")
	c := d.CapturesFor("features", 1)
	if len(c) != 2 || c[0].Data() != "ospf" || c[0].Block().Line() != 2 || c[1].Block().Line() != 4 {
		t.Fatal(c)
	}
	for i, seq := range []int{10, 20} {
		c := oneCapture(t, d, "prefix_lists", "BLUE", i)
		if c.Data().(Record)["sequence"] != seq {
			t.Fatal(c.Data())
		}
	}
	if len(d.CapturesFor("prefix_lists", "BLUE", 2)) != 0 {
		t.Fatal("stale policy indexes")
	}
}

func TestSourceInspectionAndCopies(t *testing.T) {
	source := "hostname LEAF\r\ninterface Vlan10\r\n  ip address invalid\r\n  description pending"
	_, d := parseSource(t, source)
	if d.Complete() || !d.EOF() || d.Parsed(2) || !d.Parsed(0) || !d.Visited(3) || d.Visited(4) {
		t.Fatal("incorrect inspection flags")
	}
	for _, i := range []int{-1, 4} {
		if _, err := d.State(i); err == nil {
			t.Fatal("out-of-range state accepted")
		}
	}
	if state, err := d.State(2); err != nil || state != LineInvalid {
		t.Fatal(state, err)
	}
	if d.UnparsedContent() != "  ip address invalid\r\n  description pending" || len(d.UnparsedLines()) != 2 {
		t.Fatal("unresolved source changed")
	}
	lines := d.Lines()
	if lines[1].Number() != 2 || lines[1].Index() != 1 || lines[2].Indent() != 2 || lines[2].Text() != "ip address invalid" || lines[2].Content() != "  ip address invalid\r\n" {
		t.Fatal("line metadata/content")
	}
	var joined strings.Builder
	for _, line := range lines {
		joined.WriteString(line.Content())
	}
	if joined.String() != source {
		t.Fatal("source line split changed bytes")
	}
	states := d.States()
	states[2] = LineParsed
	roots := d.Roots()
	root := roots[1]
	rootStates := root.States()
	rootStates[1] = LineParsed
	children := root.Children()
	children[0] = SourceBlock{}
	roots[1] = SourceBlock{}
	lines[0] = SourceLine{}
	if d.Complete() || root.Complete() || root.Header().Text() != "interface Vlan10" || root.Children()[0].Line() != 3 || len(root.Lines()) != 3 {
		t.Fatal("source view mutated through returned slices")
	}
	p := &ConfigurationParser{}
	o, err := p.Parse("hostname LEAF\n", false)
	if err != nil || o.Complete() || !p.Document().Complete() {
		t.Fatal("transport completeness conflated with source resolution")
	}
	_, good := parseSource(t, "hostname LEAF\ninterface Vlan10\n  ip address 10.0.0.1/24\n")
	capture := oneCapture(t, good, "interfaces", "Vlan10")
	path := capture.Path()
	path[1] = "other"
	data := capture.Data().(Record)
	data["addresses"].([]string)[0] = "changed"
	if len(good.CapturesFor("interfaces", "Vlan10")) != 1 || capture.Data().(Record)["addresses"].([]string)[0] != "10.0.0.1/24" {
		t.Fatal("capture snapshot aliased")
	}
}
