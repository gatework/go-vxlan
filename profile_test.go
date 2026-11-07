package vxlan

import (
	"context"
	"testing"
)

func TestModelParserSelection(t *testing.T) {
	spec := NXOSProfileSpec()
	spec.ModelParsers = map[string]map[string]ParseFunc{" N9K-C93180 ": {"show nve peers": func(text string, complete bool) (Observation, error) {
		return observation("nve_peers", "complete", []Record{{"model": true}}, nil), nil
	}}}
	registry, e := NewParserRegistry(map[string]ProfileSpec{"cisco_nxos": spec})
	if e != nil {
		t.Fatal(e)
	}
	delete(spec.ModelParsers, " N9K-C93180 ")
	profile, e := registry.Fetch(" CISCO_NXOS ", "n9k-c93180")
	if e != nil {
		t.Fatal(e)
	}
	o, e := profile.Parse("nve_peers", "", true)
	if e != nil || o.Records[0]["model"] != true {
		t.Fatal(o, e)
	}
	snap, e := CollectSession(context.Background(), &testSession{}, Request{Target: Record{}, Model: "N9K-C93180", Dimensions: []string{"nve_peers"}, Registry: registry})
	if e != nil || !snap.Complete() {
		t.Fatal(snap, e)
	}
}

func TestProfileValidationAndIsolation(t *testing.T) {
	for _, modify := range []func(*ProfileSpec){
		func(s *ProfileSpec) { s.Parsers["show other"] = s.Parsers["show nve peers"] },
		func(s *ProfileSpec) {
			s.ModelParsers = map[string]map[string]ParseFunc{"n9k": {"bad": s.Parsers["show nve peers"]}}
		},
		func(s *ProfileSpec) { delete(s.Parsers, "show nve peers") },
	} {
		s := NXOSProfileSpec()
		modify(&s)
		if _, e := NewParserRegistry(map[string]ProfileSpec{"cisco_nxos": s}); e == nil {
			t.Fatal("accepted invalid profile")
		}
	}
	registry := DefaultParserRegistry()
	p, e := registry.Fetch("cisco_nxos", "unknown-model")
	if e != nil {
		t.Fatal(e)
	}
	m := p.Commands()
	delete(m, "configuration")
	if p.Command("configuration") == "" {
		t.Fatal("alias")
	}
	if _, e = p.Parse("configuration", "hostname x\x00", true); e == nil {
		t.Fatal("malformed source accepted")
	}
}

func TestProfileRejectsTerminalControls(t *testing.T) {
	for _, c := range []byte{0, 9, 10, 11, 12, 13, 27, 31, 127} {
		s := NXOSProfileSpec()
		original := s.Commands["nve_peers"]
		command := original + string(c)
		s.Commands["nve_peers"] = command
		s.Parsers[command] = s.Parsers[original]
		delete(s.Parsers, original)
		if _, e := NewParserRegistry(map[string]ProfileSpec{"cisco_nxos": s}); e == nil {
			t.Fatalf("accepted control %d", c)
		}
	}
}
