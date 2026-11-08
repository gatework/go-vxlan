package parser_test

import (
	"context"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/collect"
	"github.com/gatework/go-vxlan/parser"
	"github.com/gatework/go-vxlan/vendors"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

func TestModelParserSelection(t *testing.T) {
	spec := nxos.ProfileSpec()
	spec.ModelParsers = map[string]map[string]parser.ParseFunc{" N9K-C93180 ": {"nve_peers": func(text string, complete bool) (vxlan.Observation, error) {
		return observation("nve_peers", "complete", []vxlan.Record{{"model": true}}, nil), nil
	}}}
	registry, e := parser.NewRegistry(map[string]parser.ProfileSpec{"cisco_nxos": spec})
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
	snap, e := collect.CollectSession(context.Background(), &testSession{}, collect.Request{Target: vxlan.Record{}, Dimensions: []string{"nve_peers"}, Profile: profile})
	if e != nil || !snap.Complete() {
		t.Fatal(snap, e)
	}
}

func TestProfileValidationAndIsolation(t *testing.T) {
	for _, modify := range []func(*parser.ProfileSpec){
		func(s *parser.ProfileSpec) { s.Queries = append(s.Queries, s.Queries[2]) },
		func(s *parser.ProfileSpec) {
			s.ModelParsers = map[string]map[string]parser.ParseFunc{"n9k": {"bad": s.Queries[2].Parse}}
		},
		func(s *parser.ProfileSpec) { s.Queries[2].Parse = nil },
		func(s *parser.ProfileSpec) { s.Verification["fabric"] = nil },
		func(s *parser.ProfileSpec) { s.Verification[" "] = []string{"show running-config"} },
		func(s *parser.ProfileSpec) { s.Verification["fabric"][0] = " " },
	} {
		s := nxos.ProfileSpec()
		modify(&s)
		if _, e := parser.NewRegistry(map[string]parser.ProfileSpec{"cisco_nxos": s}); e == nil {
			t.Fatal("accepted invalid profile")
		}
	}
	registry := vendors.NewBuiltinRegistry()
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
		s := nxos.ProfileSpec()
		s.Queries[2].Command += string(c)
		if _, e := parser.NewRegistry(map[string]parser.ProfileSpec{"cisco_nxos": s}); e == nil {
			t.Fatalf("accepted control %d", c)
		}
		s = nxos.ProfileSpec()
		s.Preparation[0] += string(c)
		if _, e := parser.NewRegistry(map[string]parser.ProfileSpec{"cisco_nxos": s}); e == nil {
			t.Fatalf("accepted preparation control %d", c)
		}
		s = nxos.ProfileSpec()
		s.Verification["fabric"][0] += string(c)
		if _, e := parser.NewRegistry(map[string]parser.ProfileSpec{"cisco_nxos": s}); e == nil {
			t.Fatalf("accepted verification control %d", c)
		}
	}
}

func TestVerificationQueriesAreOwnedAndDoNotAddCollectionDimensions(t *testing.T) {
	spec := nxos.ProfileSpec()
	registry, err := parser.NewRegistry(map[string]parser.ProfileSpec{"cisco_nxos": spec})
	if err != nil {
		t.Fatal(err)
	}
	spec.Verification["fabric"][0] = "changed input"
	delete(spec.Verification, "fabric")
	for range 2 {
		profile, err := registry.Fetch("cisco_nxos", "")
		if err != nil {
			t.Fatal(err)
		}
		commands := profile.VerificationCommands("fabric")
		if len(commands) != 3 || commands[0] != "show running-config" || commands[2] != "show ip interface brief vrf all" {
			t.Fatalf("verification declaration changed: %v", commands)
		}
		commands[0] = "changed accessor"
		if profile.VerificationCommands("fabric")[0] != "show running-config" {
			t.Fatal("verification accessor leaked mutable state")
		}
		if len(profile.Dimensions()) != len(spec.Queries) || profile.Command("fabric") != "" || profile.Command("interfaces") != "show interface brief" || len(profile.VerificationCommands("unknown")) != 0 {
			t.Fatal("review queries changed collection declarations")
		}
	}
}

func observation(name, status string, rows, issues []vxlan.Record) vxlan.Observation {
	o, _ := vxlan.NewObservation(name, status, rows, issues, nil)
	return o
}

type testSession struct{}

func (*testSession) Read(context.Context, string) (collect.Capture, error) {
	return collect.Capture{Complete: true}, nil
}
