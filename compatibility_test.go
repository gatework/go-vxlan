package vxlan_test

import (
	"fmt"
	"github.com/gatework/go-vxlan/vendors"
	"strings"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/collect"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/rules"

	"github.com/gatework/go-netops/assess"
)

func TestDocumentedGoContracts(t *testing.T) {
	integer, integerErr := vxlan.Fingerprint(vxlan.Record{"value": 1})
	decimal, decimalErr := vxlan.Fingerprint(vxlan.Record{"value": 1.0})
	if integerErr != nil || decimalErr != nil || integer != decimal {
		t.Fatal("integral JSON numeric values must remain stable across roundtrip")
	}
	profile, _ := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
	device, err := fabric.EncodeDocument(vxlan.Record{"device": vxlan.Record{"host": "192.0.2.1"}, "snapshot": vxlan.Record{"dimensions": vxlan.Record{"vpc": vxlan.Record{"status": "partial"}, "configuration": vxlan.Record{"status": "partial"}}}})
	if err != nil {
		t.Fatal(err)
	}
	model, _ := fabric.Build([]*fabric.Device{device}, nil)
	assessor, _ := rules.NewAssessor(assess.Policy{}, profile)
	report, err := assessor.Assess(t.Context(), model)
	if err != nil {
		t.Fatal(err)
	}
	var scopes []string
	for _, f := range report.Devices[0].Assessment.Findings {
		if f.Rule == "vxlan.evidence_incomplete" {
			scopes = append(scopes, f.Subject.Key)
		}
	}
	if len(scopes) < 2 || scopes[0] != "configuration" || scopes[1] != "vpc" {
		t.Fatalf("expected sorted dimension scopes, got %v", scopes)
	}
	r := collect.Request{Target: vxlan.Record{"password": "private-value"}}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", r, r, r), "private-value") {
		t.Fatal("request formatting leaked target")
	}
}
