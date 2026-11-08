package vxlan_test

import (
	"fmt"
	"github.com/gatework/go-vxlan/vendors"
	"strings"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/collect"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/review"
)

func TestDocumentedGoContracts(t *testing.T) {
	integer, integerErr := vxlan.Fingerprint(vxlan.Record{"value": 1})
	decimal, decimalErr := vxlan.Fingerprint(vxlan.Record{"value": 1.0})
	if integerErr != nil || decimalErr != nil || integer != decimal {
		t.Fatal("integral JSON numeric values must remain stable across roundtrip")
	}
	profile, _ := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
	advice := review.Recommendations(vxlan.Record{"snapshot": vxlan.Record{"dimensions": vxlan.Record{"vpc": vxlan.Record{"status": "partial"}, "configuration": vxlan.Record{"status": "partial"}}}}, profile)
	items := record.Rows(advice["items"])
	if len(items) < 2 || items[0]["scope"] != "configuration" || items[1]["scope"] != "vpc" {
		t.Fatal("expected sorted dimension scopes")
	}
	r := collect.Request{Target: vxlan.Record{"password": "private-value"}}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", r, r, r), "private-value") {
		t.Fatal("request formatting leaked target")
	}
}
