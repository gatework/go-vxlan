package vxlan

import (
	"fmt"
	"strings"
	"testing"
)

func TestDocumentedGoContracts(t *testing.T) {
	if Fingerprint(Record{"value": 1}) != Fingerprint(Record{"value": 1.0}) {
		t.Fatal("integral JSON numeric values must remain stable across roundtrip")
	}
	advice := Recommendations(Record{"snapshot": Record{"dimensions": Record{"vpc": Record{"status": "partial"}, "configuration": Record{"status": "partial"}}}})
	items := cfgRows(advice["items"])
	if len(items) < 2 || items[0]["scope"] != "configuration" || items[1]["scope"] != "vpc" {
		t.Fatal("expected sorted dimension scopes")
	}
	r := Request{Target: Record{"password": "private-value"}}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", r, r, r), "private-value") {
		t.Fatal("request formatting leaked target")
	}
}
