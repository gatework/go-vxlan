package vxlan_test

import (
	"fmt"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
)

func TestObservationOwnership(t *testing.T) {
	rows := []vxlan.Record{{"secret": "private", "nested": vxlan.Record{"value": "before"}}}
	o, err := vxlan.NewObservation("configuration", "complete", rows, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows[0]["nested"].(vxlan.Record)["value"] = "after"
	if o.Records[0]["nested"].(vxlan.Record)["value"] != "before" {
		t.Fatal("input alias")
	}
	if fmt.Sprint(o) != "Observation{name=configuration status=complete records=1}" {
		t.Fatal(fmt.Sprint(o))
	}
	if _, err = vxlan.NewObservation("x", "healthy", nil, nil, nil); err == nil {
		t.Fatal("invalid status accepted")
	}
	if (vxlan.Snapshot{}).Complete() {
		t.Fatal("empty snapshot complete")
	}
}
