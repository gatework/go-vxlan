package vxlan

import (
	"fmt"
	"testing"
)

func TestObservationOwnership(t *testing.T) {
	rows := []Record{{"secret": "private", "nested": Record{"value": "before"}}}
	o, err := NewObservation("configuration", "complete", rows, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows[0]["nested"].(Record)["value"] = "after"
	if o.Records[0]["nested"].(Record)["value"] != "before" {
		t.Fatal("input alias")
	}
	if fmt.Sprint(o) != "Observation{name=configuration status=complete records=1}" {
		t.Fatal(fmt.Sprint(o))
	}
	if _, err = NewObservation("x", "healthy", nil, nil, nil); err == nil {
		t.Fatal("invalid status accepted")
	}
	if (Snapshot{}).Complete() {
		t.Fatal("empty snapshot complete")
	}
}
