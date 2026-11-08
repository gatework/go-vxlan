package configuration

import (
	"github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

// CompleteConfig returns the single complete configuration evidence record.
func CompleteConfig(document vxlan.Record) vxlan.Record {
	o := record.Map(record.At(document, "snapshot", "dimensions", "configuration"))
	if o["status"] != "complete" {
		return nil
	}
	r, ok := record.RecordSlice(o["records"])
	if !ok || len(r) != 1 || r[0]["review_status"] != "complete" {
		return nil
	}
	return r[0]
}
