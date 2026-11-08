package cli

import (
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/report"
)

func normalize(value any) vxlan.Record {
	record, err := vxlan.ProjectRecord(value)
	if err != nil {
		panic(err)
	}
	return record
}
func jsonBytes(value any) []byte {
	body, err := report.EncodeJSON(value)
	if err != nil {
		panic(err)
	}
	return body
}
func fingerprint(value any) string {
	digest, err := vxlan.Fingerprint(value)
	if err != nil {
		panic(err)
	}
	return digest
}
