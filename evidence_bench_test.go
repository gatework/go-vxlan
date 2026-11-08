package vxlan_test

import (
	"encoding/json"
	"fmt"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

func benchmarkEvidence(rows int) vxlan.Record {
	records := make([]vxlan.Record, rows)
	for i := range records {
		records[i] = vxlan.Record{
			"vlan": i%4094 + 1, "interface": fmt.Sprintf("Ethernet1/%d", i%48+1),
			"mac":     fmt.Sprintf("0011.2233.%04x", i),
			"counter": json.Number("9007199254740993"), "fraction": json.Number("0.123456789012345678901"),
			"nil_rows": []vxlan.Record(nil), "empty_rows": []vxlan.Record{},
			"flags": []string{"dynamic", "local"},
		}
	}
	return vxlan.Record{
		"device": vxlan.Record{"host": "192.0.2.1", "name": "leaf"},
		"snapshot": vxlan.Snapshot{Dimensions: map[string]vxlan.Observation{
			"mac_addresses": {Name: "mac_addresses", Status: "complete", Records: records},
		}},
	}
}

func BenchmarkEvidenceProjection(b *testing.B) {
	for _, rows := range []int{128, 512, 2048} {
		b.Run(fmt.Sprintf("rows=%d", rows), func(b *testing.B) {
			input := benchmarkEvidence(rows)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := vxlan.ProjectRecord(input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkEvidenceClone(b *testing.B) {
	for _, rows := range []int{128, 512, 2048} {
		b.Run(fmt.Sprintf("rows=%d", rows), func(b *testing.B) {
			input, err := vxlan.ProjectRecord(benchmarkEvidence(rows))
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				record.Copy(input)
			}
		})
	}
}
