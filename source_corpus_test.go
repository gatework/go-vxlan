package vxlan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

// These source snapshots were exported from the Ruby reference and ctx_parser
// 0.2.4. Runtime Go parsing never invokes Ruby.
func TestSourceRubyCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/configuration_sources.json")
	if err != nil {
		t.Fatal(err)
	}
	var expectations map[string]Record
	if err = json.Unmarshal(raw, &expectations); err != nil {
		t.Fatal(err)
	}
	if len(expectations) != 431 {
		t.Fatalf("expected 431 source fixtures, got %d", len(expectations))
	}
	for name, want := range expectations {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata/configuration", name))
			if err != nil {
				t.Fatal(err)
			}
			var input struct {
				Text     string
				Complete bool
			}
			if err = json.Unmarshal(raw, &input); err != nil {
				t.Fatal(err)
			}
			p := &ConfigurationParser{}
			_, err = p.Parse(input.Text, input.Complete)
			if want["error"] != nil {
				if err == nil {
					t.Fatal("expected rejected input")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			d := p.Document()
			roots := []Record{}
			var walk func([]SourceBlock, any)
			walk = func(blocks []SourceBlock, parent any) {
				for _, b := range blocks {
					first, last := b.LineRange()
					roots = append(roots, Record{"first": first, "last": last, "parent": parent})
					walk(b.Children(), first)
				}
			}
			walk(d.Roots(), nil)
			captures := []Record{}
			for _, c := range d.Captures() {
				first, last := c.LineRange()
				captures = append(captures, Record{"path": c.Path(), "data": c.Data(), "first": first, "last": last, "complete": c.Complete()})
			}
			for _, value := range want["captures"].([]any) {
				r := value.(map[string]any)
				path := r["path"].([]any)
				for i := 1; i < len(path); i++ {
					previous := path[i-1]
					if previous == "vlan_vnis" || previous == "evpn" || previous == "members" {
						if n, ok := path[i].(float64); ok {
							path[i] = strconv.Itoa(int(n))
						}
					}
				}
			}
			got := Record{"states": d.States(), "roots": roots, "captures": captures}
			encoded, _ := json.Marshal(got)
			var normalized Record
			json.Unmarshal(encoded, &normalized)
			for _, key := range []string{"states", "roots", "captures"} {
				if !reflect.DeepEqual(normalized[key], want[key]) {
					t.Errorf("%s mismatch\ngot %s\nwant %s", key, mustJSON(normalized[key]), mustJSON(want[key]))
				}
			}
		})
	}
}
