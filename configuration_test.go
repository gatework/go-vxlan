package vxlan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestConfigMinimum(t *testing.T) {
	o := ParseConfig("hostname LEAF\ninterface Vlan10\n  vrf member BLUE\n  ip address 10.0.10.1/24\nvlan 10\n  vn-segment 10010\n", true)
	if !o.Complete() {
		t.Fatalf("%+v", o.Issues)
	}
	if o.Records[0]["hostname"] != "LEAF" {
		t.Fatal(o)
	}
	o = ParseConfig("hostname LEAF\ninterface Vlan10\n  vrf member BLUE\n  vrf member RED\n", true)
	if o.Complete() || len(o.Records[0]["interfaces"].(Record)) != 0 {
		t.Fatal("conflicting vrf admitted")
	}
}
func TestConfigRubyCorpus(t *testing.T) {
	paths, _ := filepath.Glob("testdata/configuration/*.json")
	if len(paths) == 0 {
		t.Fatal("missing corpus")
	}
	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			b, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			var c struct {
				Text     string
				Complete bool
				Expected Record
			}
			if e = json.Unmarshal(b, &c); e != nil {
				t.Fatal(e)
			}
			got := ParseConfig(c.Text, c.Complete)
			j, _ := json.Marshal(got)
			var m Record
			json.Unmarshal(j, &m)
			delete(m, "started_at")
			delete(m, "completed_at")
			if !reflect.DeepEqual(m, c.Expected) {
				t.Errorf("input %q\ngot %s\nwant %s", c.Text, j, mustJSON(c.Expected))
			}
		})
	}
}
func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
