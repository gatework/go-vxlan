package configuration_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/internal/record"
)

func TestDomainRubyCorpus(t *testing.T) {
	paths, err := filepath.Glob("../testdata/domain/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatal("missing Ruby domain corpus", err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			var row struct {
				Name     string
				Input    vxlan.Record
				Expected any
				Error    any
			}
			if e = json.Unmarshal(data, &row); e != nil {
				t.Fatal(e)
			}
			in := row.Input
			var got any
			var callErr error
			switch row.Name {
			case "recommendations", "fabric", "combine", "build", "eligible", "satisfied":
				// Typed parity tests in rules/ and change/ replay these cases;
				// the legacy review and ChangePlan they described are retired.
				return
			case "catalog", "route_targets", "subnets", "acl_rules", "acl_policy":
				// Typed equivalents in fabric/ and rules/ replay these cases.
				return
			case "bgp_neighbors", "prefix_references":
				// Retired: no rule consumes these relations.
				return
			case "scope":
				callErr = fabric.ValidatePolicyDocument(in["policy"])
				if callErr == nil {
					g := vxlan.Record{}
					for name, value := range record.Map(record.Map(in["policy"])["fabrics"]) {
						r := vxlan.Record{}
						for _, role := range []string{"leaves", "borders", "spines"} {
							r[role] = record.StringSlice(record.Map(value)[role])
						}
						g[name] = r
					}
					got = g
				}
			case "fingerprint":
				got, callErr = vxlan.Fingerprint(in["value"])
			default:
				t.Fatalf("unknown case %s", row.Name)
			}
			if row.Error != nil {
				if callErr == nil {
					t.Fatalf("%s expected error, got %#v", row.Name, got)
				}
				return
			}
			if callErr != nil {
				t.Fatal(callErr)
			}
			encoded, e := json.Marshal(got)
			if e != nil {
				t.Fatal(e)
			}
			var normalized any
			if e = json.Unmarshal(encoded, &normalized); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(normalized, row.Expected) {
				want, _ := json.MarshalIndent(row.Expected, "", "  ")
				actual, _ := json.MarshalIndent(normalized, "", "  ")
				t.Fatalf("%s mismatch\n got %s\nwant %s", row.Name, actual, want)
			}
		})
	}
}
