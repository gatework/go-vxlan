package configuration_test

import (
	"encoding/json"
	"github.com/gatework/go-vxlan/vendors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/configuration"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/review"
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
			case "recommendations":
				profile, _ := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
				got = review.Recommendations(record.Map(in["document"]), profile)
			case "fabric":
				got, callErr = review.ReviewFabric(record.Rows(in["documents"]), record.Map(in["policy"]))
			case "combine":
				got = review.CombineRecommendations(record.Map(in["advice"]), record.Rows(in["additions"]))
			case "build":
				var p *change.ChangePlan
				p, callErr = change.NewChangePlan(record.Map(in["change"]))
				if p != nil {
					got = vxlan.Record{"change": p.Change(), "commands": p.Commands(), "rollback": p.Rollback()}
				}
			case "eligible", "satisfied":
				p, e := change.NewChangePlan(record.Map(in["change"]))
				callErr = e
				if p != nil {
					if row.Name == "eligible" {
						got = p.Eligible(record.Map(in["config"]))
					} else {
						got = p.Satisfied(record.Map(in["after"]), record.Map(in["before"]))
					}
				}
			case "catalog":
				got = configuration.ServiceCatalog(record.Map(in["configs"]))
			case "route_targets":
				got = configuration.ServiceRouteTargets(in["entries"], in["asn"], in["vni"])
			case "scope":
				callErr = review.ValidateFabricPolicy(record.Map(in["policy"]))
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
			case "subnets":
				got, callErr = configuration.NewSubnetIndex(record.Map(in["config"])).Conflicts(record.String(in["address"]), in["vrf"], in["vni"], record.String(in["except_interface"]))
			case "bgp_neighbors":
				tuples := []any{}
				for _, n := range configuration.BGPNeighbors(record.Map(in["bgp"])) {
					tuples = append(tuples, []any{n["vrf"], n["peer"], n["settings"]})
				}
				got = tuples
			case "fingerprint":
				got, callErr = vxlan.Fingerprint(in["value"])
			case "acl_rules":
				got = configuration.ACLRules(in["entries"])
			case "acl_policy":
				got = configuration.ResolveACLPolicy(record.Map(in["config"]), in["entries"])
			case "prefix_references":
				got, callErr = configuration.PrefixListReferences(record.Map(in["config"]), in["family"].(string))
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
