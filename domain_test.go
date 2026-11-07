package vxlan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDomainRubyCorpus(t *testing.T) {
	paths, err := filepath.Glob("testdata/domain/*.json")
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
				Input    Record
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
				got = Recommendations(cfgMap(in["document"]))
			case "fabric":
				got, callErr = ReviewFabric(cfgRows(in["documents"]), cfgMap(in["policy"]))
			case "combine":
				got = CombineRecommendations(cfgMap(in["advice"]), cfgRows(in["additions"]))
			case "build":
				var p *ChangePlan
				p, callErr = NewChangePlan(cfgMap(in["change"]))
				if p != nil {
					got = Record{"change": p.Change(), "commands": p.Commands(), "rollback": p.Rollback()}
				}
			case "eligible", "satisfied":
				p, e := NewChangePlan(cfgMap(in["change"]))
				callErr = e
				if p != nil {
					if row.Name == "eligible" {
						got = p.Eligible(cfgMap(in["config"]))
					} else {
						got = p.Satisfied(cfgMap(in["after"]), cfgMap(in["before"]))
					}
				}
			case "catalog":
				got = ServiceCatalog(cfgMap(in["configs"]))
			case "route_targets":
				got = ServiceRouteTargets(in["entries"], in["asn"], in["vni"])
			case "scope":
				callErr = ValidateFabricPolicy(cfgMap(in["policy"]))
				if callErr == nil {
					g := Record{}
					for name, value := range cfgMap(cfgMap(in["policy"])["fabrics"]) {
						r := Record{}
						for _, role := range fabricRoles {
							r[role] = cfgStrings(cfgMap(value)[role])
						}
						g[name] = r
					}
					got = g
				}
			case "subnets":
				got, callErr = NewSubnetIndex(cfgMap(in["config"])).Conflicts(domainString(in["address"]), in["vrf"], in["vni"], domainString(in["except_interface"]))
			case "bgp_neighbors":
				tuples := []any{}
				for _, n := range BGPNeighbors(cfgMap(in["bgp"])) {
					tuples = append(tuples, []any{n["vrf"], n["peer"], n["settings"]})
				}
				got = tuples
			case "fingerprint":
				got = Fingerprint(in["value"])
			case "acl_rules":
				got = ACLRules(in["entries"])
			case "acl_policy":
				got = ResolveACLPolicy(cfgMap(in["config"]), in["entries"])
			case "prefix_references":
				got, callErr = PrefixListReferences(cfgMap(in["config"]), in["family"].(string))
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
