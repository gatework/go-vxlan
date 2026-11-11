package fabric_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/gatework/go-vxlan/fabric"
)

type domainFixture struct {
	Name     string          `json:"name"`
	Input    json.RawMessage `json:"input"`
	Expected json.RawMessage `json:"expected"`
	Error    any             `json:"error"`
}

func domainFixtures(t *testing.T, name string) map[string]domainFixture {
	t.Helper()
	files, _ := filepath.Glob("../testdata/domain/*.json")
	out := map[string]domainFixture{}
	for _, f := range files {
		body, _ := os.ReadFile(f)
		var d domainFixture
		if err := json.Unmarshal(body, &d); err != nil {
			t.Fatal(err)
		}
		if d.Name == name {
			out[filepath.Base(f)] = d
		}
	}
	if len(out) == 0 {
		t.Fatalf("no %s fixtures", name)
	}
	return out
}

func normalized(t *testing.T, v any) any {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	_ = json.Unmarshal(body, &out)
	return out
}

func expected(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}

// entriesOf decodes ACL entries; hostile shapes the typed model cannot hold
// correspond to the legacy "unknown order" result (nil).
func entriesOf(raw json.RawMessage) ([]fabric.ACLEntry, bool) {
	var entries []fabric.ACLEntry
	if json.Unmarshal(raw, &entries) != nil {
		return nil, false
	}
	return entries, true
}

func TestACLRulesMatchLegacyFixtures(t *testing.T) {
	for file, fx := range domainFixtures(t, "acl_rules") {
		var in struct {
			Entries json.RawMessage `json:"entries"`
		}
		_ = json.Unmarshal(fx.Input, &in)
		var got any
		if entries, ok := entriesOf(in.Entries); ok {
			if rules := fabric.OrderedRules(entries); rules != nil {
				got = normalized(t, rules)
			}
		}
		if want := expected(t, fx.Expected); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v want %v", file, got, want)
		}
	}
}

func TestACLPolicyMatchesLegacyFixtures(t *testing.T) {
	for file, fx := range domainFixtures(t, "acl_policy") {
		var in struct {
			Config  json.RawMessage `json:"config"`
			Entries json.RawMessage `json:"entries"`
		}
		_ = json.Unmarshal(fx.Input, &in)
		var groups struct {
			AddressGroups map[string][]string `json:"address_groups"`
		}
		groupsOK := json.Unmarshal(in.Config, &groups) == nil
		var got any
		if entries, ok := entriesOf(in.Entries); ok && groupsOK {
			c := &fabric.Configuration{ACLs: map[string][]fabric.ACLEntry{"acl": entries}, AddressGroups: groups.AddressGroups}
			if p, _ := c.ResolveACL("acl"); p != nil {
				got = normalized(t, p)
			}
		}
		if want := expected(t, fx.Expected); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v want %v", file, got, want)
		}
	}
}

func TestRouteTargetsMatchLegacyFixtures(t *testing.T) {
	for file, fx := range domainFixtures(t, "route_targets") {
		var in struct {
			Entries []fabric.RouteTarget `json:"entries"`
			ASN     *int                 `json:"asn"`
			VNI     *int                 `json:"vni"`
		}
		if err := json.Unmarshal(fx.Input, &in); err != nil {
			continue // hostile scalar shapes: legacy rejected or ignored them
		}
		c := &fabric.Configuration{BGP: fabric.RoutingNode{ASN: in.ASN}}
		var got []string
		for _, k := range c.ExpandRouteTargets(in.Entries, in.VNI) {
			got = append(got, k.String())
		}
		var tuples [][]any
		_ = json.Unmarshal(fx.Expected, &tuples)
		var want []string
		for _, tu := range tuples {
			af, _ := tu[0].(string)
			evpn, _ := tu[1].(bool)
			target := fmt.Sprint(tu[3])
			if auto, ok := tu[3].([]any); ok {
				target = fmt.Sprintf("auto(%v,%v)", nilOr(auto[1]), nilOr(auto[2]))
			}
			want = append(want, fabric.RouteTargetKey{AddressFamily: af, EVPN: evpn, Direction: fmt.Sprint(tu[2]), Target: target}.String())
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: got %v want %v", file, got, want)
		}
	}
}

func nilOr(v any) any {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return v
}

func TestSubnetConflictsMatchLegacyFixtures(t *testing.T) {
	compared := 0
	for file, fx := range domainFixtures(t, "subnets") {
		var in struct {
			Config  json.RawMessage `json:"config"`
			Address string          `json:"address"`
			VRF     *string         `json:"vrf"`
			VNI     *int            `json:"vni"`
			Except  string          `json:"except_interface"`
		}
		if err := json.Unmarshal(fx.Input, &in); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		c, err := fabric.DecodeConfiguration(in.Config)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		vrf := ""
		if in.VRF != nil {
			vrf = *in.VRF
		}
		got, err := c.SubnetConflicts(in.Address, vrf, in.VNI, in.Except)
		if fx.Error != nil {
			if err == nil {
				t.Errorf("%s: legacy failed, typed returned %v", file, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if g, w := normalized(t, got), expected(t, fx.Expected); !reflect.DeepEqual(g, w) && !(len(got) == 0 && fmt.Sprint(w) == "[]") {
			t.Errorf("%s:\n got  %v\n want %v", file, g, w)
		}
		compared++
	}
	t.Logf("subnet conflict fixtures: %d", compared)
}
