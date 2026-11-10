package change_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gatework/go-netops/evidence"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/internal/record"
)

type domainCase struct {
	Name     string          `json:"name"`
	Input    json.RawMessage `json:"input"`
	Expected json.RawMessage `json:"expected"`
	Error    any             `json:"error"`
}

func domainCases(t *testing.T, names ...string) map[string]domainCase {
	t.Helper()
	files, _ := filepath.Glob("../testdata/domain/*.json")
	out := map[string]domainCase{}
	for _, f := range files {
		body, _ := os.ReadFile(f)
		var c domainCase
		if err := json.Unmarshal(body, &c); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(names, c.Name) {
			out[filepath.Base(f)] = c
		}
	}
	return out
}

// typedConfig decodes a configuration record into the typed model; ok is
// false when the record does not fit it.
func typedConfig(t *testing.T, cfg vxlan.Record) (*fabric.Configuration, bool) {
	t.Helper()
	if cfg == nil {
		return nil, true
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d := fabric.NewDevice(fabric.Identity{Host: "192.0.2.1"}, map[evidence.Dimension]fabric.Observed{
		fabric.DimConfiguration: {Status: evidence.StatusComplete, Records: []json.RawMessage{body}},
	})
	return d.Configuration, d.Has(fabric.DimConfiguration)
}

func legacyEligible(p *change.ChangePlan, cfg vxlan.Record) bool {
	return p.Eligible(record.Copy(cfg).(vxlan.Record))
}

func typedEligible(t *testing.T, c change.Change, cfg vxlan.Record) (bool, bool) {
	tc, ok := typedConfig(t, cfg)
	if !ok {
		return false, false
	}
	return tc != nil && c.Eligible(tc) == nil, true
}

func typedSatisfied(t *testing.T, c change.Change, after, before vxlan.Record) (bool, bool) {
	a, okA := typedConfig(t, after)
	b, okB := typedConfig(t, before)
	if !okA || !okB {
		return false, false
	}
	if a == nil || b == nil {
		return false, true
	}
	return c.Eligible(b) == nil && c.Satisfied(a) == nil && c.Preserved(b, a) == nil, true
}

func changeBody(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTypedChangesMatchLegacyFixtures(t *testing.T) {
	for file, c := range domainCases(t, "build", "eligible", "satisfied") {
		var in map[string]any
		_ = json.Unmarshal(c.Input, &in)
		legacy, legacyErr := change.NewChangePlan(record.Map(in["change"]))
		typed, typedErr := change.DecodeChange(changeBody(t, in["change"]))
		if (legacyErr == nil) != (typedErr == nil) {
			t.Errorf("%s %s: legacy err %v, typed err %v", c.Name, file, legacyErr, typedErr)
			continue
		}
		if legacyErr != nil {
			continue
		}
		script, err := typed.Render()
		if err != nil || !slices.Equal(script.Commands, legacy.Commands()) || !slices.Equal(script.Rollback, legacy.Rollback()) {
			t.Errorf("%s %s: render differs:\n typed  %q %q\n legacy %q %q", c.Name, file, script.Commands, script.Rollback, legacy.Commands(), legacy.Rollback())
		}
		switch c.Name {
		case "eligible":
			got, ok := typedEligible(t, typed, record.Map(in["config"]))
			if want := legacyEligible(legacy, record.Map(in["config"])); ok && got != want {
				t.Errorf("eligible %s: typed %v legacy %v", file, got, want)
			}
		case "satisfied":
			got, ok := typedSatisfied(t, typed, record.Map(in["after"]), record.Map(in["before"]))
			if want := legacy.Satisfied(record.Map(in["after"]), record.Map(in["before"])); ok && got != want {
				t.Errorf("satisfied %s: typed %v legacy %v", file, got, want)
			}
		}
	}
}

// mutations derive configuration variants that exercise each eligibility
// and readback condition; legacy and typed implementations must agree on
// every one of them.
func mutations(cfg vxlan.Record) map[string]vxlan.Record {
	out := map[string]vxlan.Record{"identity": record.Copy(cfg).(vxlan.Record)}
	add := func(name string, f func(vxlan.Record)) {
		c := record.Copy(cfg).(vxlan.Record)
		defer func() { _ = recover() }()
		f(c)
		out[name] = c
	}
	ifaces := func(c vxlan.Record) vxlan.Record {
		m, _ := c["interfaces"].(map[string]any)
		if m == nil {
			m = vxlan.Record{}
			c["interfaces"] = m
		}
		return m
	}
	svis := func(c vxlan.Record, f func(name string, svi vxlan.Record)) {
		for name, v := range ifaces(c) {
			if svi, ok := v.(map[string]any); ok && len(name) > 4 && name[:4] == "Vlan" {
				f(name, svi)
			}
		}
	}
	add("no_anycast", func(c vxlan.Record) { svis(c, func(_ string, s vxlan.Record) { s["anycast"] = false }) })
	add("other_vrf", func(c vxlan.Record) { svis(c, func(_ string, s vxlan.Record) { s["vrf"] = "other" }) })
	add("no_vrf", func(c vxlan.Record) { svis(c, func(_ string, s vxlan.Record) { delete(s, "vrf") }) })
	add("gateway_present", func(c vxlan.Record) {
		svis(c, func(_ string, s vxlan.Record) { s["addresses"] = []any{"192.0.2.254/24"} })
	})
	add("gateway_cleared", func(c vxlan.Record) { svis(c, func(_ string, s vxlan.Record) { s["addresses"] = []any{} }) })
	add("other_gateway", func(c vxlan.Record) {
		svis(c, func(_ string, s vxlan.Record) { s["addresses"] = []any{"198.51.100.1/24"} })
	})
	add("overlap_in_vrf", func(c vxlan.Record) {
		ifaces(c)["Vlan999"] = vxlan.Record{"vrf": "tenant", "addresses": []any{"192.0.2.1/25"}}
	})
	add("overlap_other_vrf", func(c vxlan.Record) {
		ifaces(c)["Vlan999"] = vxlan.Record{"vrf": "blue", "addresses": []any{"192.0.2.1/25"}}
	})
	add("no_svi", func(c vxlan.Record) { svis(c, func(n string, _ vxlan.Record) { delete(ifaces(c), n) }) })
	add("unmapped", func(c vxlan.Record) {
		if m, ok := c["vlan_vnis"].(map[string]any); ok {
			for k := range m {
				m[k] = nil
			}
		}
	})
	add("remapped", func(c vxlan.Record) {
		if m, ok := c["vlan_vnis"].(map[string]any); ok {
			for k := range m {
				m[k] = float64(12345)
			}
		}
	})
	add("second_vlan_same_vni", func(c vxlan.Record) {
		if m, ok := c["vlan_vnis"].(map[string]any); ok {
			for _, v := range m {
				m["4000"] = v
				break
			}
		}
	})
	add("binding_removed", func(c vxlan.Record) { svis(c, func(_ string, s vxlan.Record) { delete(s, "acl_bindings") }) })
	add("binding_other", func(c vxlan.Record) {
		svis(c, func(_ string, s vxlan.Record) { s["acl_bindings"] = vxlan.Record{"in": "other", "out": "other"} })
	})
	add("acl_bound_elsewhere", func(c vxlan.Record) {
		ifaces(c)["Ethernet1/1"] = vxlan.Record{"acl_bindings": vxlan.Record{"in": "protect"}}
	})
	add("acls_removed", func(c vxlan.Record) { delete(c, "acls") })
	add("acl_rule_changed", func(c vxlan.Record) {
		if m, ok := c["acls"].(map[string]any); ok {
			for k := range m {
				m[k] = []any{vxlan.Record{"sequence": float64(10), "action": "permit", "expression": "ip any any"}}
			}
		}
	})
	add("acl_remark_added", func(c vxlan.Record) {
		if m, ok := c["acls"].(map[string]any); ok {
			for k, v := range m {
				if rows, ok := v.([]any); ok {
					m[k] = append(rows, vxlan.Record{"sequence": float64(5), "action": "remark", "expression": "note"})
				}
			}
		}
	})
	add("address_group_changed", func(c vxlan.Record) {
		c["address_groups"] = vxlan.Record{"admins": []any{"198.51.100.0/24"}}
	})
	add("address_group_added", func(c vxlan.Record) {
		c["address_groups"] = vxlan.Record{"admins": []any{"192.0.2.0/24"}}
	})
	add("nve_l3", func(c vxlan.Record) {
		if nve, ok := c["nve"].(map[string]any); ok {
			if m, ok := nve["members"].(map[string]any); ok {
				for _, v := range m {
					if mm, ok := v.(map[string]any); ok {
						mm["associate_vrf"] = true
					}
				}
			}
		}
	})
	add("evpn_removed", func(c vxlan.Record) { delete(c, "evpn") })
	add("unrelated_interface_added", func(c vxlan.Record) {
		ifaces(c)["Ethernet1/48"] = vxlan.Record{"description": "new"}
	})
	add("unrelated_vlan_added", func(c vxlan.Record) {
		if m, ok := c["vlan_vnis"].(map[string]any); ok {
			m["3999"] = float64(39999)
		}
	})
	return out
}

func TestTypedChangesMatchLegacyOnMutations(t *testing.T) {
	compared, skipped := 0, 0
	for file, c := range domainCases(t, "eligible", "satisfied") {
		var in map[string]any
		_ = json.Unmarshal(c.Input, &in)
		legacy, err := change.NewChangePlan(record.Map(in["change"]))
		if err != nil {
			continue
		}
		typed, err := change.DecodeChange(changeBody(t, in["change"]))
		if err != nil {
			t.Fatalf("%s: typed rejected a legacy change: %v", file, err)
		}
		seeds := []vxlan.Record{record.Map(in["config"]), record.Map(in["before"]), record.Map(in["after"])}
		for si, seed := range seeds {
			if seed == nil {
				continue
			}
			for name, cfg := range mutations(seed) {
				got, ok := typedEligible(t, typed, cfg)
				if !ok {
					skipped++
					continue
				}
				if want := legacyEligible(legacy, cfg); got != want {
					t.Errorf("%s seed %d %s: eligible typed %v legacy %v", file, si, name, got, want)
				}
				// Readback of every mutation against every seed as "before".
				for _, before := range seeds {
					if before == nil {
						continue
					}
					got, ok := typedSatisfied(t, typed, cfg, before)
					if !ok {
						skipped++
						continue
					}
					if want := legacy.Satisfied(record.Copy(cfg).(vxlan.Record), record.Copy(before).(vxlan.Record)); got != want {
						t.Errorf("%s seed %d %s: satisfied typed %v legacy %v", file, si, name, got, want)
					}
					compared++
				}
			}
		}
	}
	if compared < 100 {
		t.Fatalf("too few differential comparisons: %d", compared)
	}
	t.Logf("differential comparisons: %d (skipped %d not fitting the typed model)", compared, skipped)
}

var _ = fmt.Sprint
