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

// TestTypedChangesMatchLegacyFixtures checks the typed increments against the
// legacy expectations recorded in the build, eligible and satisfied fixtures.
func TestTypedChangesMatchLegacyFixtures(t *testing.T) {
	for file, c := range domainCases(t, "build", "eligible", "satisfied") {
		var in map[string]any
		_ = json.Unmarshal(c.Input, &in)
		typed, typedErr := change.DecodeChange(changeBody(t, in["change"]))
		switch c.Name {
		case "build":
			if (c.Error == nil) != (typedErr == nil) {
				t.Errorf("build %s: legacy error %v, typed error %v", file, c.Error, typedErr)
				continue
			}
			if typedErr != nil {
				continue
			}
			var want struct {
				Commands []string `json:"commands"`
				Rollback []string `json:"rollback"`
			}
			_ = json.Unmarshal(c.Expected, &want)
			script, err := typed.Render()
			if err != nil || !slices.Equal(script.Commands, want.Commands) || !slices.Equal(script.Rollback, want.Rollback) {
				t.Errorf("build %s: render differs:\n typed  %q %q\n legacy %q %q", file, script.Commands, script.Rollback, want.Commands, want.Rollback)
			}
		case "eligible", "satisfied":
			var want bool
			if c.Error != nil || json.Unmarshal(c.Expected, &want) != nil {
				if typedErr == nil && c.Error != nil {
					t.Errorf("%s %s: legacy rejected the change, typed accepted it", c.Name, file)
				}
				continue
			}
			if typedErr != nil {
				t.Errorf("%s %s: typed rejected a legacy change: %v", c.Name, file, typedErr)
				continue
			}
			var got, ok bool
			if c.Name == "eligible" {
				got, ok = typedEligible(t, typed, record.Map(in["config"]))
			} else {
				got, ok = typedSatisfied(t, typed, record.Map(in["after"]), record.Map(in["before"]))
			}
			if ok && got != want {
				t.Errorf("%s %s: typed %v legacy %v", c.Name, file, got, want)
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

// TestTypedChangesMatchLegacyOnMutations replays the frozen legacy verdicts
// (testdata/typed/change-oracle.json) for every configuration mutation.
func TestTypedChangesMatchLegacyOnMutations(t *testing.T) {
	body, err := os.ReadFile("../testdata/typed/change-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle map[string]string
	if err := json.Unmarshal(body, &oracle); err != nil {
		t.Fatal(err)
	}
	compared := 0
	for file, c := range domainCases(t, "eligible", "satisfied") {
		var in map[string]any
		_ = json.Unmarshal(c.Input, &in)
		typed, err := change.DecodeChange(changeBody(t, in["change"]))
		if err != nil {
			continue
		}
		seeds := []vxlan.Record{record.Map(in["config"]), record.Map(in["before"]), record.Map(in["after"])}
		for si, seed := range seeds {
			if seed == nil {
				continue
			}
			for name, cfg := range mutations(seed) {
				eligible, ok := typedEligible(t, typed, cfg)
				if !ok {
					t.Fatalf("%s %s: mutation does not fit the typed model", file, name)
				}
				for bi, before := range seeds {
					if before == nil {
						continue
					}
					want, frozen := oracle[oracleKey(file, si, name, bi)]
					if !frozen {
						t.Fatalf("%s seed %d %s: no frozen verdict", file, si, name)
					}
					satisfied, _ := typedSatisfied(t, typed, cfg, before)
					if got := verdictCode(eligible, satisfied); got != want {
						t.Errorf("%s seed %d %s before %d: typed %s legacy %s (eligible, satisfied)", file, si, name, bi, got, want)
					}
					compared++
				}
			}
		}
	}
	if compared != len(oracle) {
		t.Fatalf("compared %d of %d frozen verdicts", compared, len(oracle))
	}
	t.Logf("frozen legacy verdicts reproduced: %d", compared)
}

// oracleKey and verdictCode index the frozen legacy verdicts
// (testdata/typed/change-oracle.json).
func oracleKey(file string, seed int, mutation string, before int) string {
	return fmt.Sprintf("%s/%d/%s/%d", file[:12], seed, mutation, before)
}

func verdictCode(eligible, satisfied bool) string {
	code := []byte("00")
	if eligible {
		code[0] = '1'
	}
	if satisfied {
		code[1] = '1'
	}
	return string(code)
}

func TestACLIncrementRejectsOutOfRangeSequence(t *testing.T) {
	for _, seq := range []int{0, 4294967296} {
		body := fmt.Sprintf(`{"kind":"svi_acl","vlan":8,"vni":10008,"acl":"protect","direction":"out","entries":[{"sequence":%d,"action":"permit","expression":"ip any any"}],"create_acl":true,"previous_binding":null}`, seq)
		if _, err := change.DecodeChange([]byte(body)); err == nil {
			t.Fatalf("sequence %d accepted", seq)
		}
	}
}
