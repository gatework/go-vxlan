package rules

import (
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-vxlan/fabric"
)

// Detection rules ported from the legacy fabric review. Executable gateway,
// ACL and VLAN-mapping increments are still derived by the legacy review and
// published in plan.json; these rules report the risk.

func fabricPolicyRules() []fabricRule {
	return []fabricRule{gatewayMismatch, aclBinding, aclContent, aclUndefined2, aclDependency, addressGroup,
		subnetConflict, routeTargets, tenantRouting, vlanMappingMissing}
}

func joinSorted(s []string) string { return strings.Join(sortedCopy(s), ",") }

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// mappedRows keeps services with a VLAN, as legacy compares gateway, ACL and
// SVI attributes only on mapped deployments.
func mappedRows(rows []roleService) []roleService {
	return slices.DeleteFunc(slices.Clone(rows), func(r roleService) bool { return r.service.VLAN == nil })
}

// transportRows are the VNIs legacy compares for transport: unambiguous,
// with at least two deployments.
func transportRows(rows []roleService) bool { return len(rows) >= 2 && unambiguous(rows) }

var gatewayMismatch = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_gateway", Title: "同业务网关地址不一致", Severity: assess.SeverityHigh, Category: assess.CategoryConsistency,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	return perVNI(f, func(role fabric.Role, vni int, rows []roleService) []assess.Finding {
		if !transportRows(rows) {
			return nil
		}
		rows = mappedRows(rows)
		if len(rows) < 2 || !gateways(rows) {
			return nil
		}
		return consensus(f, role, vni, "svi.addresses", rows, func(r roleService) (string, bool) {
			if r.service.SVI == nil {
				return "", false
			}
			return joinSorted(r.service.SVI.Addresses), true
		})
	})
})

// aclView is one deployment's ACL state in one direction.
type aclView struct {
	row     roleService
	name    string
	bound   bool
	defined bool
	policy  *fabric.ACLPolicy
}

func aclViews(rows []roleService, direction string) []aclView {
	var out []aclView
	for _, r := range rows {
		v := aclView{row: r}
		if r.service.SVI != nil {
			v.name, v.bound = r.service.SVI.ACLBindings[direction]
		}
		if v.bound {
			v.policy, v.defined = r.device.Configuration.ResolveACL(v.name)
		}
		out = append(out, v)
	}
	return out
}

// aclReview runs the per-VNI, per-direction ACL comparison of the legacy
// review and lets each rule pick the findings it owns.
func aclReview(f *fabric.Fabric, pick func(role fabric.Role, vni int, direction string, views []aclView, differentBinding, differentContent bool) []assess.Finding) []assess.Finding {
	return perVNI(f, func(role fabric.Role, vni int, rows []roleService) []assess.Finding {
		if !transportRows(rows) {
			return nil
		}
		rows = mappedRows(rows)
		if len(rows) < 2 || !gateways(rows) {
			return nil
		}
		var out []assess.Finding
		for _, direction := range []string{"in", "out"} {
			views := aclViews(rows, direction)
			bindings, contents := map[string]bool{}, map[string]bool{}
			unknown := false
			for _, v := range views {
				bindings[strconv.FormatBool(v.bound)+v.name] = true
				contents[v.policy.Key()] = true
				if v.bound && v.policy == nil {
					unknown = true
				}
			}
			out = append(out, pick(role, vni, direction, views, len(bindings) > 1, len(contents) > 1 || unknown)...)
		}
		return out
	})
}

func aclSubject(f *fabric.Fabric, role fabric.Role, vni int, direction string) assess.Subject {
	return vniSubject(f, role, vni).Child("acl_direction", direction)
}

func aclActual(views []aclView) map[string]any {
	out := map[string]any{}
	for _, v := range views {
		out[v.row.device.Host] = map[string]any{"acl": v.name, "bound": v.bound, "defined": v.defined, "policy_verified": v.policy != nil}
	}
	return out
}

var aclBinding = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_acl_binding", Title: "共同业务 SVI 的 ACL 挂载不一致", Severity: assess.SeverityHigh, Category: assess.CategorySecurity,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	return aclReview(f, func(role fabric.Role, vni int, direction string, views []aclView, differentBinding, _ bool) []assess.Finding {
		if !differentBinding {
			return nil
		}
		return []assess.Finding{{Subject: aclSubject(f, role, vni, direction), Actual: aclActual(views), Detail: "可推导的 svi_acl 增量见 plan.json"}}
	})
})

var aclContent = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_acl_content", Title: "ACL 有序规则或依赖对象不一致", Severity: assess.SeverityHigh, Category: assess.CategorySecurity,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	out := aclReview(f, func(role fabric.Role, vni int, direction string, views []aclView, differentBinding, differentContent bool) []assess.Finding {
		if differentBinding || !differentContent {
			return nil
		}
		return []assess.Finding{{Subject: aclSubject(f, role, vni, direction), Actual: aclActual(views)}}
	})
	return append(out, aclCatalog(f, false)...)
})

// aclCatalog compares same-name ACL definitions across a role, including
// definitions not yet bound. dependency selects unresolvable definitions
// instead of semantic differences.
func aclCatalog(f *fabric.Fabric, dependency bool) []assess.Finding {
	if !configured(f) {
		return nil
	}
	var out []assess.Finding
	for _, role := range []fabric.Role{fabric.RoleLeaf, fabric.RoleBorder} {
		members := f.ByRole(role)
		names := map[string]bool{}
		for _, d := range members {
			for n := range d.Configuration.ACLs {
				names[n] = true
			}
		}
		for _, name := range slices.Sorted(maps.Keys(names)) {
			semantics, identities := map[string]bool{}, map[string]bool{}
			var unknown []string
			for _, d := range members {
				entries, ok := d.Configuration.ACLs[name]
				if !ok {
					continue
				}
				policy, _ := d.Configuration.ResolveACL(name)
				var rules []fabric.ACLRule
				if policy != nil {
					rules = policy.Rules
				} else {
					rules = fabric.OrderedRules(entries)
				}
				semantics[fmt.Sprint(rules == nil, rules)] = true
				identities[policy.Key()] = true
				if policy == nil {
					unknown = append(unknown, d.Host)
				}
			}
			subject := fabricSubject(f).Child("role", string(role)).Child("acl", name)
			if dependency && len(unknown) > 0 {
				out = append(out, assess.Finding{Subject: subject, Actual: unknown, Detail: "依赖对象未验证（包括尚未挂载的定义）"})
			}
			if !dependency && (len(semantics) > 1 || len(identities) > 1) {
				out = append(out, assess.Finding{Subject: subject, Detail: "同名 ACL 的有序规则或依赖对象不同（包括尚未挂载的定义）"})
			}
		}
	}
	return out
}

var aclUndefined2 = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_acl_undefined", Title: "业务 SVI 挂载的 ACL 在该设备上没有定义", Severity: assess.SeverityHigh, Category: assess.CategorySecurity,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	return aclReview(f, func(role fabric.Role, vni int, direction string, views []aclView, differentBinding, differentContent bool) []assess.Finding {
		if !differentBinding && !differentContent {
			return nil
		}
		var out []assess.Finding
		for _, v := range views {
			if v.bound && !v.defined {
				out = append(out, assess.Finding{Subject: aclSubject(f, role, vni, direction).Child("device", v.row.device.Host), Actual: v.name})
			}
		}
		return out
	})
})

var aclDependency = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_acl_dependency", Title: "ACL 依赖对象缺失、为空或无法解析，不能证明策略一致", Severity: assess.SeverityMedium, Category: assess.CategoryEvidence,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	out := aclReview(f, func(role fabric.Role, vni int, direction string, views []aclView, differentBinding, differentContent bool) []assess.Finding {
		if !differentBinding && !differentContent {
			return nil
		}
		var out []assess.Finding
		for _, v := range views {
			if v.defined && v.policy == nil {
				out = append(out, assess.Finding{Subject: aclSubject(f, role, vni, direction).Child("device", v.row.device.Host), Actual: v.name})
			}
		}
		return out
	})
	return append(out, aclCatalog(f, true)...)
})

var addressGroup = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_address_group", Title: "ACL 引用的地址组成员不同或缺失", Severity: assess.SeverityHigh, Category: assess.CategorySecurity,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	if !configured(f) {
		return nil
	}
	var out []assess.Finding
	for _, role := range []fabric.Role{fabric.RoleLeaf, fabric.RoleBorder} {
		refs := map[string][]*fabric.Device{}
		for _, d := range f.ByRole(role) {
			seen := map[string]bool{}
			for _, entries := range d.Configuration.ACLs {
				for _, e := range entries {
					for _, g := range fabric.AddressGroupRefs(e.Expression) {
						if !seen[g] {
							seen[g] = true
							refs[g] = append(refs[g], d)
						}
					}
				}
			}
		}
		for _, name := range slices.Sorted(maps.Keys(refs)) {
			values := map[string]bool{}
			actual := map[string][]string{}
			for _, d := range refs[name] {
				members, ok := d.Configuration.AddressGroups[name]
				values[fmt.Sprint(ok, members)] = true
				actual[d.Host] = members
			}
			if len(values) > 1 {
				out = append(out, assess.Finding{Subject: fabricSubject(f).Child("role", string(role)).Child("address_group", name), Actual: actual,
					Detail: "仅比较引用此对象的业务，不自动复制"})
			}
		}
	}
	return out
})

var sviName = regexp.MustCompile(`^Vlan(\d+)$`)

type subnetUse struct {
	host, iface, vrf string
	vni              int
	prefix           netip.Prefix
}

var subnetConflict = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_subnet_vni_conflict", Title: "同一 VRF 的网段在不同 VNI 上重叠", Severity: assess.SeverityHigh, Category: assess.CategoryConfiguration,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	if !configured(f) {
		return nil
	}
	var uses []subnetUse
	for _, d := range f.Members {
		c := d.Configuration
		for _, name := range slices.Sorted(maps.Keys(c.Interfaces)) {
			m := sviName.FindStringSubmatch(name)
			svi := c.Interfaces[name]
			if m == nil || !fabric.True(svi.Anycast) {
				continue
			}
			vni := c.VLANVNIs[m[1]]
			if vni == nil {
				continue
			}
			for _, a := range svi.Addresses {
				p, err := netip.ParsePrefix(a)
				if err != nil {
					continue
				}
				uses = append(uses, subnetUse{d.Host, name, svi.VRF, *vni, p.Masked()})
			}
		}
	}
	type pair struct{ a, b string }
	seen := map[pair]bool{}
	var out []assess.Finding
	for i := range uses {
		for j := i + 1; j < len(uses); j++ {
			a, b := uses[i], uses[j]
			if a.vrf != b.vrf || a.vni == b.vni || a.prefix.Addr().Is4() != b.prefix.Addr().Is4() || !a.prefix.Overlaps(b.prefix) {
				continue
			}
			ka, kb := fmt.Sprintf("%s|%d", a.prefix, a.vni), fmt.Sprintf("%s|%d", b.prefix, b.vni)
			if ka > kb {
				ka, kb = kb, ka
			}
			if seen[pair{ka, kb}] {
				continue
			}
			seen[pair{ka, kb}] = true
			out = append(out, assess.Finding{Subject: fabricSubject(f).Child("vrf", a.vrf).Child("prefix", a.prefix.String()),
				Actual: []string{fmt.Sprintf("%s %s vni %d %s", a.host, a.iface, a.vni, a.prefix), fmt.Sprintf("%s %s vni %d %s", b.host, b.iface, b.vni, b.prefix)},
				Detail: "需核对迁移或隔离设计"})
		}
	}
	return out
})

var routeTargets = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_route_targets", Title: "EVPN 导入/导出 RT 声明不一致，需核对路由互通与隔离", Severity: assess.SeverityHigh, Category: assess.CategoryConsistency,
	References: []string{nxosGuide},
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	return perVNI(f, func(role fabric.Role, vni int, rows []roleService) []assess.Finding {
		if !transportRows(rows) {
			return nil
		}
		return consensus(f, role, vni, "evpn.route_targets", rows, func(r roleService) (string, bool) {
			if r.service.EVPN == nil {
				return "", false
			}
			v := vni
			return fabric.RouteTargetsKey(r.device.Configuration.ExpandRouteTargets(r.service.EVPN.RouteTargets, &v)), true
		})
	})
})

var tenantRouting = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_tenant_routing", Title: "共同业务的租户 VNI 或路由导入/导出声明不一致", Severity: assess.SeverityHigh, Category: assess.CategoryConsistency,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	return perVNI(f, func(role fabric.Role, vni int, rows []roleService) []assess.Finding {
		if !transportRows(rows) {
			return nil
		}
		tenants := slices.DeleteFunc(slices.Clone(rows), func(r roleService) bool { return r.service.SVI == nil || r.service.SVI.VRF == "" })
		if len(tenants) < 2 {
			return nil
		}
		return consensus(f, role, vni, "vrf.tenant", tenants, func(r roleService) (string, bool) {
			t := r.device.Configuration.Tenant(r.service.SVI.VRF)
			return t, t != ""
		})
	})
})

var vlanMappingMissing = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_vlan_mapping_missing", Title: "已有业务在部分设备上缺少 VLAN/VNI 关联", Severity: assess.SeverityHigh, Category: assess.CategoryConfiguration,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	return perVNI(f, func(role fabric.Role, vni int, rows []roleService) []assess.Finding {
		var out []assess.Finding
		for _, r := range rows {
			if slices.Equal(r.service.Missing, []string{"VLAN"}) {
				out = append(out, assess.Finding{Subject: vniSubject(f, role, vni).Child("device", r.device.Host),
					Detail: "若能唯一推导，vlan_vni_add 增量见 plan.json；禁止按 VNI 数值猜测 VLAN"})
			}
		}
		return out
	})
})
