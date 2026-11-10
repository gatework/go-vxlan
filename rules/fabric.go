package rules

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-netops/drift"
	"github.com/gatework/go-netops/evidence"
	"github.com/gatework/go-vxlan/fabric"
)

type fabricRule = assess.Rule[*fabric.Fabric]
type fabricInput = assess.Input[*fabric.Fabric]

// FabricRules returns the cross-device rules in evaluation order.
func FabricRules() []fabricRule {
	return append([]fabricRule{
		fabricEvidence, serviceIncomplete, vlanMappingAmbiguous, vlanMapping,
		replication, arpSuppression, sviAttributes, anycastMAC, spineL2,
		nvePeerMissing, duplicateLocalMAC,
	}, slices.Concat(fabricPolicyRules(), operationFabricRules())...)
}

func fabricSubject(f *fabric.Fabric) assess.Subject { return assess.NewSubject("fabric", f.Name) }

// configured returns members by role when every declared member reported a
// complete configuration. Cross-device conclusions from a partial fabric
// could blame the wrong device, so they are withheld entirely.
func configured(f *fabric.Fabric) bool {
	if len(f.Missing) > 0 {
		return false
	}
	for _, d := range f.Members {
		if !d.Has(fabric.DimConfiguration) || !d.Configuration.Complete() {
			return false
		}
	}
	return true
}

var fabricEvidence = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_evidence_incomplete", Title: "成员配置证据不完整，跨设备审查已停止", Severity: assess.SeverityHigh, Category: assess.CategoryEvidence,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	var unknown []string
	for _, d := range f.Members {
		if !d.Has(fabric.DimConfiguration) || !d.Configuration.Complete() {
			unknown = append(unknown, d.Host)
		}
	}
	if len(unknown) == 0 && len(f.Missing) == 0 {
		return nil
	}
	return []assess.Finding{{Subject: fabricSubject(f), Actual: map[string][]string{"incomplete": unknown, "not_collected": f.Missing}}}
})

// roleService is one device's deployment of a VNI within a role.
type roleService struct {
	device  *fabric.Device
	service fabric.Service
}

// servicesByRole groups each role's L2 services by VNI, VTEP roles only.
func servicesByRole(f *fabric.Fabric) map[fabric.Role]map[int][]roleService {
	out := map[fabric.Role]map[int][]roleService{}
	for _, role := range []fabric.Role{fabric.RoleLeaf, fabric.RoleBorder} {
		byVNI := map[int][]roleService{}
		for _, d := range f.ByRole(role) {
			for _, s := range d.Configuration.Services() {
				byVNI[s.VNI] = append(byVNI[s.VNI], roleService{d, s})
			}
		}
		out[role] = byVNI
	}
	return out
}

func vniSubject(f *fabric.Fabric, role fabric.Role, vni int) assess.Subject {
	return fabricSubject(f).Child("role", string(role)).Child("vni", strconv.Itoa(vni))
}

// perVNI runs check for every VNI deployed by each VTEP role of a fully
// configured fabric, in role then VNI order.
func perVNI(f *fabric.Fabric, check func(role fabric.Role, vni int, rows []roleService) []assess.Finding) []assess.Finding {
	if !configured(f) {
		return nil
	}
	var out []assess.Finding
	groups := servicesByRole(f)
	for _, role := range []fabric.Role{fabric.RoleLeaf, fabric.RoleBorder} {
		for _, vni := range slices.Sorted(maps.Keys(groups[role])) {
			out = append(out, check(role, vni, groups[role][vni])...)
		}
	}
	return out
}

// unambiguous drops VNIs where a device maps several VLANs; those are
// reported by vlan_mapping_ambiguous and cannot be compared.
func unambiguous(rows []roleService) bool {
	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.device.Host] {
			return false
		}
		seen[r.device.Host] = true
	}
	return true
}

var serviceIncomplete = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_service_incomplete", Title: "业务已开始部署，但 VLAN/NVE/EVPN 关联不完整", Severity: assess.SeverityHigh, Category: assess.CategoryConfiguration,
	Verify: []evidence.Dimension{fabric.DimConfiguration, fabric.DimNVEVNIs},
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	return perVNI(f, func(role fabric.Role, vni int, rows []roleService) []assess.Finding {
		var out []assess.Finding
		for _, r := range rows {
			if !r.service.Complete() {
				out = append(out, assess.Finding{Subject: vniSubject(f, role, vni).Child("device", r.device.Host), Actual: r.service.Missing, Expected: []string{}})
			}
		}
		return out
	})
})

var vlanMappingAmbiguous = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_vlan_mapping_ambiguous", Title: "同一设备将多个 VLAN 映射到相同 VNI", Severity: assess.SeverityHigh, Category: assess.CategoryConfiguration,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	return perVNI(f, func(role fabric.Role, vni int, rows []roleService) []assess.Finding {
		vlans := map[string][]int{}
		for _, r := range rows {
			if r.service.VLAN != nil {
				vlans[r.device.Host] = append(vlans[r.device.Host], *r.service.VLAN)
			}
		}
		var out []assess.Finding
		for _, host := range slices.Sorted(maps.Keys(vlans)) {
			if len(vlans[host]) > 1 {
				out = append(out, assess.Finding{Subject: vniSubject(f, role, vni).Child("device", host), Actual: vlans[host]})
			}
		}
		return out
	})
})

// consensus compares one attribute across a VNI's deployments and reports
// each outlier, or every member when no majority exists.
func consensus[V comparable](f *fabric.Fabric, role fabric.Role, vni int, path string, rows []roleService, value func(roleService) (V, bool)) []assess.Finding {
	var members []drift.Member[V]
	for _, r := range rows {
		v, ok := value(r)
		members = append(members, drift.Member[V]{Subject: vniSubject(f, role, vni).Child("device", r.device.Host), Value: v, Present: ok})
	}
	_, _, devs := drift.Consensus(path, members)
	var out []assess.Finding
	for _, d := range devs {
		finding := d.Finding(path + " " + string(d.Kind))
		finding.Category = assess.CategoryConsistency
		out = append(out, finding)
	}
	return out
}

func comparable2(rows []roleService) bool { return len(rows) >= 2 && unambiguous(rows) }

var vlanMapping = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_vlan_mapping", Title: "相同 VNI 的本地 VLAN 编号不一致", Severity: assess.SeverityMedium, Category: assess.CategoryConsistency,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	return perVNI(f, func(role fabric.Role, vni int, rows []roleService) []assess.Finding {
		// A missing VLAN is reported by service_incomplete; compare numbers
		// only among devices that map one.
		rows = slices.DeleteFunc(slices.Clone(rows), func(r roleService) bool { return r.service.VLAN == nil })
		if !comparable2(rows) {
			return nil
		}
		return consensus(f, role, vni, "vlan", rows, func(r roleService) (int, bool) {
			if r.service.VLAN == nil {
				return 0, false
			}
			return *r.service.VLAN, true
		})
	})
})

type replicationMode struct{ Mode, Group string }

var replication = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_replication", Title: "NVE 复制方式或组播组声明不一致", Severity: assess.SeverityHigh, Category: assess.CategoryConsistency,
	References: []string{nxosGuide},
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	return perVNI(f, func(role fabric.Role, vni int, rows []roleService) []assess.Finding {
		if !comparable2(rows) {
			return nil
		}
		return consensus(f, role, vni, "nve.replication", rows, func(r roleService) (replicationMode, bool) {
			if r.service.Member == nil {
				return replicationMode{}, false
			}
			return replicationMode{r.service.Member.Replication, r.service.Member.MulticastGroup}, true
		})
	})
})

var arpSuppression = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_arp_suppression", Title: "ARP 抑制的显式配置不一致", Severity: assess.SeverityMedium, Category: assess.CategoryConsistency,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	return perVNI(f, func(role fabric.Role, vni int, rows []roleService) []assess.Finding {
		if !comparable2(rows) {
			return nil
		}
		return consensus(f, role, vni, "nve.suppress_arp", rows, func(r roleService) (bool, bool) {
			if r.service.Member == nil || r.service.Member.SuppressARP == nil {
				return false, false
			}
			return *r.service.Member.SuppressARP, true
		})
	})
})

func gateways(rows []roleService) bool {
	return slices.ContainsFunc(rows, func(r roleService) bool { return r.service.Gateway() })
}

var sviAttributes = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_svi_attributes", Title: "业务 SVI 的 VRF、Anycast、MTU 或 shutdown 不一致", Severity: assess.SeverityHigh, Category: assess.CategoryConsistency,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	return perVNI(f, func(role fabric.Role, vni int, rows []roleService) []assess.Finding {
		var vlanRows []roleService
		for _, r := range rows {
			if r.service.VLAN != nil {
				vlanRows = append(vlanRows, r)
			}
		}
		if !comparable2(vlanRows) || !gateways(vlanRows) {
			return nil
		}
		svi := func(get func(*fabric.Interface) (string, bool)) func(roleService) (string, bool) {
			return func(r roleService) (string, bool) {
				if r.service.SVI == nil {
					return "", false
				}
				return get(r.service.SVI)
			}
		}
		var out []assess.Finding
		out = append(out, consensus(f, role, vni, "svi.vrf", vlanRows, svi(func(i *fabric.Interface) (string, bool) { return i.VRF, i.VRF != "" }))...)
		out = append(out, consensus(f, role, vni, "svi.anycast", vlanRows, svi(func(i *fabric.Interface) (string, bool) {
			if i.Anycast == nil {
				return "absent", true
			}
			return strconv.FormatBool(*i.Anycast), true
		}))...)
		out = append(out, consensus(f, role, vni, "svi.mtu", vlanRows, svi(func(i *fabric.Interface) (string, bool) {
			if i.MTU == nil {
				return "", false
			}
			return strconv.Itoa(*i.MTU), true
		}))...)
		out = append(out, consensus(f, role, vni, "svi.shutdown", vlanRows, svi(func(i *fabric.Interface) (string, bool) {
			if i.Shutdown == nil {
				return "", false
			}
			return strconv.FormatBool(*i.Shutdown), true
		}))...)
		return out
	})
})

var anycastMAC = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_anycast_mac", Title: "Anycast 网关 MAC 不一致", Severity: assess.SeverityHigh, Category: assess.CategoryConsistency,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	return perVNI(f, func(role fabric.Role, vni int, rows []roleService) []assess.Finding {
		if !comparable2(rows) || !gateways(rows) {
			return nil
		}
		return consensus(f, role, vni, "fabric_forwarding.anycast_mac", rows, func(r roleService) (string, bool) {
			mac := r.device.Configuration.AnycastMAC
			return mac, mac != ""
		})
	})
})

var spineL2 = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_spine_l2", Title: "Spine 承载了 L2 VNI，与角色不符", Severity: assess.SeverityMedium, Category: assess.CategoryConfiguration,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	if !configured(f) {
		return nil
	}
	var out []assess.Finding
	for _, d := range f.ByRole(fabric.RoleSpine) {
		var vnis []int
		for _, s := range d.Configuration.Services() {
			vnis = append(vnis, s.VNI)
		}
		if len(vnis) > 0 {
			out = append(out, assess.Finding{Subject: fabricSubject(f).Child("role", string(fabric.RoleSpine)).Child("device", d.Host), Actual: slices.Compact(vnis)})
		}
	}
	return out
})

// sourceAddresses returns the NVE source loopback's addresses (no prefix).
func sourceAddresses(c *fabric.Configuration) []string {
	iface, ok := c.Interfaces[canonicalLoopback(c.NVE.SourceInterface)]
	if !ok {
		return nil
	}
	var out []string
	for _, a := range iface.Addresses {
		if p, err := netip.ParsePrefix(a); err == nil {
			out = append(out, p.Addr().String())
		}
	}
	return out
}

func l2VNIs(c *fabric.Configuration) map[int]bool {
	out := map[int]bool{}
	for _, s := range c.Services() {
		out[s.VNI] = true
	}
	return out
}

var nvePeerMissing = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_nve_peer_missing", Title: "VTEP 缺少与共享 VNI 的对端之间的 NVE peer", Severity: assess.SeverityHigh, Category: assess.CategoryRuntime,
	Verify: []evidence.Dimension{fabric.DimNVEPeers, fabric.DimBGP},
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	if !configured(f) {
		return nil
	}
	vteps := f.VTEPs()
	var out []assess.Finding
	for _, d := range vteps {
		// Only conclude for devices whose peer table is complete.
		if !d.Has(fabric.DimNVEPeers) {
			continue
		}
		up := map[string]bool{}
		for _, p := range d.NVEPeers {
			if strings.EqualFold(p.State, "up") {
				up[p.PeerIP] = true
			}
		}
		mine := l2VNIs(d.Configuration)
		own := sourceAddresses(d.Configuration)
		for _, peer := range vteps {
			if peer == d {
				continue
			}
			addrs := sourceAddresses(peer.Configuration)
			if len(addrs) == 0 || slices.Equal(addrs, own) { // vPC pairs share an anycast VTEP
				continue
			}
			shared := 0
			for vni := range l2VNIs(peer.Configuration) {
				if mine[vni] {
					shared++
				}
			}
			if shared == 0 || slices.ContainsFunc(addrs, func(a string) bool { return up[a] }) {
				continue
			}
			out = append(out, assess.Finding{
				Subject:  fabricSubject(f).Child("device", d.Host).Child("nve_peer", peer.Host),
				Expected: addrs, Detail: fmt.Sprintf("共享 %d 个 L2 VNI，但未观测到 Up 的 NVE peer", shared),
			})
		}
	}
	return out
})

func vpcDomain(d *fabric.Device) int {
	if d.Configuration != nil && d.Configuration.VPCDomain != nil {
		return d.Configuration.VPCDomain.ID
	}
	return 0
}

var duplicateLocalMAC = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_duplicate_local_mac", Title: "同一 MAC 在多台非 vPC 对等的 VTEP 上同时本地学习", Severity: assess.SeverityHigh, Category: assess.CategoryRuntime,
	Verify: []evidence.Dimension{fabric.DimL2RouteMACs, fabric.DimMACs},
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	type key struct {
		topology int
		mac      string
	}
	seen := map[key][]*fabric.Device{}
	for _, d := range f.VTEPs() {
		if !d.Has(fabric.DimL2RouteMACs) {
			continue
		}
		for _, m := range d.L2RouteMACs {
			if strings.EqualFold(m.Producer, "Local") {
				k := key{m.TopologyID, strings.ToLower(m.MAC)}
				seen[k] = append(seen[k], d)
			}
		}
	}
	keys := slices.SortedFunc(maps.Keys(seen), func(a, b key) int {
		if a.topology != b.topology {
			return a.topology - b.topology
		}
		return strings.Compare(a.mac, b.mac)
	})
	var out []assess.Finding
	for _, k := range keys {
		devices := seen[k]
		if len(devices) < 2 {
			continue
		}
		domains := map[int]bool{}
		var hosts []string
		for _, d := range devices {
			domains[vpcDomain(d)] = true
			hosts = append(hosts, d.Host)
		}
		if len(devices) == 2 && len(domains) == 1 && !domains[0] {
			continue // the two members of one vPC domain legitimately share local MACs
		}
		out = append(out, assess.Finding{Subject: fabricSubject(f).Child("topology", strconv.Itoa(k.topology)).Child("mac", k.mac), Actual: hosts,
			Detail: "可能是重复 MAC、二层环路或主机频繁迁移；核对 MAC mobility 计数与接入端口"})
	}
	return out
})

type driftMember = drift.Member[string]

// consensusFindings turns consensus deviations into consistency findings.
func consensusFindings(path string, members []driftMember) []assess.Finding {
	_, _, devs := drift.Consensus(path, members)
	out := make([]assess.Finding, 0, len(devs))
	for _, d := range devs {
		finding := d.Finding(path + " " + string(d.Kind))
		finding.Category = assess.CategoryConsistency
		out = append(out, finding)
	}
	return out
}
