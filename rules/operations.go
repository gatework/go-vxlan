package rules

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-netops/evidence"
	"github.com/gatework/go-vxlan/fabric"
)

// Rules over operational statements (fabric.Operations).

func operationDeviceRules() []deviceRule {
	return []deviceRule{peerLinkVLANs, vpcOptions, managementMissing}
}

func operationFabricRules() []fabricRule {
	return []fabricRule{dhcpRelay, vlanName, managementConsensus, vpcPeerOptions}
}

func ops(c *fabric.Configuration) *fabric.Operations {
	if c == nil || c.Operations == nil {
		return &fabric.Operations{}
	}
	return c.Operations
}

// allowedVLANs reports whether vlan is allowed by a trunk list; ok is false
// when the list cannot prove it either way.
func allowedVLANs(list string, vlan int) (allowed, ok bool) {
	switch list {
	case "", "all":
		return true, true
	case "none":
		return false, true
	case "unknown":
		return false, false
	}
	for part := range strings.SplitSeq(list, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, _ := strconv.Atoi(lo)
		b := a
		if isRange {
			b, _ = strconv.Atoi(hi)
		}
		if vlan >= a && vlan <= b {
			return true, true
		}
	}
	return false, true
}

var peerLinkVLANs = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.vpc_peer_link_vlans", Title: "vPC peer-link 未放行 VXLAN 业务 VLAN", Severity: assess.SeverityHigh, Category: assess.CategoryConfiguration,
	Requires: []evidence.Dimension{fabric.DimConfiguration}, Verify: []evidence.Dimension{fabric.DimConfiguration, fabric.DimVPC},
}, func(in deviceInput) []assess.Finding {
	c := in.Model.Configuration
	if !c.Complete() || c.VPCDomain == nil {
		return nil
	}
	var vlans []int
	for _, s := range c.Services() {
		if s.VLAN != nil {
			vlans = append(vlans, *s.VLAN)
		}
	}
	vlans = slices.Compact(slices.Sorted(slices.Values(vlans)))
	var out []assess.Finding
	for _, name := range slices.Sorted(maps.Keys(c.Interfaces)) {
		if !c.Interfaces[name].PeerLink {
			continue
		}
		list := ops(c).TrunkAllowed[name]
		var missing []int
		unknown := false
		for _, v := range vlans {
			allowed, ok := allowedVLANs(list, v)
			if !ok {
				unknown = true
				break
			}
			if !allowed {
				missing = append(missing, v)
			}
		}
		subject := device(in.Model).Child("peer_link", name)
		switch {
		case unknown:
			out = append(out, assess.Finding{Subject: subject, Severity: assess.SeverityLow, Actual: list, Detail: "无法从 allowed vlan 语句证明业务 VLAN 已放行"})
		case len(missing) > 0:
			out = append(out, assess.Finding{Subject: subject, Actual: missing, Expected: "allowed", Detail: "孤立端口与单归属主机流量依赖 peer-link；缺失 VLAN 会造成 vPC 一致性或转发问题"})
		}
	}
	return out
})

var vpcOptions = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.vpc_domain_options", Title: "vPC 域缺少推荐的收敛与同步选项", Severity: assess.SeverityLow, Category: assess.CategoryConfiguration,
	Requires: []evidence.Dimension{fabric.DimConfiguration}, References: []string{nxosGuide},
	Params: assess.Params{"required": []string{"peer_gateway", "auto_recovery", "arp_synchronize"}},
}, func(in deviceInput) []assess.Finding {
	c := in.Model.Configuration
	if !c.Complete() || c.VPCDomain == nil {
		return nil
	}
	o := ops(c).VPC
	if o == nil {
		o = &fabric.VPCOptions{}
	}
	present := map[string]bool{
		"peer_gateway": c.VPCDomain.PeerGateway, "peer_switch": c.VPCDomain.PeerSwitch,
		"auto_recovery": o.AutoRecovery, "arp_synchronize": o.ARPSynchronize, "nd_synchronize": o.NDSynchronize,
		"fast_convergence": o.FastConvergence, "delay_restore": o.DelayRestore != nil,
	}
	var missing []string
	for _, opt := range in.Params.Strings("required", nil) {
		if !present[opt] {
			missing = append(missing, opt)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return []assess.Finding{{Subject: device(in.Model).Child("vpc_domain", strconv.Itoa(c.VPCDomain.ID)), Actual: missing, Expected: in.Params.Strings("required", nil)}}
})

func serverSet(servers []fabric.Server) string {
	parts := make([]string, len(servers))
	for i, s := range servers {
		parts[i] = s.Address + "@" + s.VRF
	}
	return joinSorted(parts)
}

type serverKind struct {
	name string
	get  func(*fabric.Operations) []fabric.Server
}

var serverKinds = []serverKind{
	{"ntp", func(o *fabric.Operations) []fabric.Server { return o.NTPServers }},
	{"logging", func(o *fabric.Operations) []fabric.Server { return o.LoggingServers }},
	{"tacacs", func(o *fabric.Operations) []fabric.Server { return o.TACACSServers }},
	{"snmp", func(o *fabric.Operations) []fabric.Server { return o.SNMPHosts }},
}

var managementMissing = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.management_servers_missing", Title: "缺少管理平面服务器配置（时间、日志或认证）", Severity: assess.SeverityMedium, Category: assess.CategoryConfiguration,
	Requires: []evidence.Dimension{fabric.DimConfiguration}, Params: assess.Params{"required": []string{"ntp", "logging", "tacacs"}},
}, func(in deviceInput) []assess.Finding {
	c := in.Model.Configuration
	if !c.Complete() {
		return nil
	}
	var missing []string
	for _, k := range serverKinds {
		if slices.Contains(in.Params.Strings("required", nil), k.name) && len(k.get(ops(c))) == 0 {
			missing = append(missing, k.name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return []assess.Finding{{Subject: device(in.Model).Child("management", "servers"), Actual: missing}}
})

var dhcpRelay = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_dhcp_relay", Title: "共同业务网关的 DHCP 中继服务器不一致", Severity: assess.SeverityHigh, Category: assess.CategoryConsistency,
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
		return consensus(f, role, vni, "svi.dhcp_relay", rows, func(r roleService) (string, bool) {
			relays := ops(r.device.Configuration).DHCPRelays["Vlan"+strconv.Itoa(*r.service.VLAN)]
			return serverSet(relays), len(relays) > 0
		})
	})
})

var vlanName = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_vlan_name", Title: "相同 VNI 的本地 VLAN 名称不一致", Severity: assess.SeverityInfo, Category: assess.CategoryConsistency,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	return perVNI(f, func(role fabric.Role, vni int, rows []roleService) []assess.Finding {
		rows = mappedRows(rows)
		if !comparable2(rows) {
			return nil
		}
		return consensus(f, role, vni, "vlan.name", rows, func(r roleService) (string, bool) {
			name, ok := ops(r.device.Configuration).VLANNames[strconv.Itoa(*r.service.VLAN)]
			return name, ok
		})
	})
})

var managementConsensus = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_management_servers", Title: "Fabric 成员的管理平面服务器集合不一致", Severity: assess.SeverityMedium, Category: assess.CategoryConsistency,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	if !configured(f) {
		return nil
	}
	var out []assess.Finding
	for _, k := range serverKinds {
		var members []memberValue
		for _, d := range f.Members {
			servers := k.get(ops(d.Configuration))
			members = append(members, memberValue{d, serverSet(servers), len(servers) > 0})
		}
		out = append(out, fabricConsensus(f, "management."+k.name, members)...)
	}
	return out
})

var vpcPeerOptions = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.fabric_vpc_peer_options", Title: "同一 vPC 域的两台对等设备选项不一致", Severity: assess.SeverityMedium, Category: assess.CategoryConsistency,
}, func(in fabricInput) []assess.Finding {
	f := in.Model
	if !configured(f) {
		return nil
	}
	domains := map[int][]*fabric.Device{}
	for _, d := range f.Members {
		if id := vpcDomain(d); id != 0 {
			domains[id] = append(domains[id], d)
		}
	}
	var out []assess.Finding
	for _, id := range slices.Sorted(maps.Keys(domains)) {
		peers := domains[id]
		if len(peers) != 2 {
			continue // ambiguous pairing: domain ids are local, not fabric-unique
		}
		describe := func(d *fabric.Device) string {
			c := d.Configuration
			o := ops(c).VPC
			if o == nil {
				o = &fabric.VPCOptions{}
			}
			delay := "-"
			if o.DelayRestore != nil {
				delay = strconv.Itoa(*o.DelayRestore)
			}
			return fmt.Sprintf("peer_gateway=%t peer_switch=%t auto_recovery=%t arp_sync=%t nd_sync=%t fast_convergence=%t delay_restore=%s",
				c.VPCDomain.PeerGateway, c.VPCDomain.PeerSwitch, o.AutoRecovery, o.ARPSynchronize, o.NDSynchronize, o.FastConvergence, delay)
		}
		a, b := describe(peers[0]), describe(peers[1])
		if a != b {
			out = append(out, assess.Finding{Subject: fabricSubject(f).Child("vpc_domain", strconv.Itoa(id)),
				Actual: map[string]string{peers[0].Host: a, peers[1].Host: b}})
		}
	}
	return out
})

type memberValue struct {
	device  *fabric.Device
	value   string
	present bool
}

// fabricConsensus compares one attribute across all fabric members.
func fabricConsensus(f *fabric.Fabric, path string, members []memberValue) []assess.Finding {
	var ms []driftMember
	for _, m := range members {
		ms = append(ms, driftMember{Subject: fabricSubject(f).Child("device", m.device.Host), Value: m.value, Present: m.present})
	}
	return consensusFindings(path, ms)
}
