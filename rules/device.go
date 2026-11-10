// Package rules is the VXLAN/EVPN rule catalog: per-device rules over
// fabric.Device and cross-device rules over fabric.Fabric, evaluated by the
// go-netops assessment engine.
//
// Rules state facts and risks. A rule that needs evidence declares it in
// RuleMeta.Requires; the engine skips the rule when that evidence is
// incomplete, so missing findings never stand in for health.
package rules

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-netops/evidence"
	"github.com/gatework/go-vxlan/fabric"
)

const nxosGuide = "https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/103x/configuration/vxlan/cisco-nexus-9000-series-nx-os-vxlan-configuration-guide-release-103x/m_configuring_vxlan_bgp_evpn.html"

type deviceRule = assess.Rule[*fabric.Device]
type deviceInput = assess.Input[*fabric.Device]

func device(d *fabric.Device) assess.Subject { return assess.NewSubject("device", d.Host) }

// notUp are session states the legacy review treats as not established.
var notUp = []string{"down", "idle", "active", "connect", "opensent", "openconfirm"}

func isNotUp(state string) bool { return slices.Contains(notUp, strings.ToLower(state)) }

// DeviceRules returns the per-device rules in evaluation order.
func DeviceRules() []deviceRule {
	return []deviceRule{
		evidenceIncomplete, configRelation, aclUndefined, nveShutdown,
		nveVNIDown, nvePeerDown, bgpSessionDown, bgpNoPrefixes, ospfNotFull,
		vpcPeer, vpcMember, portChannelMember,
	}
}

var evidenceIncomplete = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.evidence_incomplete", Title: "证据不完整，先补采", Severity: assess.SeverityMedium, Category: assess.CategoryEvidence,
}, func(in deviceInput) []assess.Finding {
	d := in.Model
	var out []assess.Finding
	for _, dim := range slices.Sorted(maps.Keys(d.Coverage)) {
		status := d.Coverage[dim]
		if status.Complete() || status == evidence.StatusNotRequested {
			continue
		}
		f := assess.Finding{Subject: device(d).Child("dimension", string(dim)), Actual: issueCodes(d.Issues[dim]), Detail: "状态 " + string(status)}
		if status == evidence.StatusUnsupported {
			f.Severity = assess.SeverityLow
		}
		out = append(out, f)
	}
	// Configuration is the evidence every review depends on: not collecting
	// it is itself a gap, unlike optional runtime dimensions.
	if d.Coverage.Status(fabric.DimConfiguration) == evidence.StatusNotRequested {
		out = append(out, assess.Finding{Subject: device(d).Child("dimension", string(fabric.DimConfiguration)), Detail: "未采集运行配置"})
	}
	if d.Has(fabric.DimConfiguration) && !d.Configuration.Complete() {
		out = append(out, assess.Finding{Subject: device(d).Child("dimension", string(fabric.DimConfiguration)),
			Detail: "配置未完整审查，不能据此推导业务关系", Actual: d.Configuration.ReviewStatus})
	}
	return out
})

func issueCodes(issues []evidence.Issue) []string {
	var codes []string
	for _, i := range issues {
		if !slices.Contains(codes, i.Code) {
			codes = append(codes, i.Code)
		}
	}
	return codes
}

var relationTitles = map[string]string{
	"vlan_vni_without_nve": "VLAN 已映射 VNI，但缺少 NVE 成员",
	"nve_l2_without_vlan":  "L2 NVE 成员缺少 VLAN 映射",
	"nve_l2_without_evpn":  "L2 NVE 成员缺少 EVPN 配置",
	"nve_l3_without_vrf":   "L3 NVE 成员缺少 VRF 关联",
	"evpn_vni_without_nve": "EVPN VNI 缺少 NVE 成员",
	"vni_layer_conflict":   "VNI 的 L2/L3 属性冲突",
	"l3_vni_without_nve":   "VRF VNI 缺少 NVE 成员",
}

var configRelation = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.config_relation", Title: "配置关联需要核查", Severity: assess.SeverityHigh, Category: assess.CategoryConfiguration,
	Requires: []evidence.Dimension{fabric.DimConfiguration}, Verify: []evidence.Dimension{fabric.DimConfiguration, fabric.DimNVEVNIs, fabric.DimNVEPeers, fabric.DimBGP},
	References: []string{nxosGuide},
}, func(in deviceInput) []assess.Finding {
	c := in.Model.Configuration
	if !c.Complete() {
		return nil
	}
	var out []assess.Finding
	for _, rf := range c.ReviewFindings {
		subject := device(in.Model)
		if rf.VNI != nil {
			subject = subject.Child("vni", strconv.Itoa(*rf.VNI))
		} else if rf.VRF != "" {
			subject = subject.Child("vrf", rf.VRF)
		}
		out = append(out, assess.Finding{
			Subject: subject, Title: relationTitles[rf.Code], Detail: rf.Code, Actual: rf,
			Remediation: relationRemediation(c, rf),
		})
	}
	return out
})

var aclUndefined = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.acl_undefined", Title: "接口引用的 ACL 在本机未定义", Severity: assess.SeverityMedium, Category: assess.CategorySecurity,
	Requires: []evidence.Dimension{fabric.DimConfiguration}, Verify: []evidence.Dimension{fabric.DimConfiguration},
}, func(in deviceInput) []assess.Finding {
	c := in.Model.Configuration
	if !c.Complete() {
		return nil
	}
	var out []assess.Finding
	for _, name := range slices.Sorted(maps.Keys(c.Interfaces)) {
		iface := c.Interfaces[name]
		for _, direction := range slices.Sorted(maps.Keys(iface.ACLBindings)) {
			acl := iface.ACLBindings[direction]
			if _, ok := c.ACLs[acl]; ok {
				continue
			}
			out = append(out, assess.Finding{
				Subject: device(in.Model).Child("interface", name).Child("direction", direction),
				Detail:  fmt.Sprintf("接口引用 ACL %s，本机缺少定义", acl), Actual: acl,
				Remediation: &assess.Remediation{Status: assess.RemediationBlocked,
					Blockers: []string{"先确认接口是否承载业务及 ACL 的权威定义；无地址或无 VNI 可能是残留配置，不能直接推断业务中断，也不能按名称复制其他 Fabric 的 ACL。"},
					Impact:   "新增 ACL 定义会作用于本机所有同名引用；须核对全部引用及回退范围。"},
			})
		}
	}
	return out
})

var nveShutdown = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.nve_shutdown", Title: "NVE 接口已配置但处于 shutdown 或缺少源接口", Severity: assess.SeverityHigh, Category: assess.CategoryConfiguration,
	Requires: []evidence.Dimension{fabric.DimConfiguration}, Verify: []evidence.Dimension{fabric.DimConfiguration, fabric.DimNVEVNIs},
}, func(in deviceInput) []assess.Finding {
	c := in.Model.Configuration
	if !c.Complete() || c.NVE.Interface == "" || len(c.NVE.Members) == 0 {
		return nil
	}
	var problems []string
	if c.NVE.Shutdown == nil || *c.NVE.Shutdown {
		problems = append(problems, "shutdown")
	}
	if c.NVE.SourceInterface == "" {
		problems = append(problems, "source_interface")
	} else if _, ok := c.Interfaces[canonicalLoopback(c.NVE.SourceInterface)]; !ok {
		problems = append(problems, "source_interface_undefined")
	}
	if len(problems) == 0 {
		return nil
	}
	return []assess.Finding{{Subject: device(in.Model).Child("interface", c.NVE.Interface), Actual: problems,
		Detail: fmt.Sprintf("%d 个 VNI 成员依赖该 NVE 接口", len(c.NVE.Members))}}
})

var loopbackName = regexp.MustCompile(`(?i)^(?:lo|loopback)(\d+)$`)

func canonicalLoopback(name string) string {
	if m := loopbackName.FindStringSubmatch(name); m != nil {
		return "loopback" + m[1]
	}
	return name
}

// stateRule reports faulty rows of one runtime table. An observed fault is
// true even when the table is partial, so these rules do not require
// complete evidence; they mark findings from partial tables, and the
// evidence_incomplete rule reports that the table cannot prove the rest.
func stateRule(id assess.RuleID, title string, sev assess.Severity, dim evidence.Dimension, rows func(*fabric.Device) []assess.Finding) deviceRule {
	return assess.NewRule(assess.RuleMeta{
		ID: id, Title: title, Severity: sev, Category: assess.CategoryRuntime,
		Verify: []evidence.Dimension{dim, fabric.DimConfiguration},
	}, func(in deviceInput) []assess.Finding {
		out := rows(in.Model)
		if status := in.Model.Coverage.Status(dim); !status.Complete() {
			for i := range out {
				out[i].Detail = strings.TrimSpace(out[i].Detail + " (证据" + string(status) + "，仅能确认已观测到的异常)")
			}
		}
		return out
	})
}

var nveVNIDown = stateRule("vxlan.nve_vni_down", "NVE VNI 未处于 Up", assess.SeverityHigh, fabric.DimNVEVNIs, func(d *fabric.Device) []assess.Finding {
	var out []assess.Finding
	for _, v := range d.NVEVNIs {
		if isNotUp(v.State) {
			out = append(out, assess.Finding{Subject: device(d).Child("vni", strconv.Itoa(v.VNI)), Actual: v.State, Expected: "up"})
		}
	}
	return out
})

var nvePeerDown = stateRule("vxlan.nve_peer_down", "NVE peer 未处于 Up", assess.SeverityHigh, fabric.DimNVEPeers, func(d *fabric.Device) []assess.Finding {
	var out []assess.Finding
	for _, p := range d.NVEPeers {
		if isNotUp(p.State) {
			out = append(out, assess.Finding{Subject: device(d).Child("nve_peer", p.PeerIP), Actual: p.State, Expected: "up"})
		}
	}
	return out
})

var bgpSessionDown = stateRule("vxlan.bgp_session_down", "BGP EVPN 邻居未建立", assess.SeverityHigh, fabric.DimBGP, func(d *fabric.Device) []assess.Finding {
	var out []assess.Finding
	for _, n := range d.BGPNeighbors {
		if isNotUp(n.State) {
			out = append(out, assess.Finding{Subject: device(d).Child("vrf", n.VRF).Child("bgp_peer", n.PeerIP), Actual: n.State, Expected: "established"})
		}
	}
	return out
})

var bgpNoPrefixes = stateRule("vxlan.bgp_no_prefixes", "BGP EVPN 会话已建立但未收到任何路由", assess.SeverityMedium, fabric.DimBGP, func(d *fabric.Device) []assess.Finding {
	var out []assess.Finding
	for _, n := range d.BGPNeighbors {
		if strings.EqualFold(n.State, "established") && n.PrefixesReceived != nil {
			if v, ok := fabric.CounterInt64(*n.PrefixesReceived); ok && v == 0 {
				out = append(out, assess.Finding{Subject: device(d).Child("vrf", n.VRF).Child("bgp_peer", n.PeerIP), Actual: 0,
					Detail: "对端未通告 EVPN 路由；核对对端 VNI 部署、send-community extended 与路由策略"})
			}
		}
	}
	return out
})

var ospfNotFull = stateRule("vxlan.ospf_neighbor_not_full", "Underlay OSPF 邻居未达到 FULL", assess.SeverityHigh, fabric.DimOSPF, func(d *fabric.Device) []assess.Finding {
	var out []assess.Finding
	for _, n := range d.OSPFNeighbors {
		state, _, _ := strings.Cut(strings.ToLower(n.State), "/")
		// 2WAY is the steady state between DROTHERs on broadcast segments.
		if state == "full" || state == "2way" {
			continue
		}
		out = append(out, assess.Finding{Subject: device(d).Child("ospf_process", n.Process).Child("neighbor", n.NeighborID),
			Actual: n.State, Expected: "full", Detail: "接口 " + n.Interface})
	}
	return out
})

var vpcPeer = stateRule("vxlan.vpc_peer_unhealthy", "vPC 对等体、keepalive 或全局一致性异常", assess.SeverityCritical, fabric.DimVPC, func(d *fabric.Device) []assess.Finding {
	v := d.VPC
	if v == nil {
		return nil
	}
	subject := device(d).Child("vpc_domain", strconv.Itoa(v.DomainID))
	var out []assess.Finding
	check := func(field, actual, expected string) {
		if actual != "" && !strings.EqualFold(actual, expected) {
			out = append(out, assess.Finding{Subject: subject.Child("status", field), Actual: actual, Expected: expected})
		}
	}
	check("peer_status", v.PeerStatus, "peer adjacency formed ok")
	check("keepalive_status", v.KeepaliveStatus, "peer is alive")
	check("consistency_status", v.ConsistencyStatus, "success")
	for _, l := range v.PeerLinks {
		if !strings.EqualFold(l.State, "up") {
			out = append(out, assess.Finding{Subject: subject.Child("peer_link", l.Interface), Actual: l.State, Expected: "up"})
		}
	}
	return out
})

var vpcMember = stateRule("vxlan.vpc_member_inconsistent", "vPC 成员接口 down 或一致性检查失败", assess.SeverityHigh, fabric.DimVPC, func(d *fabric.Device) []assess.Finding {
	if d.VPC == nil {
		return nil
	}
	var out []assess.Finding
	for _, m := range d.VPC.Members {
		consistent := strings.EqualFold(m.Consistency, "success") || strings.EqualFold(m.Consistency, "Not Applicable")
		if strings.EqualFold(m.State, "up") && consistent {
			continue
		}
		out = append(out, assess.Finding{Subject: device(d).Child("vpc", m.ID.String()).Child("interface", m.Interface),
			Actual: map[string]string{"state": m.State, "consistency": m.Consistency, "reason": m.Reason}})
	}
	return out
})

var portChannelMember = stateRule("vxlan.port_channel_member_down", "Port-channel 成员未绑定 (非 P 状态)", assess.SeverityMedium, fabric.DimPortChannels, func(d *fabric.Device) []assess.Finding {
	var out []assess.Finding
	for _, pc := range d.PortChannels {
		// Only bundles that are up are expected to carry every member.
		if !strings.Contains(pc.Flags, "U") {
			continue
		}
		for _, m := range pc.Members {
			if !strings.Contains(m.Flags, "P") {
				out = append(out, assess.Finding{Subject: device(d).Child("port_channel", pc.Interface).Child("member", m.Interface), Actual: m.Flags, Expected: "P"})
			}
		}
	}
	return out
})
