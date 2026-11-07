package vxlan

import (
	"fmt"
	"strings"
)

const recommendationReference = "https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/103x/configuration/vxlan/cisco-nexus-9000-series-nx-os-vxlan-configuration-guide-release-103x/m_configuring_vxlan_bgp_evpn.html"

var recommendationTitles = map[string]string{"vlan_vni_without_nve": "VLAN 已映射 VNI，但缺少 NVE 成员", "nve_l2_without_vlan": "L2 NVE 成员缺少 VLAN 映射", "nve_l2_without_evpn": "L2 NVE 成员缺少 EVPN 配置", "nve_l3_without_vrf": "L3 NVE 成员缺少 VRF 关联", "evpn_vni_without_nve": "EVPN VNI 缺少 NVE 成员", "vni_layer_conflict": "VNI 的 L2/L3 属性冲突", "l3_vni_without_nve": "VRF VNI 缺少 NVE 成员"}
var recommendationCommands = map[string]string{"configuration": "show running-config", "cdp_neighbors": "show cdp neighbors detail", "nve_peers": "show nve peers", "nve_vnis": "show nve vni", "bgp_neighbors": "show bgp l2vpn evpn summary", "ospf_neighbors": "show ip ospf neighbors", "vpc": "show vpc brief", "interfaces": "show interface brief", "port_channels": "show port-channel summary", "mac_addresses": "show mac address-table", "l2route_macs": "show l2route evpn mac all", "l2route_mac_ips": "show l2route evpn mac-ip all"}

func recommendationItem(code, scope, title string, evidence any, verify []any, category string) Record {
	return Record{"code": code, "scope": scope, "title": title, "category": category, "status": "blocked", "evidence": evidence, "prerequisites": []string{}, "blockers": []string{}, "commands": []string{}, "rollback": []string{}, "verify": verify, "expected": "重新采集并核对该项事实；业务连通性须另行验收。", "references": []string{recommendationReference}}
}
func domainAppend(m Record, key, value string) { m[key] = append(cfgStrings(m[key]), value) }
func adviceCounts(items []Record) Record {
	counts := Record{}
	for _, item := range items {
		status := domainString(item["status"])
		counts[status] = cfgNumber(counts[status]) + 1
	}
	return counts
}

// CombineRecommendations resolves proven local findings and enforces role blockers.
func CombineRecommendations(advice Record, additions []Record) Record {
	resolved := []Record{}
	var conflict Record
	for _, item := range additions {
		if item["status"] == "candidate" {
			resolved = append(resolved, cfgRows(item["resolves"])...)
		}
		if conflict == nil && item["code"] == "fabric_role_conflict" {
			conflict = item
		}
	}
	items := []Record{}
	for _, item := range cfgRows(advice["items"]) {
		found := false
		for _, r := range resolved {
			if domainEq(domainSlice(item, "code", "vni"), r) {
				found = true
			}
		}
		if !found {
			items = append(items, item)
		}
	}
	items = append(items, additions...)
	if conflict != nil {
		for i, item := range items {
			if item["status"] == "candidate" {
				copy := domainMerge(item, Record{"status": "blocked", "commands": []string{}, "rollback": []string{}, "blockers": append(append([]string{}, cfgStrings(item["blockers"])...), cfgStrings(conflict["blockers"])...)})
				delete(copy, "change")
				items[i] = copy
			}
		}
	}
	return domainMerge(advice, Record{"items": items, "counts": adviceCounts(items)})
}

// Recommendations generates review-only advice from persisted configuration/runtime evidence.
func Recommendations(document Record) Record {
	dimensions := cfgMap(domainAt(document, "snapshot", "dimensions"))
	selected := Record{}
	for name, value := range dimensions {
		if name != "collection" {
			selected[name] = value
		}
	}
	if len(selected) == 0 {
		selected["configuration"] = Record{"status": "not_requested"}
	}
	items := []Record{}
	for _, name := range cfgKeys(selected) {
		o := cfgMap(selected[name])
		if o["status"] == "complete" && (name != "configuration" || CompleteConfig(document) != nil) {
			continue
		}
		issues := []any{}
		for _, issue := range cfgRows(o["issues"]) {
			issues = append(issues, issue["code"])
		}
		evidence := Record{"status": o["status"], "issues": issues}
		if name == "configuration" {
			records := cfgRows(o["records"])
			statuses := []any{}
			for _, r := range records {
				statuses = append(statuses, r["review_status"])
			}
			evidence["configuration_records"] = len(records)
			evidence["review_status"] = statuses
		}
		verify := []any{}
		if c, ok := recommendationCommands[name]; ok {
			verify = append(verify, c)
		}
		item := recommendationItem("evidence_incomplete", name, "证据不完整，先补采", evidence, verify, "evidence")
		item["status"] = "investigate"
		item["expected"] = "完整回显或明确的零记录证明；空响应不能等同无配置。"
		items = append(items, item)
	}
	if config := CompleteConfig(document); config != nil {
		for _, finding := range cfgRows(config["review_findings"]) {
			items = append(items, configurationRecommendation(config, finding))
		}
		interfaces := cfgMap(config["interfaces"])
		for _, name := range cfgKeys(interfaces) {
			iface := cfgMap(interfaces[name])
			bindings := cfgMap(iface["acl_bindings"])
			for _, direction := range cfgKeys(bindings) {
				acl := domainString(bindings[direction])
				if _, ok := cfgMap(config["acls"])[acl]; ok {
					continue
				}
				item := recommendationItem("acl_reference_undefined", name+" / "+direction, fmt.Sprintf("接口引用 ACL %s，本机缺少定义", acl), Record{"interface": name, "direction": direction, "acl": acl, "addresses": cfgStrings(iface["addresses"]), "vlan_vni": cfgMap(config["vlan_vnis"])[strings.TrimPrefix(name, "Vlan")]}, []any{"show running-config", "show ip interface brief vrf all"}, "configuration")
				domainAppend(item, "blockers", "先确认接口是否承载业务及 ACL 的权威定义；无地址或无 VNI 可能是残留配置，不能直接推断业务中断，也不能按名称复制其他 Fabric 的 ACL。")
				item["impact"] = "新增 ACL 定义会作用于本机所有同名引用；须核对全部引用及回退范围。"
				item["references"] = []string{}
				items = append(items, item)
			}
		}
	}
	for _, dimension := range []string{"nve_vnis", "nve_peers", "bgp_neighbors"} {
		rows := []Record{}
		for _, row := range cfgRows(cfgMap(dimensions[dimension])["records"]) {
			if domainHas([]string{"down", "idle", "active", "connect", "opensent", "openconfirm"}, strings.ToLower(domainString(row["state"]))) {
				rows = append(rows, row)
			}
		}
		if len(rows) == 0 {
			continue
		}
		item := recommendationItem(dimension+"_not_up", dimension, "观测到未建立的运行状态", rows, []any{recommendationCommands[dimension], "show running-config"}, "runtime")
		item["status"] = "investigate"
		item["prerequisites"] = []string{"先确认业务预期，再检查对端、底层路由、接口和配置；不自动重启邻居或启用接口。"}
		items = append(items, item)
	}
	return Record{"schema_version": 1, "review_only": true, "health_assessment": "not_performed", "device": document["device"], "observed_at": domainAt(document, "snapshot", "observed_at"), "items": items, "counts": adviceCounts(items)}
}
func configurationRecommendation(config, finding Record) Record {
	vni := finding["vni"]
	code := domainString(finding["code"])
	title, ok := recommendationTitles[code]
	if !ok {
		title = "配置关联需要核查"
	}
	item := recommendationItem(code, "VNI "+domainString(vni), title, finding, []any{"show running-config", "show nve vni", "show nve peers", "show bgp l2vpn evpn summary"}, "configuration")
	item["vni"] = vni
	item["prerequisites"] = []string{"确认该 VNI 应在本机承载业务，而非预配置或退网残留。", "核对当前软件版本、设备角色、同 Fabric 对端的 VLAN/VNI、RD/RT 与复制方式。", "重新采集配置并确认与本报告一致；审批维护窗口后逐台操作，出现异常先回读，勿盲目重放。"}
	item["impact"] = "补齐可能开始发布路由或扩展二层广播域；须核对隔离边界、对端配置和回退条件。"
	item["expected"] = "VLAN、NVE 与 EVPN 关联一致；预期承载业务的 VNI 状态 Up，BGP/对端正常，业务验收通过。"
	if !domainInteger(vni, 1, 16777215) {
		domainAppend(item, "blockers", "VNI 非有效整数，无法生成命令。")
		return item
	}
	vlans := []string{}
	for _, vlan := range cfgKeys(cfgMap(config["vlan_vnis"])) {
		if domainEq(cfgMap(config["vlan_vnis"])[vlan], vni) {
			vlans = append(vlans, vlan)
		}
	}
	nve := cfgMap(config["nve"])
	member := cfgMap(nve["members"])[domainString(vni)]
	evpn := cfgMap(config["evpn"])[domainString(vni)]
	item["evidence"] = domainMerge(finding, Record{"vlan_ids": vlans, "nve_member": member, "evpn": evpn})
	switch code {
	case "nve_l2_without_evpn":
		if recommendationL2Context(config, vni, vlans) && member != nil && cfgMap(member)["associate_vrf"] == false && cfgMap(member)["replication"] == "bgp" && evpn == nil && recommendationAutoPolicy(config) {
			recommendationCandidate(item, recommendationEVPNAdd(vni), recommendationEVPNRemove(vni), "本机现有 L2 EVPN 均采用 RD auto、RT import/export auto；候选沿用此模式，仍需确认本 VNI 的业务意图。")
		} else {
			domainAppend(item, "blockers", "需要唯一 VLAN 映射、L2 BGP 复制以及一致的 RD/RT 策略；缺失或冲突时不能套用 auto。")
		}
	case "vlan_vni_without_nve", "evpn_vni_without_nve":
		auto := recommendationAutoPolicy(config)
		if evpn != nil {
			auto = recommendationAutoEVPN(cfgMap(evpn))
		}
		if recommendationL2Context(config, vni, vlans) && member == nil && recommendationBGPReplication(nve) && auto {
			commands := []string{"interface " + domainString(nve["interface"]), "  member vni " + domainString(vni), "    ingress-replication protocol bgp", "exit", "exit"}
			rollback := []string{"interface " + domainString(nve["interface"]), "  no member vni " + domainString(vni), "exit"}
			if evpn == nil {
				commands = append(commands, recommendationEVPNAdd(vni)...)
				rollback = append(rollback, recommendationEVPNRemove(vni)...)
			}
			recommendationCandidate(item, commands, rollback, "本机既有 L2 成员统一使用 BGP 复制、EVPN auto 策略；仅补齐缺失的 NVE/EVPN，不启用额外 ARP 抑制。")
		} else {
			domainAppend(item, "blockers", "需确认 VNI 的 L2/L3 角色、VLAN、NVE 接口、复制模式和 RD/RT，当前不能唯一确定增量配置。")
		}
	case "nve_l2_without_vlan":
		domainAppend(item, "blockers", "请提供本 VNI 对应 VLAN ID，并核对 access/trunk/SVI；不能由 VNI 尾数或其他设备名称猜测。")
		item["template"] = []string{"vlan <VLAN_ID>", "  vn-segment " + domainString(vni)}
	default:
		domainAppend(item, "blockers", "需要明确 VRF/VNI 业务映射和 L2/L3 角色；先核对设计，再补齐或清理残留配置。")
	}
	return item
}
func recommendationL2Context(config Record, vni any, vlans []string) bool {
	nve := cfgMap(config["nve"])
	if config["nv_overlay_evpn"] != true || nve["shutdown"] != false || nve["host_reachability"] != "bgp" || cfgMatch(`(?i)nve[1-9]\d*`, domainString(nve["interface"])) == nil || len(vlans) != 1 || cfgMatch(`\d+`, vlans[0]) == nil || cfgNumber(vlans[0]) < 1 || cfgNumber(vlans[0]) > 4094 {
		return false
	}
	for _, vrf := range cfgMap(config["vrfs"]) {
		if domainEq(cfgMap(vrf)["vni"], vni) {
			return false
		}
	}
	return true
}
func recommendationAutoPolicy(config Record) bool {
	count := 0
	for _, v := range cfgMap(config["evpn"]) {
		settings := cfgMap(v)
		if settings["type"] == "l2" {
			count++
			if !recommendationAutoEVPN(settings) {
				return false
			}
		}
	}
	return count > 0
}
func recommendationAutoEVPN(settings Record) bool {
	targets := cfgRows(settings["route_targets"])
	if settings["type"] != "l2" || settings["rd"] != "auto" || len(targets) != 2 {
		return false
	}
	directions := []string{}
	for _, rt := range targets {
		directions = append(directions, domainString(rt["direction"]))
		if rt["target"] != "auto" || rt["evpn"] != false {
			return false
		}
	}
	return domainEq(cfgUniqueSorted(directions), []string{"export", "import"})
}
func recommendationBGPReplication(nve Record) bool {
	count := 0
	for _, v := range cfgMap(nve["members"]) {
		m := cfgMap(v)
		if domainTruthy(m["associate_vrf"]) {
			continue
		}
		count++
		if m["replication"] != "bgp" || domainTruthy(m["multicast_group"]) {
			return false
		}
	}
	return count > 0
}
func recommendationEVPNAdd(vni any) []string {
	return []string{"evpn", "  vni " + domainString(vni) + " l2", "    rd auto", "    route-target import auto", "    route-target export auto", "exit", "exit"}
}
func recommendationEVPNRemove(vni any) []string {
	return []string{"evpn", "  no vni " + domainString(vni) + " l2", "exit"}
}
func recommendationCandidate(item Record, commands, rollback []string, assumption string) {
	item["status"] = "candidate"
	domainAppend(item, "prerequisites", assumption)
	item["commands"] = append(append([]string{"configure terminal"}, commands...), "end")
	item["rollback"] = append(append([]string{"configure terminal"}, rollback...), "end")
}
