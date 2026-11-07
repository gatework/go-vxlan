package vxlan

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

var fabricRoles = []string{"leaves", "borders", "spines"}

// ValidateFabricPolicy enforces explicit unique canonical IP membership and roles.
func ValidateFabricPolicy(policy Record) error {
	if len(policy) != 1 {
		return fmt.Errorf("需要 fabrics 策略")
	}
	groups, ok := policy["fabrics"].(map[string]any)
	if !ok || len(groups) == 0 {
		return fmt.Errorf("需要 fabrics 策略")
	}
	seen := map[string]bool{}
	for name, value := range groups {
		group, ok := value.(map[string]any)
		if name == "" || !ok || len(group) == 0 {
			return fmt.Errorf("Fabric 需要明确的角色成员清单")
		}
		for role := range group {
			if !domainHas(fabricRoles, role) {
				return fmt.Errorf("Fabric 需要明确的角色成员清单")
			}
		}
		count := 0
		for _, role := range fabricRoles {
			v, exists := group[role]
			if !exists {
				continue
			}
			hosts, ok := domainStrings(v)
			if !ok {
				return fmt.Errorf("角色成员须为地址列表")
			}
			for _, host := range hosts {
				a, e := netip.ParseAddr(host)
				if e != nil || a.String() != host || strings.Contains(host, "/") || a.Zone() != "" {
					return fmt.Errorf("成员地址无效")
				}
				if seen[host] {
					return fmt.Errorf("成员不能重复、跨角色或跨 Fabric")
				}
				seen[host] = true
				count++
			}
		}
		if count < 2 {
			return fmt.Errorf("Fabric 至少需要两个成员")
		}
	}
	return nil
}

type fabricReview struct {
	documents Record
	groups    Record
	findings  []Record
	items     Record
	coverage  []Record
	role      any
	indexes   map[string]*SubnetIndex
}

// ReviewFabric compares explicit same-role deployed services and blocks unsafe drafts.
func ReviewFabric(documents []Record, policy Record) (result Record, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = e
				result = nil
			} else {
				panic(r)
			}
		}
	}()
	if e := ValidateFabricPolicy(policy); e != nil {
		return nil, e
	}
	r := &fabricReview{documents: Record{}, groups: Record{}, findings: []Record{}, items: Record{}, coverage: []Record{}, indexes: map[string]*SubnetIndex{}}
	observed := []string{}
	for _, d := range documents {
		device, ok := d["device"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("缺少设备身份")
		}
		host, ok := device["host"].(string)
		if !ok {
			return nil, fmt.Errorf("缺少设备身份")
		}
		if _, exists := r.documents[host]; exists {
			return nil, fmt.Errorf("重复设备身份")
		}
		r.documents[host] = d
		observed = append(observed, host)
	}
	hosts := []string{}
	for _, fabric := range cfgKeys(cfgMap(policy["fabrics"])) {
		group := cfgMap(cfgMap(policy["fabrics"])[fabric])
		normalized := Record{}
		for _, role := range fabricRoles {
			members := cfgStrings(group[role])
			normalized[role] = append([]string{}, members...)
			hosts = append(hosts, members...)
		}
		r.groups[fabric] = normalized
	}
	assigned, unassigned, missing := []string{}, []string{}, []string{}
	for _, h := range hosts {
		if domainHas(observed, h) {
			assigned = append(assigned, h)
		} else {
			missing = append(missing, h)
		}
	}
	for _, h := range observed {
		if !domainHas(hosts, h) {
			unassigned = append(unassigned, h)
		}
	}
	inventory := Record{"groups": r.groups, "assigned": assigned, "unassigned": unassigned, "missing": missing}
	if len(unassigned) > 0 {
		r.finding("未归属", nil, "fabric_scope_unassigned", "已采集设备未纳入 Fabric 策略，跨设备审查未覆盖", unassigned)
	}
	for _, fabric := range cfgKeys(r.groups) {
		group := cfgMap(r.groups[fabric])
		configs := Record{}
		order := []string{}
		unknown := []string{}
		for _, role := range fabricRoles {
			for _, host := range cfgStrings(group[role]) {
				config := CompleteConfig(cfgMap(r.documents[host]))
				configs[host] = config
				order = append(order, host)
				if config == nil {
					unknown = append(unknown, host)
				}
			}
		}
		if len(unknown) > 0 {
			r.finding(fabric, nil, "fabric_evidence_incomplete", "成员配置证据不完整，停止该 Fabric 的变更推导", unknown)
			continue
		}
		for _, role := range []string{"leaves", "borders"} {
			r.role = role
			members := cfgStrings(group[role])
			if len(members) > 0 {
				local := Record{}
				for _, h := range members {
					local[h] = configs[h]
				}
				r.reviewGroup(fabric, local, configs, members, order)
			}
		}
		r.role = "spines"
		for _, host := range cfgStrings(group["spines"]) {
			r.reviewSpine(fabric, host, cfgMap(configs[host]))
		}
		r.role = nil
		r.reviewSubnets(fabric, configs, order)
	}
	return Record{"schema_version": 2, "scope": "same_role_same_deployed_vni", "inventory": inventory, "findings": r.findings, "device_items": r.items, "coverage": r.coverage}, nil
}
func (r *fabricReview) finding(fabric string, vni any, code, title string, evidence any) {
	r.findings = append(r.findings, Record{"fabric": fabric, "role": r.role, "vni": vni, "code": code, "title": title, "evidence": evidence})
}
func (r *fabricReview) observations(rows []Record, value func(Record) any) []Record {
	out := []Record{}
	for _, row := range rows {
		out = append(out, Record{"host": row["host"], "name": cfgMap(cfgMap(r.documents[domainString(row["host"])])["device"])["name"], "vlan": row["vlan"], "value": value(row)})
	}
	return out
}
func (r *fabricReview) compare(fabric string, vni any, code, title string, rows []Record, value func(Record) any) {
	evidence := r.observations(rows, value)
	values := []any{}
	for _, e := range evidence {
		values = append(values, e["value"])
	}
	if len(domainUniq(values)) > 1 {
		r.finding(fabric, vni, code, title, evidence)
	}
}
func (r *fabricReview) addItem(host string, item Record) {
	r.items[host] = append(cfgRows(r.items[host]), item)
}
func (r *fabricReview) recommendation(fabric string, vni any, code, title string, evidence []Record) Record {
	scope := "角色核查"
	if vni != nil {
		scope = "VNI " + domainString(vni)
	}
	return Record{"code": code, "category": "fabric", "scope": fabric + " / " + domainString(r.role) + " / " + scope, "title": title, "status": "blocked", "evidence": evidence, "prerequisites": []string{"仅在本 Fabric、相同已部署业务范围内适用；核对业务访问策略与维护窗口。", "下发前重新读取配置，任何变化均使计划过期；逐设备逐项确认，不批量重放。"}, "blockers": []string{}, "commands": []string{}, "rollback": []string{}, "verify": []string{"show running-config", "show nve vni", "show ip interface brief vrf all"}, "impact": "改变网关或 ACL 可能改变可达性及业务隔离；配置回读通过后仍需业务验收。", "expected": "共同业务的网关和访问控制一致，允许/拒绝流量均符合设计。", "references": []string{}}
}
func (r *fabricReview) propose(item Record, plan *ChangePlan, blocked bool) {
	if blocked {
		domainAppend(item, "blockers", "共同业务的承载关联或复制/路由声明存在冲突，先解决这些前置问题，再生成网关或 ACL 增量。")
		return
	}
	item["status"] = "candidate"
	item["change"] = plan.Change()
	item["commands"] = plan.Commands()
	item["rollback"] = plan.Rollback()
}
func (r *fabricReview) reviewGroup(fabric string, configs, all Record, hosts, allHosts []string) {
	services := serviceCatalog(configs, hosts)
	policies := Record{}
	for _, host := range hosts {
		policies[host] = Record{}
		for name, entries := range cfgMap(cfgMap(configs[host])["acls"]) {
			cfgMap(policies[host])[name] = ResolveACLPolicy(cfgMap(configs[host]), entries)
		}
	}
	vnis := []int{}
	for vni := range services {
		vnis = append(vnis, vni)
	}
	sort.Ints(vnis)
	for _, vni := range vnis {
		rows := services[vni]
		deployed, incompleteHosts := []string{}, []string{}
		incomplete := []Record{}
		for _, row := range rows {
			host := domainString(row["host"])
			if !domainHas(deployed, host) {
				deployed = append(deployed, host)
			}
			if len(cfgStrings(row["missing"])) > 0 {
				incomplete = append(incomplete, row)
				if !domainHas(incompleteHosts, host) {
					incompleteHosts = append(incompleteHosts, host)
				}
			}
		}
		notDeployed := []string{}
		for _, host := range hosts {
			if !domainHas(deployed, host) {
				notDeployed = append(notDeployed, host)
			}
		}
		r.coverage = append(r.coverage, Record{"fabric": fabric, "role": r.role, "vni": vni, "deployed": deployed, "not_deployed": notDeployed, "incomplete": incompleteHosts})
		if len(incomplete) > 0 {
			r.finding(fabric, vni, "fabric_service_incomplete", "业务已开始部署，但 VLAN/NVE/EVPN 关联不完整", r.observations(incomplete, func(row Record) any { return Record{"missing": row["missing"]} }))
			r.reviewMissingMappings(fabric, vni, rows, all, allHosts)
		}
		if len(deployed) != len(rows) {
			evidence := []Record{}
			for _, row := range rows {
				evidence = append(evidence, domainSlice(row, "host", "vlan"))
			}
			r.finding(fabric, vni, "fabric_vlan_mapping_ambiguous", "同一 Leaf 将多个 VLAN 映射到相同 VNI", evidence)
			continue
		}
		if len(rows) < 2 {
			continue
		}
		constraints := r.reviewTransport(fabric, vni, rows)
		blocked := len(incomplete) > 0 || constraints
		filtered := []Record{}
		for _, row := range rows {
			if row["vlan"] != nil {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
		if len(rows) < 2 {
			continue
		}
		r.compare(fabric, vni, "fabric_vlan_mapping", "相同 VNI 的本地 VLAN 编号不一致", rows, func(row Record) any { return row["vlan"] })
		gateway := false
		for _, row := range rows {
			svi := cfgMap(row["svi"])
			if row["svi"] != nil && (domainTruthy(svi["anycast"]) || len(cfgStrings(svi["addresses"])) > 0) {
				gateway = true
			}
		}
		if !gateway {
			continue
		}
		r.reviewGateway(fabric, vni, rows, all, allHosts, blocked)
		for _, direction := range []string{"in", "out"} {
			r.reviewACL(fabric, vni, rows, direction, policies, blocked)
		}
		for _, field := range []string{"vrf", "anycast", "mtu", "shutdown"} {
			r.compare(fabric, vni, "fabric_"+field, "业务 SVI 的 "+field+" 不一致", rows, func(row Record) any { return cfgMap(row["svi"])[field] })
		}
		r.compare(fabric, vni, "fabric_anycast_mac", "Anycast 网关 MAC 不一致", rows, func(row Record) any { return cfgMap(row["config"])["anycast_mac"] })
	}
	r.reviewACLCatalog(fabric, configs, policies, hosts)
	r.reviewAddressGroups(fabric, configs, hosts)
}
func (r *fabricReview) reviewTransport(fabric string, vni int, rows []Record) bool {
	before := len(r.findings)
	r.compare(fabric, vni, "fabric_replication", "NVE 复制方式或组播组声明不一致", rows, func(row Record) any {
		if row["nve"] == nil {
			return nil
		}
		return domainSlice(EffectiveNVEMember(cfgMap(row["config"]), cfgMap(row["nve"])), "replication", "multicast_group")
	})
	r.compare(fabric, vni, "fabric_arp_suppression", "ARP 抑制的显式配置不一致", rows, func(row Record) any { return cfgMap(row["nve"])["suppress_arp"] })
	r.compare(fabric, vni, "fabric_route_targets", "EVPN 导入/导出 RT 声明不一致，需核对路由互通与隔离", rows, func(row Record) any {
		if row["evpn"] == nil {
			return nil
		}
		return ServiceRouteTargets(cfgMap(row["evpn"])["route_targets"], cfgMap(cfgMap(row["config"])["bgp"])["asn"], vni)
	})
	tenants := []Record{}
	for _, row := range rows {
		if cfgMap(row["svi"])["vrf"] != nil {
			tenants = append(tenants, row)
		}
	}
	if len(tenants) >= 2 {
		r.compare(fabric, vni, "fabric_tenant_routing", "共同业务的租户 VNI 或路由导入/导出声明不一致", tenants, func(row Record) any {
			return ServiceTenant(cfgMap(row["config"]), domainString(cfgMap(row["svi"])["vrf"]))
		})
	}
	return len(r.findings) > before
}
func (r *fabricReview) reviewSpine(fabric, host string, config Record) {
	services := serviceCatalog(Record{host: config}, []string{host})
	if len(services) == 0 {
		return
	}
	vnis := []int{}
	for vni := range services {
		vnis = append(vnis, vni)
	}
	sort.Ints(vnis)
	evidence := []Record{{"host": host, "value": Record{"role": "spines", "l2_vnis": vnis}}}
	r.finding(fabric, nil, "fabric_role_conflict", "声明为 Spine，但存在 L2 业务承载配置", evidence)
	item := r.recommendation(fabric, nil, "fabric_role_conflict", "核对 Spine 是否应承担业务 VTEP 职责", evidence)
	domainAppend(item, "blockers", "先确认角色或迁移残留；不能因为出现 NVE 就自动把 Spine 当作 Leaf，不能自动补业务配置或删除 NVE。")
	r.addItem(host, item)
}
func (r *fabricReview) gatewayConflicts(configs, change Record, hosts []string, exceptHost, exceptInterface string) []Record {
	out := []Record{}
	for _, host := range hosts {
		idx := r.indexes[host]
		if idx == nil {
			idx = NewSubnetIndex(cfgMap(configs[host]))
			r.indexes[host] = idx
		}
		excluded := ""
		if exceptHost == host {
			excluded = exceptInterface
		}
		conflicts, e := idx.Conflicts(domainString(change["address"]), change["vrf"], change["vni"], excluded)
		if e != nil {
			panic(e)
		}
		for _, entry := range conflicts {
			out = append(out, domainMerge(Record{"host": host, "name": cfgMap(cfgMap(r.documents[host])["device"])["name"]}, entry))
		}
	}
	return out
}
func fabricConflictNames(conflicts []Record) string {
	names := []string{}
	for _, c := range conflicts {
		names = append(names, domainString(c["name"])+" "+domainString(c["interface"]))
	}
	return strings.Join(names, "、")
}
func (r *fabricReview) reviewMissingMappings(fabric string, vni int, rows []Record, configs Record, hosts []string) {
	for _, row := range rows {
		if !domainEq(row["missing"], []string{"VLAN"}) {
			continue
		}
		evidence := r.observations(rows, func(peer Record) any {
			var gateway any
			if peer["svi"] != nil {
				gateway = cfgStrings(cfgMap(peer["svi"])["addresses"])
			}
			return Record{"missing": peer["missing"], "gateway": gateway, "vrf": cfgMap(peer["svi"])["vrf"]}
		})
		item := r.recommendation(fabric, vni, "fabric_vlan_mapping_missing", "补齐已有业务的 VLAN/VNI 关联", evidence)
		plan := InferServiceMapping(vni, row, rows)
		var change Record
		conflicts := []Record{}
		if plan != nil {
			change = plan.Change()
			conflicts = r.gatewayConflicts(configs, change, hosts, domainString(row["host"]), "Vlan"+domainString(change["vlan"]))
		}
		if len(conflicts) > 0 {
			item["evidence"] = append(cfgRows(item["evidence"]), conflicts...)
			domainAppend(item, "blockers", "同 VRF 存在跨 SVI/跨 VNI 网段重叠，不能通过新增映射扩大冲突："+fabricConflictNames(conflicts))
			plan = nil
		}
		if plan != nil {
			local := cfgMap(domainAt(cfgMap(row["config"]), "interfaces", "Vlan"+domainString(change["vlan"])))
			updated := []Record{}
			for _, entry := range evidence {
				if entry["host"] == row["host"] {
					entry = domainMerge(entry, Record{"vlan": domainString(change["vlan"]), "value": Record{"missing": []string{"VLAN/VNI 映射"}, "gateway": local["addresses"], "vrf": local["vrf"]}})
				}
				updated = append(updated, entry)
			}
			item["evidence"] = updated
			item["impact"] = "将已有 VLAN 接入既有 VXLAN 业务，可能立即扩展广播域；不创建 VLAN，不更改网关或 ACL。"
			domainAppend(item, "prerequisites", "本机未映射 VLAN 的网关、VRF、Anycast 身份及 ACL 与完整对端一致，NVE/EVPN 也已匹配；确认该业务确应在本机接入。")
			item["expected"] = "本机 VLAN/VNI 关联完整、VNI 状态符合预期，既有网关及 ACL 保持不变；接入业务验收通过。"
			item["resolves"] = []Record{{"code": "nve_l2_without_vlan", "vni": vni}}
			r.propose(item, plan, false)
		} else {
			domainAppend(item, "blockers", "没有唯一且完整的业务对应关系；需核对本机未映射 VLAN、网关、VRF、ACL 与对端配置，禁止按 VNI 数值猜测 VLAN。")
		}
		r.addItem(domainString(row["host"]), item)
	}
}
func (r *fabricReview) reviewGateway(fabric string, vni int, rows []Record, configs Record, hosts []string, blocked bool) {
	values := []any{}
	for _, row := range rows {
		if row["svi"] == nil {
			values = append(values, nil)
		} else {
			addresses := append([]string{}, cfgStrings(cfgMap(row["svi"])["addresses"])...)
			sort.Strings(addresses)
			values = append(values, addresses)
		}
	}
	if len(domainUniq(values)) == 1 {
		return
	}
	evidence := r.observations(rows, func(row Record) any {
		if row["svi"] == nil {
			return nil
		}
		return cfgStrings(cfgMap(row["svi"])["addresses"])
	})
	r.finding(fabric, vni, "fabric_gateway", "同业务网关地址不一致", evidence)
	expected := []any{}
	for _, value := range values {
		if value != nil && len(value.([]string)) > 0 {
			expected = append(expected, value)
		}
	}
	expected = domainUniq(expected)
	for i, row := range rows {
		if len(expected) == 1 && domainEq(values[i], expected[0]) {
			continue
		}
		item := r.recommendation(fabric, vni, "fabric_gateway", "网关地址需要一致", append([]Record{}, evidence...))
		var address any
		if len(expected) == 1 && len(expected[0].([]string)) == 1 {
			address = expected[0].([]string)[0]
		}
		change := Record{"kind": "svi_gateway_add", "vlan": cfgNumber(row["vlan"]), "vni": vni, "vrf": cfgMap(row["svi"])["vrf"], "address": address}
		contexts := []any{}
		for _, entry := range rows {
			contexts = append(contexts, []any{cfgMap(entry["svi"])["vrf"], cfgMap(entry["svi"])["anycast"], cfgMap(entry["config"])["anycast_mac"]})
		}
		contexts = domainUniq(contexts)
		contextOK := len(contexts) == 1
		if contextOK {
			for _, v := range contexts[0].([]any) {
				if !domainTruthy(v) {
					contextOK = false
				}
			}
		}
		conflicts := []Record{}
		if address != nil {
			conflicts = r.gatewayConflicts(configs, change, hosts, "", "")
		}
		item["evidence"] = append(cfgRows(item["evidence"]), conflicts...)
		plan := CandidateChangePlan(change, cfgMap(row["config"]))
		if len(conflicts) == 0 && contextOK && len(expected) == 1 && len(expected[0].([]string)) == 1 && plan != nil {
			r.propose(item, plan, blocked)
		} else {
			domainAppend(item, "blockers", "存在已有地址、跨 SVI/跨 VNI 网段冲突，或 VRF/Anycast 模式/MAC 不一致、缺少唯一网关；需先确认迁移设计，禁止重复添加网关。")
			if len(conflicts) > 0 {
				domainAppend(item, "blockers", "Fabric 内冲突接口："+fabricConflictNames(conflicts))
			}
		}
		r.addItem(domainString(row["host"]), item)
	}
}
