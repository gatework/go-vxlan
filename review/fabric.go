package review

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	vxlan "github.com/gatework/go-vxlan"
	changepkg "github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/configuration"
	"github.com/gatework/go-vxlan/internal/record"
)

var fabricRoles = []string{"leaves", "borders", "spines"}

func ValidateFabricPolicy(policy vxlan.Record) error {
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
			if !record.Contains(fabricRoles, role) {
				return fmt.Errorf("Fabric 需要明确的角色成员清单")
			}
		}
		count := 0
		for _, role := range fabricRoles {
			v, exists := group[role]
			if !exists {
				continue
			}
			hosts, ok := record.Strings(v)
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
	documents      vxlan.Record
	groups         vxlan.Record
	findings       []vxlan.Record
	items          vxlan.Record
	coverage       []vxlan.Record
	role           any
	indexes        map[string]*configuration.SubnetIndex
	verify         []string
	verifyBlockers []string
}

// ReviewFabric compares explicit same-role deployed services and blocks unsafe drafts.
// Verification commands come from the selected profile's catalog. A missing
// fabric scope preserves review findings but prevents executable candidates.
func ReviewFabric(documents []vxlan.Record, policy vxlan.Record, queries QueryCatalog) (result vxlan.Record, err error) {
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
	r := &fabricReview{
		documents: vxlan.Record{}, groups: vxlan.Record{}, items: vxlan.Record{},
		findings: []vxlan.Record{}, coverage: []vxlan.Record{},
		indexes: map[string]*configuration.SubnetIndex{},
	}
	if queries != nil {
		r.verify = append([]string{}, queries.VerificationCommands("fabric")...)
	}
	if len(r.verify) == 0 {
		r.verifyBlockers = []string{"所选 Profile 缺少 Fabric 验证查询，无法验证变更；先补充查询定义。"}
	}
	observed := []string{}
	for _, document := range documents {
		d, err := vxlan.ProjectRecord(document)
		if err != nil {
			return nil, err
		}
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
	for _, fabric := range record.Keys(record.Map(policy["fabrics"])) {
		group := record.Map(record.Map(policy["fabrics"])[fabric])
		normalized := vxlan.Record{}
		for _, role := range fabricRoles {
			members := record.StringSlice(group[role])
			normalized[role] = append([]string{}, members...)
			hosts = append(hosts, members...)
		}
		r.groups[fabric] = normalized
	}
	assigned, unassigned, missing := []string{}, []string{}, []string{}
	for _, h := range hosts {
		if record.Contains(observed, h) {
			assigned = append(assigned, h)
		} else {
			missing = append(missing, h)
		}
	}
	for _, h := range observed {
		if !record.Contains(hosts, h) {
			unassigned = append(unassigned, h)
		}
	}
	inventory := vxlan.Record{"groups": r.groups, "assigned": assigned, "unassigned": unassigned, "missing": missing}
	if len(unassigned) > 0 {
		r.finding("未归属", nil, "fabric_scope_unassigned", "已采集设备未纳入 Fabric 策略，跨设备审查未覆盖", unassigned)
	}
	for _, fabric := range record.Keys(r.groups) {
		group := record.Map(r.groups[fabric])
		configs := vxlan.Record{}
		order := []string{}
		unknown := []string{}
		for _, role := range fabricRoles {
			for _, host := range record.StringSlice(group[role]) {
				config := configuration.CompleteConfig(record.Map(r.documents[host]))
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
			members := record.StringSlice(group[role])
			if len(members) > 0 {
				local := vxlan.Record{}
				for _, h := range members {
					local[h] = configs[h]
				}
				r.reviewGroup(fabric, local, configs, members, order)
			}
		}
		r.role = "spines"
		for _, host := range record.StringSlice(group["spines"]) {
			r.reviewSpine(fabric, host, record.Map(configs[host]))
		}
		r.role = nil
		r.reviewSubnets(fabric, configs, order)
	}
	return vxlan.Record{"schema_version": 2, "scope": "same_role_same_deployed_vni", "inventory": inventory, "findings": r.findings, "device_items": r.items, "coverage": r.coverage}, nil
}
func (r *fabricReview) finding(fabric string, vni any, code, title string, evidence any) {
	r.findings = append(r.findings, vxlan.Record{"fabric": fabric, "role": r.role, "vni": vni, "code": code, "title": title, "evidence": evidence})
}
func (r *fabricReview) observations(rows []vxlan.Record, value func(vxlan.Record) any) []vxlan.Record {
	out := []vxlan.Record{}
	for _, row := range rows {
		out = append(out, vxlan.Record{"host": row["host"], "name": record.Map(record.Map(r.documents[record.String(row["host"])])["device"])["name"], "vlan": row["vlan"], "value": value(row)})
	}
	return out
}
func (r *fabricReview) compare(fabric string, vni any, code, title string, rows []vxlan.Record, value func(vxlan.Record) any) {
	evidence := r.observations(rows, value)
	values := []any{}
	for _, e := range evidence {
		values = append(values, e["value"])
	}
	if len(record.Unique(values)) > 1 {
		r.finding(fabric, vni, code, title, evidence)
	}
}
func (r *fabricReview) addItem(host string, item vxlan.Record) {
	r.items[host] = append(record.Rows(r.items[host]), item)
}
func (r *fabricReview) recommendation(fabric string, vni any, code, title string, evidence []vxlan.Record) vxlan.Record {
	scope := "角色核查"
	if vni != nil {
		scope = "VNI " + record.String(vni)
	}
	return vxlan.Record{
		"code": code, "category": "fabric",
		"scope": fabric + " / " + record.String(r.role) + " / " + scope,
		"title": title, "status": "blocked", "evidence": evidence,
		"prerequisites": []string{
			"仅在本 Fabric、相同已部署业务范围内适用；核对业务访问策略与维护窗口。",
			"下发前重新读取配置，任何变化均使计划过期；逐设备逐项确认，不批量重放。",
		},
		"blockers": append([]string{}, r.verifyBlockers...),
		"commands": []string{}, "rollback": []string{},
		"verify":     append([]string{}, r.verify...),
		"impact":     "改变网关或 ACL 可能改变可达性及业务隔离；配置回读通过后仍需业务验收。",
		"expected":   "共同业务的网关和访问控制一致，允许/拒绝流量均符合设计。",
		"references": []string{},
	}
}
func (r *fabricReview) propose(item vxlan.Record, plan *changepkg.ChangePlan, blocked bool) {
	if blocked {
		domainAppend(item, "blockers", "共同业务的承载关联或复制/路由声明存在冲突，先解决这些前置问题，再生成网关或 ACL 增量。")
		return
	}
	if len(r.verifyBlockers) > 0 {
		return
	}
	item["status"] = "candidate"
	item["change"] = plan.Change()
	item["commands"] = plan.Commands()
	item["rollback"] = plan.Rollback()
}
func (r *fabricReview) reviewGroup(fabric string, configs, all vxlan.Record, hosts, allHosts []string) {
	services := configuration.CatalogForHosts(configs, hosts)
	policies := vxlan.Record{}
	for _, host := range hosts {
		policies[host] = vxlan.Record{}
		for name, entries := range record.Map(record.Map(configs[host])["acls"]) {
			record.Map(policies[host])[name] = configuration.ResolveACLPolicy(record.Map(configs[host]), entries)
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
		incomplete := []vxlan.Record{}
		for _, row := range rows {
			host := record.String(row["host"])
			if !record.Contains(deployed, host) {
				deployed = append(deployed, host)
			}
			if len(record.StringSlice(row["missing"])) > 0 {
				incomplete = append(incomplete, row)
				if !record.Contains(incompleteHosts, host) {
					incompleteHosts = append(incompleteHosts, host)
				}
			}
		}
		notDeployed := []string{}
		for _, host := range hosts {
			if !record.Contains(deployed, host) {
				notDeployed = append(notDeployed, host)
			}
		}
		r.coverage = append(r.coverage, vxlan.Record{"fabric": fabric, "role": r.role, "vni": vni, "deployed": deployed, "not_deployed": notDeployed, "incomplete": incompleteHosts})
		if len(incomplete) > 0 {
			r.finding(fabric, vni, "fabric_service_incomplete", "业务已开始部署，但 VLAN/NVE/EVPN 关联不完整", r.observations(incomplete, func(row vxlan.Record) any { return vxlan.Record{"missing": row["missing"]} }))
			r.reviewMissingMappings(fabric, vni, rows, all, allHosts)
		}
		if len(deployed) != len(rows) {
			evidence := []vxlan.Record{}
			for _, row := range rows {
				evidence = append(evidence, record.Select(row, "host", "vlan"))
			}
			r.finding(fabric, vni, "fabric_vlan_mapping_ambiguous", "同一 Leaf 将多个 VLAN 映射到相同 VNI", evidence)
			continue
		}
		if len(rows) < 2 {
			continue
		}
		constraints := r.reviewTransport(fabric, vni, rows)
		blocked := len(incomplete) > 0 || constraints
		filtered := []vxlan.Record{}
		for _, row := range rows {
			if row["vlan"] != nil {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
		if len(rows) < 2 {
			continue
		}
		r.compare(fabric, vni, "fabric_vlan_mapping", "相同 VNI 的本地 VLAN 编号不一致", rows, func(row vxlan.Record) any { return row["vlan"] })
		gateway := false
		for _, row := range rows {
			svi := record.Map(row["svi"])
			if row["svi"] != nil && (record.Truthy(svi["anycast"]) || len(record.StringSlice(svi["addresses"])) > 0) {
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
			r.compare(fabric, vni, "fabric_"+field, "业务 SVI 的 "+field+" 不一致", rows, func(row vxlan.Record) any { return record.Map(row["svi"])[field] })
		}
		r.compare(fabric, vni, "fabric_anycast_mac", "Anycast 网关 MAC 不一致", rows, func(row vxlan.Record) any { return record.Map(row["config"])["anycast_mac"] })
	}
	r.reviewACLCatalog(fabric, configs, policies, hosts)
	r.reviewAddressGroups(fabric, configs, hosts)
}
func (r *fabricReview) reviewTransport(fabric string, vni int, rows []vxlan.Record) bool {
	before := len(r.findings)
	r.compare(fabric, vni, "fabric_replication", "NVE 复制方式或组播组声明不一致", rows, func(row vxlan.Record) any {
		if row["nve"] == nil {
			return nil
		}
		return record.Select(configuration.EffectiveNVEMember(record.Map(row["config"]), record.Map(row["nve"])), "replication", "multicast_group")
	})
	r.compare(fabric, vni, "fabric_arp_suppression", "ARP 抑制的显式配置不一致", rows, func(row vxlan.Record) any { return record.Map(row["nve"])["suppress_arp"] })
	r.compare(fabric, vni, "fabric_route_targets", "EVPN 导入/导出 RT 声明不一致，需核对路由互通与隔离", rows, func(row vxlan.Record) any {
		if row["evpn"] == nil {
			return nil
		}
		return configuration.ServiceRouteTargets(record.Map(row["evpn"])["route_targets"], record.Map(record.Map(row["config"])["bgp"])["asn"], vni)
	})
	tenants := []vxlan.Record{}
	for _, row := range rows {
		if record.Map(row["svi"])["vrf"] != nil {
			tenants = append(tenants, row)
		}
	}
	if len(tenants) >= 2 {
		r.compare(fabric, vni, "fabric_tenant_routing", "共同业务的租户 VNI 或路由导入/导出声明不一致", tenants, func(row vxlan.Record) any {
			return configuration.ServiceTenant(record.Map(row["config"]), record.String(record.Map(row["svi"])["vrf"]))
		})
	}
	return len(r.findings) > before
}
func (r *fabricReview) reviewSpine(fabric, host string, config vxlan.Record) {
	services := configuration.CatalogForHosts(vxlan.Record{host: config}, []string{host})
	if len(services) == 0 {
		return
	}
	vnis := []int{}
	for vni := range services {
		vnis = append(vnis, vni)
	}
	sort.Ints(vnis)
	evidence := []vxlan.Record{{"host": host, "value": vxlan.Record{"role": "spines", "l2_vnis": vnis}}}
	r.finding(fabric, nil, "fabric_role_conflict", "声明为 Spine，但存在 L2 业务承载配置", evidence)
	item := r.recommendation(fabric, nil, "fabric_role_conflict", "核对 Spine 是否应承担业务 VTEP 职责", evidence)
	domainAppend(item, "blockers", "先确认角色或迁移残留；不能因为出现 NVE 就自动把 Spine 当作 Leaf，不能自动补业务配置或删除 NVE。")
	r.addItem(host, item)
}
func (r *fabricReview) gatewayConflicts(configs, change vxlan.Record, hosts []string, exceptHost, exceptInterface string) []vxlan.Record {
	out := []vxlan.Record{}
	for _, host := range hosts {
		idx := r.indexes[host]
		if idx == nil {
			idx = configuration.NewSubnetIndex(record.Map(configs[host]))
			r.indexes[host] = idx
		}
		excluded := ""
		if exceptHost == host {
			excluded = exceptInterface
		}
		conflicts, e := idx.Conflicts(record.String(change["address"]), change["vrf"], change["vni"], excluded)
		if e != nil {
			panic(e)
		}
		for _, entry := range conflicts {
			out = append(out, record.Merge(vxlan.Record{"host": host, "name": record.Map(record.Map(r.documents[host])["device"])["name"]}, entry))
		}
	}
	return out
}
func fabricConflictNames(conflicts []vxlan.Record) string {
	names := []string{}
	for _, c := range conflicts {
		names = append(names, record.String(c["name"])+" "+record.String(c["interface"]))
	}
	return strings.Join(names, "、")
}
func (r *fabricReview) reviewMissingMappings(fabric string, vni int, rows []vxlan.Record, configs vxlan.Record, hosts []string) {
	for _, row := range rows {
		if !record.Equal(row["missing"], []string{"VLAN"}) {
			continue
		}
		evidence := r.observations(rows, func(peer vxlan.Record) any {
			var gateway any
			if peer["svi"] != nil {
				gateway = record.StringSlice(record.Map(peer["svi"])["addresses"])
			}
			return vxlan.Record{"missing": peer["missing"], "gateway": gateway, "vrf": record.Map(peer["svi"])["vrf"]}
		})
		item := r.recommendation(fabric, vni, "fabric_vlan_mapping_missing", "补齐已有业务的 VLAN/VNI 关联", evidence)
		plan := InferServiceMapping(vni, row, rows)
		var change vxlan.Record
		conflicts := []vxlan.Record{}
		if plan != nil {
			change = plan.Change()
			conflicts = r.gatewayConflicts(configs, change, hosts, record.String(row["host"]), "Vlan"+record.String(change["vlan"]))
		}
		if len(conflicts) > 0 {
			item["evidence"] = append(record.Rows(item["evidence"]), conflicts...)
			domainAppend(item, "blockers", "同 VRF 存在跨 SVI/跨 VNI 网段重叠，不能通过新增映射扩大冲突："+fabricConflictNames(conflicts))
			plan = nil
		}
		if plan != nil {
			local := record.Map(record.At(record.Map(row["config"]), "interfaces", "Vlan"+record.String(change["vlan"])))
			updated := []vxlan.Record{}
			for _, entry := range evidence {
				if entry["host"] == row["host"] {
					entry = record.Merge(entry, vxlan.Record{"vlan": record.String(change["vlan"]), "value": vxlan.Record{"missing": []string{"VLAN/VNI 映射"}, "gateway": local["addresses"], "vrf": local["vrf"]}})
				}
				updated = append(updated, entry)
			}
			item["evidence"] = updated
			item["impact"] = "将已有 VLAN 接入既有 VXLAN 业务，可能立即扩展广播域；不创建 VLAN，不更改网关或 ACL。"
			domainAppend(item, "prerequisites", "本机未映射 VLAN 的网关、VRF、Anycast 身份及 ACL 与完整对端一致，NVE/EVPN 也已匹配；确认该业务确应在本机接入。")
			item["expected"] = "本机 VLAN/VNI 关联完整、VNI 状态符合预期，既有网关及 ACL 保持不变；接入业务验收通过。"
			item["resolves"] = []vxlan.Record{{"code": "nve_l2_without_vlan", "vni": vni}}
			r.propose(item, plan, false)
		} else {
			domainAppend(item, "blockers", "没有唯一且完整的业务对应关系；需核对本机未映射 VLAN、网关、VRF、ACL 与对端配置，禁止按 VNI 数值猜测 VLAN。")
		}
		r.addItem(record.String(row["host"]), item)
	}
}
func (r *fabricReview) reviewGateway(fabric string, vni int, rows []vxlan.Record, configs vxlan.Record, hosts []string, blocked bool) {
	values := []any{}
	for _, row := range rows {
		if row["svi"] == nil {
			values = append(values, nil)
		} else {
			addresses := append([]string{}, record.StringSlice(record.Map(row["svi"])["addresses"])...)
			sort.Strings(addresses)
			values = append(values, addresses)
		}
	}
	if len(record.Unique(values)) == 1 {
		return
	}
	evidence := r.observations(rows, func(row vxlan.Record) any {
		if row["svi"] == nil {
			return nil
		}
		return record.StringSlice(record.Map(row["svi"])["addresses"])
	})
	r.finding(fabric, vni, "fabric_gateway", "同业务网关地址不一致", evidence)
	expected := []any{}
	for _, value := range values {
		if value != nil && len(value.([]string)) > 0 {
			expected = append(expected, value)
		}
	}
	expected = record.Unique(expected)
	var address any
	if len(expected) == 1 && len(expected[0].([]string)) == 1 {
		address = expected[0].([]string)[0]
	}
	contexts := make([]any, 0, len(rows))
	for _, entry := range rows {
		contexts = append(contexts, []any{record.Map(entry["svi"])["vrf"], record.Map(entry["svi"])["anycast"], record.Map(entry["config"])["anycast_mac"]})
	}
	contexts = record.Unique(contexts)
	contextOK := len(contexts) == 1
	if contextOK {
		for _, value := range contexts[0].([]any) {
			if !record.Truthy(value) {
				contextOK = false
			}
		}
	}
	// Address, VNI, host scope and exclusions are fixed for this gateway review.
	// Query each distinct VRF once; candidate count must not multiply a fabric scan.
	conflictsByVRF := map[string][]vxlan.Record{}
	for i, row := range rows {
		if len(expected) == 1 && record.Equal(values[i], expected[0]) {
			continue
		}
		item := r.recommendation(fabric, vni, "fabric_gateway", "网关地址需要一致", append([]vxlan.Record{}, evidence...))
		change := vxlan.Record{"kind": "svi_gateway_add", "vlan": record.Number(row["vlan"]), "vni": vni, "vrf": record.Map(row["svi"])["vrf"], "address": address}
		conflicts := []vxlan.Record{}
		if address != nil {
			key, err := record.CanonicalJSON(change["vrf"])
			if err != nil {
				panic(err)
			}
			var found bool
			conflicts, found = conflictsByVRF[string(key)]
			if !found {
				conflicts = r.gatewayConflicts(configs, change, hosts, "", "")
				conflictsByVRF[string(key)] = conflicts
			}
		}
		item["evidence"] = append(record.Rows(item["evidence"]), record.CopyRecords(conflicts)...)
		plan := changepkg.CandidateChangePlan(change, record.Map(row["config"]))
		if len(conflicts) == 0 && contextOK && len(expected) == 1 && len(expected[0].([]string)) == 1 && plan != nil {
			r.propose(item, plan, blocked)
		} else {
			domainAppend(item, "blockers", "存在已有地址、跨 SVI/跨 VNI 网段冲突，或 VRF/Anycast 模式/MAC 不一致、缺少唯一网关；需先确认迁移设计，禁止重复添加网关。")
			if len(conflicts) > 0 {
				domainAppend(item, "blockers", "Fabric 内冲突接口："+fabricConflictNames(conflicts))
			}
		}
		r.addItem(record.String(row["host"]), item)
	}
}
