package vxlan

import (
	"fmt"
	"net/netip"
	"sort"
)

// ChangePlan owns a validated business increment, commands and readback checks.
// Accessors return copies so subsequent caller mutations cannot alter approval.
type ChangePlan struct {
	change             Record
	commands, rollback []string
	policy             Record
}

func NewChangePlan(change Record) (*ChangePlan, error) {
	if change == nil {
		return nil, fmt.Errorf("增量须为映射")
	}
	kind := domainString(change["kind"])
	fields := []string{"kind", "vlan", "vni"}
	switch kind {
	case "vlan_vni_add", "svi_gateway_add":
		fields = append(fields, "vrf", "address")
	case "svi_acl":
		fields = append(fields, "acl", "direction", "entries", "address_groups", "create_acl", "previous_binding")
	default:
		return nil, fmt.Errorf("不支持的增量类型")
	}
	for k := range change {
		if !domainHas(fields, k) {
			return nil, fmt.Errorf("增量字段无效")
		}
	}
	if !domainInteger(change["vlan"], 1, 4094) {
		return nil, fmt.Errorf("VLAN 无效")
	}
	if !domainInteger(change["vni"], 1, 16777215) {
		return nil, fmt.Errorf("VNI 无效")
	}
	p := &ChangePlan{change: domainCopy(change).(Record)}
	vlan, vni := cfgNumber(change["vlan"]), cfgNumber(change["vni"])
	iface := fmt.Sprintf("Vlan%d", vlan)
	if kind != "svi_acl" {
		address, ok := change["address"].(string)
		vrf, vrfOK := change["vrf"].(string)
		network, e := netip.ParsePrefix(address)
		if !ok || !vrfOK || vrf == "" || cfgMatch(`\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}`, address) == nil || e != nil || !network.Addr().Is4() {
			return nil, fmt.Errorf("缺少已验证的业务网关")
		}
		if kind == "vlan_vni_add" {
			p.commands = []string{"configure terminal", fmt.Sprintf("vlan %d", vlan), fmt.Sprintf("  vn-segment %d", vni), "end"}
			p.rollback = []string{"configure terminal", fmt.Sprintf("vlan %d", vlan), "  no vn-segment", "end"}
		} else {
			p.commands = []string{"configure terminal", "interface " + iface, "  ip address " + address, "end"}
			p.rollback = []string{"configure terminal", "interface " + iface, "  no ip address " + address, "end"}
		}
		return p, nil
	}
	name, ok := change["acl"].(string)
	direction := domainString(change["direction"])
	if !ok || cfgMatch(`[A-Za-z0-9_.-]{1,63}`, name) == nil || !domainHas([]string{"in", "out"}, direction) {
		return nil, fmt.Errorf("ACL 参数无效")
	}
	create, ok := change["create_acl"].(bool)
	if !ok {
		return nil, fmt.Errorf("ACL 创建状态无效")
	}
	if change["previous_binding"] != nil && change["previous_binding"] != name {
		return nil, fmt.Errorf("不能覆盖既有绑定")
	}
	groups := Record{}
	if g, exists := change["address_groups"]; exists {
		var ok bool
		groups, ok = g.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("ACL 依赖未验证")
		}
	}
	p.policy = ResolveACLPolicy(Record{"address_groups": groups}, change["entries"])
	if p.policy == nil || !domainEq(p.policy["address_groups"], groups) {
		return nil, fmt.Errorf("ACL 规则或依赖未验证")
	}
	if len(cfgRows(p.policy["rules"])) == 0 {
		return nil, fmt.Errorf("无有效 ACL 规则")
	}
	entries := append([]Record{}, cfgRows(change["entries"])...)
	sort.SliceStable(entries, func(i, j int) bool { return cfgNumber(entries[i]["sequence"]) < cfgNumber(entries[j]["sequence"]) })
	rules := []string{}
	for _, entry := range entries {
		if entry["action"] == "remark" {
			continue
		}
		if cfgMatch(`(?:ip|tcp|udp|icmp|igmp|gre|esp|ah|ospf) [A-Za-z0-9_.:/ -]+`, domainString(entry["expression"])) == nil {
			return nil, fmt.Errorf("ACL 规则语法未验证")
		}
		rules = append(rules, fmt.Sprintf("  %d %s %s", cfgNumber(entry["sequence"]), entry["action"], entry["expression"]))
	}
	p.commands = []string{"configure terminal"}
	if create {
		p.commands = append(p.commands, "ip access-list "+name)
		p.commands = append(p.commands, rules...)
		p.commands = append(p.commands, "exit")
	}
	p.commands = append(p.commands, "interface "+iface, "  ip access-group "+name+" "+direction, "end")
	p.rollback = []string{"configure terminal"}
	if change["previous_binding"] == nil {
		p.rollback = append(p.rollback, "interface "+iface, "  no ip access-group "+name+" "+direction, "exit")
	}
	if create {
		p.rollback = append(p.rollback, "no ip access-list "+name)
	}
	p.rollback = append(p.rollback, "end")
	return p, nil
}
func CandidateChangePlan(change, config Record) *ChangePlan {
	p, e := NewChangePlan(change)
	if e != nil || !p.Eligible(config) {
		return nil
	}
	return p
}
func (p *ChangePlan) Change() Record     { return domainCopy(p.change).(Record) }
func (p *ChangePlan) Commands() []string { return append([]string{}, p.commands...) }
func (p *ChangePlan) Rollback() []string { return append([]string{}, p.rollback...) }
func (p *ChangePlan) iface() string      { return fmt.Sprintf("Vlan%d", cfgNumber(p.change["vlan"])) }
func (p *ChangePlan) mappedSVI(config Record) Record {
	if !domainEq(cfgMap(config["vlan_vnis"])[domainString(p.change["vlan"])], p.change["vni"]) {
		return nil
	}
	svi, ok := cfgMap(config["interfaces"])[p.iface()].(map[string]any)
	if !ok {
		return nil
	}
	return svi
}
func (p *ChangePlan) gatewayContext(config Record) bool {
	svi := cfgMap(cfgMap(config["interfaces"])[p.iface()])
	if svi["anycast"] != true || !domainEq(svi["vrf"], p.change["vrf"]) {
		return false
	}
	network, e := domainNetwork(domainString(p.change["address"]))
	if e != nil {
		return false
	}
	for name, v := range cfgMap(config["interfaces"]) {
		other := cfgMap(v)
		if name == p.iface() || !domainEq(other["vrf"], p.change["vrf"]) {
			continue
		}
		for _, address := range cfgStrings(other["addresses"]) {
			candidate, e := domainNetwork(address)
			if e != nil || domainOverlap(network, candidate) {
				return false
			}
		}
	}
	return true
}
func (p *ChangePlan) creationIsolated(config Record) bool {
	for _, binding := range ACLBindings(config, domainString(p.change["acl"])) {
		if binding["interface"] != p.iface() || binding["direction"] != p.change["direction"] {
			return false
		}
	}
	return true
}
func (p *ChangePlan) Eligible(config Record) (result bool) {
	defer func() {
		if recover() != nil {
			result = false
		}
	}()
	if config == nil {
		return false
	}
	switch p.change["kind"] {
	case "svi_gateway_add":
		svi := p.mappedSVI(config)
		return svi != nil && p.gatewayContext(config) && len(cfgStrings(svi["addresses"])) == 0
	case "vlan_vni_add":
		mappings := cfgMap(config["vlan_vnis"])
		value, exists := mappings[domainString(p.change["vlan"])]
		return exists && value == nil && p.targetState(config)
	case "svi_acl":
		svi := p.mappedSVI(config)
		if svi == nil || !domainEq(ResolveACLPolicy(config, p.change["entries"]), p.policy) {
			return false
		}
		if p.change["create_acl"] == true && !p.creationIsolated(config) {
			return false
		}
		entries := cfgMap(config["acls"])[domainString(p.change["acl"])]
		binding := cfgMap(svi["acl_bindings"])[domainString(p.change["direction"])]
		return domainEq(binding, p.change["previous_binding"]) && ((p.change["create_acl"] == true && entries == nil) || (p.change["create_acl"] == false && domainEq(ACLRules(entries), p.policy["rules"])))
	}
	return false
}
func (p *ChangePlan) targetState(config Record) bool {
	switch p.change["kind"] {
	case "svi_gateway_add":
		return p.gatewayContext(config) && domainEq(domainAt(config, "interfaces", p.iface(), "addresses"), []string{domainString(p.change["address"])})
	case "vlan_vni_add":
		vni := domainString(p.change["vni"])
		member := cfgMap(domainAt(config, "nve", "members", vni))
		if !p.gatewayContext(config) || !domainEq(domainAt(config, "interfaces", p.iface(), "addresses"), []string{domainString(p.change["address"])}) || member["associate_vrf"] != false || domainAt(config, "evpn", vni, "type") != "l2" {
			return false
		}
		for vlan, mapped := range cfgMap(config["vlan_vnis"]) {
			if vlan != domainString(p.change["vlan"]) && domainEq(mapped, p.change["vni"]) {
				return false
			}
		}
		return true
	case "svi_acl":
		return (p.change["create_acl"] != true || p.creationIsolated(config)) && domainAt(config, "interfaces", p.iface(), "acl_bindings", domainString(p.change["direction"])) == p.change["acl"] && domainEq(ResolveACLPolicy(config, cfgMap(config["acls"])[domainString(p.change["acl"])]), p.policy)
	}
	return false
}
func (p *ChangePlan) preservedContext(config Record) Record {
	context := domainCopy(config).(Record)
	for _, key := range []string{"config_digest", "review_status", "review_findings", "segments", "unnumbered_addresses"} {
		delete(context, key)
	}
	acls := cfgMap(context["acls"])
	for name, entries := range acls {
		acls[name] = ACLRules(entries)
	}
	switch p.change["kind"] {
	case "svi_gateway_add":
		delete(cfgMap(cfgMap(context["interfaces"])[p.iface()]), "addresses")
	case "vlan_vni_add":
		delete(cfgMap(context["vlan_vnis"]), domainString(p.change["vlan"]))
	case "svi_acl":
		delete(cfgMap(domainAt(context, "interfaces", p.iface(), "acl_bindings")), domainString(p.change["direction"]))
		if p.change["create_acl"] == true {
			delete(acls, domainString(p.change["acl"]))
		}
	}
	return context
}
func (p *ChangePlan) Satisfied(after, before Record) (result bool) {
	defer func() {
		if recover() != nil {
			result = false
		}
	}()
	return p.Eligible(before) && after != nil && p.mappedSVI(after) != nil && domainEq(p.preservedContext(before), p.preservedContext(after)) && p.targetState(after)
}
