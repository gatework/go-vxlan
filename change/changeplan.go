package change

import (
	"fmt"
	"net/netip"
	"sort"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/configuration"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/internal/textparse"
)

// ChangePlan owns a validated business increment, commands and readback checks.
// Accessors return copies so subsequent caller mutations cannot alter approval.
type ChangePlan struct {
	change             vxlan.Record
	commands, rollback []string
	policy             vxlan.Record
}

func NewChangePlan(change vxlan.Record) (*ChangePlan, error) {
	if change == nil {
		return nil, fmt.Errorf("增量须为映射")
	}
	if _, err := vxlan.ProjectRecord(change); err != nil {
		return nil, err
	}
	kind := record.String(change["kind"])
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
		if !record.Contains(fields, k) {
			return nil, fmt.Errorf("增量字段无效")
		}
	}
	if !record.Integer(change["vlan"], 1, 4094) {
		return nil, fmt.Errorf("VLAN 无效")
	}
	if !record.Integer(change["vni"], 1, 16777215) {
		return nil, fmt.Errorf("VNI 无效")
	}
	p := &ChangePlan{change: record.Copy(change).(vxlan.Record)}
	vlan, vni := record.Number(change["vlan"]), record.Number(change["vni"])
	iface := fmt.Sprintf("Vlan%d", vlan)
	if kind != "svi_acl" {
		address, ok := change["address"].(string)
		vrf, vrfOK := change["vrf"].(string)
		network, e := netip.ParsePrefix(address)
		if !ok || !vrfOK || vrf == "" || textparse.Match(`\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}`, address) == nil || e != nil || !network.Addr().Is4() {
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
	direction := record.String(change["direction"])
	if !ok || textparse.Match(`[A-Za-z0-9_.-]{1,63}`, name) == nil || !record.Contains([]string{"in", "out"}, direction) {
		return nil, fmt.Errorf("ACL 参数无效")
	}
	create, ok := change["create_acl"].(bool)
	if !ok {
		return nil, fmt.Errorf("ACL 创建状态无效")
	}
	if change["previous_binding"] != nil && change["previous_binding"] != name {
		return nil, fmt.Errorf("不能覆盖既有绑定")
	}
	groups := vxlan.Record{}
	if g, exists := change["address_groups"]; exists {
		var ok bool
		groups, ok = g.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("ACL 依赖未验证")
		}
	}
	p.policy = configuration.ResolveACLPolicy(vxlan.Record{"address_groups": groups}, change["entries"])
	if p.policy == nil || !record.Equal(p.policy["address_groups"], groups) {
		return nil, fmt.Errorf("ACL 规则或依赖未验证")
	}
	if len(record.Rows(p.policy["rules"])) == 0 {
		return nil, fmt.Errorf("无有效 ACL 规则")
	}
	entries := append([]vxlan.Record{}, record.Rows(change["entries"])...)
	sort.SliceStable(entries, func(i, j int) bool {
		return record.Number(entries[i]["sequence"]) < record.Number(entries[j]["sequence"])
	})
	rules := []string{}
	for _, entry := range entries {
		if entry["action"] == "remark" {
			continue
		}
		if textparse.Match(`(?:ip|tcp|udp|icmp|igmp|gre|esp|ah|ospf) [A-Za-z0-9_.:/ -]+`, record.String(entry["expression"])) == nil {
			return nil, fmt.Errorf("ACL 规则语法未验证")
		}
		rules = append(rules, fmt.Sprintf("  %d %s %s", record.Number(entry["sequence"]), entry["action"], entry["expression"]))
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
func CandidateChangePlan(change, config vxlan.Record) *ChangePlan {
	p, e := NewChangePlan(change)
	if e != nil || !p.Eligible(config) {
		return nil
	}
	return p
}
func (p *ChangePlan) Change() vxlan.Record { return record.Copy(p.change).(vxlan.Record) }
func (p *ChangePlan) Commands() []string   { return append([]string{}, p.commands...) }
func (p *ChangePlan) Rollback() []string   { return append([]string{}, p.rollback...) }
func (p *ChangePlan) iface() string {
	return fmt.Sprintf("Vlan%d", record.Number(p.change["vlan"]))
}
func (p *ChangePlan) mappedSVI(config vxlan.Record) vxlan.Record {
	if !record.Equal(record.Map(config["vlan_vnis"])[record.String(p.change["vlan"])], p.change["vni"]) {
		return nil
	}
	svi, ok := record.Map(config["interfaces"])[p.iface()].(map[string]any)
	if !ok {
		return nil
	}
	return svi
}
func (p *ChangePlan) gatewayContext(config vxlan.Record) bool {
	svi := record.Map(record.Map(config["interfaces"])[p.iface()])
	if svi["anycast"] != true || !record.Equal(svi["vrf"], p.change["vrf"]) {
		return false
	}
	network, e := configuration.Network(record.String(p.change["address"]))
	if e != nil {
		return false
	}
	for name, v := range record.Map(config["interfaces"]) {
		other := record.Map(v)
		if name == p.iface() || !record.Equal(other["vrf"], p.change["vrf"]) {
			continue
		}
		for _, address := range record.StringSlice(other["addresses"]) {
			candidate, e := configuration.Network(address)
			if e != nil || configuration.Overlap(network, candidate) {
				return false
			}
		}
	}
	return true
}
func (p *ChangePlan) creationIsolated(config vxlan.Record) bool {
	for _, binding := range configuration.ACLBindings(config, record.String(p.change["acl"])) {
		if binding["interface"] != p.iface() || binding["direction"] != p.change["direction"] {
			return false
		}
	}
	return true
}
func (p *ChangePlan) Eligible(config vxlan.Record) (result bool) {
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
		return svi != nil && p.gatewayContext(config) && len(record.StringSlice(svi["addresses"])) == 0
	case "vlan_vni_add":
		mappings := record.Map(config["vlan_vnis"])
		value, exists := mappings[record.String(p.change["vlan"])]
		return exists && value == nil && p.targetState(config)
	case "svi_acl":
		svi := p.mappedSVI(config)
		if svi == nil || !record.Equal(configuration.ResolveACLPolicy(config, p.change["entries"]), p.policy) {
			return false
		}
		if p.change["create_acl"] == true && !p.creationIsolated(config) {
			return false
		}
		entries := record.Map(config["acls"])[record.String(p.change["acl"])]
		binding := record.Map(svi["acl_bindings"])[record.String(p.change["direction"])]
		return record.Equal(binding, p.change["previous_binding"]) && ((p.change["create_acl"] == true && entries == nil) || (p.change["create_acl"] == false && record.Equal(configuration.ACLRules(entries), p.policy["rules"])))
	}
	return false
}
func (p *ChangePlan) targetState(config vxlan.Record) bool {
	switch p.change["kind"] {
	case "svi_gateway_add":
		return p.gatewayContext(config) && record.Equal(record.At(config, "interfaces", p.iface(), "addresses"), []string{record.String(p.change["address"])})
	case "vlan_vni_add":
		vni := record.String(p.change["vni"])
		member := record.Map(record.At(config, "nve", "members", vni))
		if !p.gatewayContext(config) || !record.Equal(record.At(config, "interfaces", p.iface(), "addresses"), []string{record.String(p.change["address"])}) || member["associate_vrf"] != false || record.At(config, "evpn", vni, "type") != "l2" {
			return false
		}
		for vlan, mapped := range record.Map(config["vlan_vnis"]) {
			if vlan != record.String(p.change["vlan"]) && record.Equal(mapped, p.change["vni"]) {
				return false
			}
		}
		return true
	case "svi_acl":
		return (p.change["create_acl"] != true || p.creationIsolated(config)) && record.At(config, "interfaces", p.iface(), "acl_bindings", record.String(p.change["direction"])) == p.change["acl"] && record.Equal(configuration.ResolveACLPolicy(config, record.Map(config["acls"])[record.String(p.change["acl"])]), p.policy)
	}
	return false
}
func (p *ChangePlan) preservedContext(config vxlan.Record) vxlan.Record {
	context := record.Copy(config).(vxlan.Record)
	for _, key := range []string{"config_digest", "review_status", "review_findings", "segments", "unnumbered_addresses"} {
		delete(context, key)
	}
	acls := record.Map(context["acls"])
	for name, entries := range acls {
		acls[name] = configuration.ACLRules(entries)
	}
	switch p.change["kind"] {
	case "svi_gateway_add":
		delete(record.Map(record.Map(context["interfaces"])[p.iface()]), "addresses")
	case "vlan_vni_add":
		delete(record.Map(context["vlan_vnis"]), record.String(p.change["vlan"]))
	case "svi_acl":
		delete(record.Map(record.At(context, "interfaces", p.iface(), "acl_bindings")), record.String(p.change["direction"]))
		if p.change["create_acl"] == true {
			delete(acls, record.String(p.change["acl"]))
		}
	}
	return context
}
func (p *ChangePlan) Satisfied(after, before vxlan.Record) (result bool) {
	defer func() {
		if recover() != nil {
			result = false
		}
	}()
	if _, err := vxlan.ProjectRecord(vxlan.Record{"before": before, "after": after}); err != nil {
		return false
	}
	return p.Eligible(before) && after != nil && p.mappedSVI(after) != nil && record.Equal(p.preservedContext(before), p.preservedContext(after)) && p.targetState(after)
}
