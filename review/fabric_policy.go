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
	"github.com/gatework/go-vxlan/internal/textparse"
)

func (r *fabricReview) reviewACL(fabric string, vni int, rows []vxlan.Record, direction string, policies vxlan.Record, blocked bool) {
	bindings, definitions := []any{}, []any{}
	unknown := false
	for _, row := range rows {
		name := record.Map(record.Map(row["svi"])["acl_bindings"])[direction]
		var definition any
		if name != nil {
			definition = record.Map(policies[record.String(row["host"])])[record.String(name)]
			if record.Map(definition) == nil || len(record.Map(definition)) == 0 {
				unknown = true
			}
		}
		bindings = append(bindings, name)
		definitions = append(definitions, definition)
	}
	differentBinding := len(record.Unique(bindings)) > 1
	differentContent := len(record.Unique(definitions)) > 1 || unknown
	if !differentBinding && !differentContent {
		return
	}
	evidence := r.observations(rows, func(row vxlan.Record) any {
		name := record.Map(record.Map(row["svi"])["acl_bindings"])[direction]
		var entries any
		var policy vxlan.Record
		if name != nil {
			entries = record.Map(record.Map(row["config"])["acls"])[record.String(name)]
			policy, _ = record.Map(policies[record.String(row["host"])])[record.String(name)].(map[string]any)
		}
		var groups, digest any
		if policy != nil {
			groups = policy["address_groups"]
			var err error
			digest, err = vxlan.Fingerprint(policy)
			if err != nil {
				panic(err)
			}
		}
		return vxlan.Record{"acl": name, "defined": entries != nil, "entries": entries, "policy_verified": policy != nil, "address_groups": groups, "digest": digest}
	})
	code := "fabric_acl_content"
	if differentBinding {
		code = "fabric_acl_binding"
	}
	r.finding(fabric, vni, code, direction+" 方向 ACL 挂载/有序规则不一致", evidence)
	undefined, unresolved := []vxlan.Record{}, []vxlan.Record{}
	for _, row := range evidence {
		value := record.Map(row["value"])
		if value["acl"] != nil && value["defined"] == false {
			undefined = append(undefined, row)
		}
		if value["defined"] == true && value["policy_verified"] == false {
			unresolved = append(unresolved, row)
		}
	}
	if len(undefined) > 0 {
		r.finding(fabric, vni, "fabric_acl_undefined", direction+" 方向已挂载 ACL，但本机没有对应定义", undefined)
	}
	if len(unresolved) > 0 {
		r.finding(fabric, vni, "fabric_acl_dependency", direction+" 方向 ACL 依赖对象缺失、为空或尚未解析，不能证明策略一致", unresolved)
	}
	names := []any{}
	for _, n := range bindings {
		if n != nil {
			names = append(names, n)
		}
	}
	names = record.Unique(names)
	var name any
	if len(names) > 0 {
		name = names[0]
	}
	originals, unique := []any{}, []any{}
	for _, row := range rows {
		entries := record.Map(record.Map(row["config"])["acls"])[record.String(name)]
		if entries != nil {
			originals = append(originals, entries)
			unique = append(unique, record.Map(policies[record.String(row["host"])])[record.String(name)])
		}
	}
	unique = record.Unique(unique)
	var original any
	var policy vxlan.Record
	if len(originals) > 0 {
		original = originals[0]
	}
	if len(unique) == 1 {
		policy, _ = unique[0].(map[string]any)
	}
	for _, row := range rows {
		host := record.String(row["host"])
		currentName := record.Map(record.Map(row["svi"])["acl_bindings"])[direction]
		var currentEntries any
		if len(names) == 1 {
			currentEntries = record.Map(record.Map(row["config"])["acls"])[record.String(name)]
		}
		currentPolicy := record.Map(policies[host])[record.String(name)]
		if len(names) == 1 && len(unique) == 1 && policy != nil && record.Equal(currentName, name) && record.Equal(currentPolicy, policy) {
			continue
		}
		item := r.recommendation(fabric, vni, code, "统一 "+direction+" 方向访问控制", evidence)
		change := vxlan.Record{"kind": "svi_acl", "vlan": record.Number(row["vlan"]), "vni": vni, "direction": direction, "acl": name, "entries": original, "create_acl": currentEntries == nil, "previous_binding": currentName}
		if len(unique) == 1 && policy != nil {
			change["address_groups"] = policy["address_groups"]
		}
		contexts := []any{}
		for _, entry := range rows {
			contexts = append(contexts, record.Map(entry["svi"])["vrf"])
		}
		contextMatches := len(record.Unique(contexts)) == 1
		plan := changepkg.CandidateChangePlan(change, record.Map(row["config"]))
		if len(names) == 1 && len(unique) == 1 && policy != nil && contextMatches && plan != nil {
			domainAppend(item, "prerequisites", "依据是本业务已挂载且有序内容一致的 ACL；即使挂载节点较少，也不以无 ACL 的多数节点为删除依据。确认此业务应统一受该 ACL 保护。")
			r.propose(item, plan, blocked)
		} else {
			domainAppend(item, "blockers", "ACL 名称、有序规则、地址组成员、VRF 或当前绑定不能证明一致；需选择权威规则及完整依赖，不自动覆盖或撤销访问控制。")
			shared := []vxlan.Record{}
			if change["create_acl"] == true {
				for _, binding := range configuration.ACLBindings(record.Map(row["config"]), record.String(name)) {
					if binding["interface"] != "Vlan"+record.String(row["vlan"]) || binding["direction"] != direction {
						shared = append(shared, binding)
					}
				}
			}
			if len(shared) > 0 {
				refs := []string{}
				for _, binding := range shared {
					refs = append(refs, record.String(binding["interface"])+" "+record.String(binding["direction"]))
				}
				domainAppend(item, "blockers", "创建 "+record.String(name)+" 还会激活既有引用："+strings.Join(refs, "、")+"。需合并所有受影响接口核对策略和回退，禁止作为单个 SVI 的补齐执行。")
			}
		}
		r.addItem(host, item)
	}
}
func (r *fabricReview) reviewACLCatalog(fabric string, configs, policies vxlan.Record, hosts []string) {
	names := []string{}
	for _, host := range hosts {
		names = append(names, record.Keys(record.Map(record.Map(configs[host])["acls"]))...)
	}
	for _, name := range record.UniqueSorted(names) {
		rows := []vxlan.Record{}
		semantics, identities := []any{}, []any{}
		unknown := []vxlan.Record{}
		for _, host := range hosts {
			entries := record.Map(record.Map(configs[host])["acls"])[name]
			if entries == nil {
				continue
			}
			policy, _ := record.Map(policies[host])[name].(map[string]any)
			var rules any = configuration.ACLRules(entries)
			if policy != nil {
				rules = policy["rules"]
			}
			row := vxlan.Record{"host": host, "entries": entries, "semantics": rules, "policy": policy}
			rows = append(rows, row)
			semantics = append(semantics, rules)
			identities = append(identities, policy)
			if policy == nil {
				unknown = append(unknown, row)
			}
		}
		if len(record.Unique(semantics)) > 1 || len(record.Unique(identities)) > 1 {
			r.finding(fabric, nil, "fabric_acl_content", "同名 ACL "+name+" 的有序规则或依赖对象不同（包括尚未挂载的定义）", rows)
		}
		if len(unknown) > 0 {
			r.finding(fabric, nil, "fabric_acl_dependency", "ACL "+name+" 的依赖对象未验证，不能证明策略一致（包括尚未挂载的定义）", unknown)
		}
	}
}
func (r *fabricReview) reviewAddressGroups(fabric string, configs vxlan.Record, hosts []string) {
	references := map[string][]string{}
	names := []string{}
	for _, host := range hosts {
		for _, entries := range record.Map(record.Map(configs[host])["acls"]) {
			for _, entry := range record.Rows(entries) {
				for _, name := range configuration.AddressGroupReferences(record.String(entry["expression"])) {
					references[host] = append(references[host], name)
					names = append(names, name)
				}
			}
		}
	}
	for _, name := range record.UniqueSorted(names) {
		rows := []vxlan.Record{}
		values := []any{}
		for _, host := range hosts {
			if record.Contains(references[host], name) {
				value := record.Map(record.Map(configs[host])["address_groups"])[name]
				rows = append(rows, vxlan.Record{"host": host, "value": value})
				values = append(values, value)
			}
		}
		if len(record.Unique(values)) > 1 {
			r.finding(fabric, nil, "fabric_address_group", "ACL 地址组 "+name+" 成员不同或缺失；仅比较引用此对象的业务，不自动复制", rows)
		}
	}
}

type fabricSubnet struct {
	vrf      any
	prefix   netip.Prefix
	rows     []vxlan.Record
	position int
}

func (r *fabricReview) reviewSubnets(fabric string, configs vxlan.Record, hosts []string) {
	networks := []*fabricSubnet{}
	byKey := map[string]*fabricSubnet{}
	groups := []string{}
	for _, host := range hosts {
		config := record.Map(configs[host])
		interfaces := record.Map(config["interfaces"])
		for _, name := range record.NaturalKeys(interfaces) {
			svi := record.Map(interfaces[name])
			if textparse.Match(`Vlan\d+`, name) == nil || !record.Truthy(svi["anycast"]) {
				continue
			}
			vni := record.Map(config["vlan_vnis"])[strings.TrimPrefix(name, "Vlan")]
			if vni == nil {
				continue
			}
			for _, address := range record.StringSlice(svi["addresses"]) {
				prefix, e := configuration.Network(address)
				if e != nil {
					panic(e)
				}
				group := string(record.JSON([]any{svi["vrf"], prefix.Addr().Is4()}))
				if !record.Contains(groups, group) {
					groups = append(groups, group)
				}
				key := group + prefix.String()
				network := byKey[key]
				if network == nil {
					network = &fabricSubnet{vrf: svi["vrf"], prefix: prefix, rows: []vxlan.Record{}, position: len(networks)}
					byKey[key] = network
					networks = append(networks, network)
				}
				network.rows = append(network.rows, vxlan.Record{"host": host, "interface": name, "vni": vni, "address": address})
			}
		}
	}
	for _, group := range groups {
		selected := []*fabricSubnet{}
		for _, network := range networks {
			if group == string(record.JSON([]any{network.vrf, network.prefix.Addr().Is4()})) {
				selected = append(selected, network)
			}
		}
		sort.SliceStable(selected, func(i, j int) bool { return selected[i].prefix.Addr().Less(selected[j].prefix.Addr()) })
		active := []*fabricSubnet{}
		for _, network := range selected {
			kept := []*fabricSubnet{}
			for _, other := range active {
				if configuration.Overlap(other.prefix, network.prefix) {
					kept = append(kept, other)
				}
			}
			active = kept
			conflicts := [][]vxlan.Record{}
			for _, other := range active {
				combined := append(append([]vxlan.Record{}, other.rows...), network.rows...)
				vnis := []any{}
				for _, row := range combined {
					vnis = append(vnis, row["vni"])
				}
				if len(record.Unique(vnis)) > 1 {
					conflicts = append(conflicts, combined)
				}
			}
			vnis := []any{}
			for _, row := range network.rows {
				vnis = append(vnis, row["vni"])
			}
			if len(record.Unique(vnis)) > 1 {
				conflicts = append(conflicts, network.rows)
			}
			for _, evidence := range conflicts {
				r.finding(fabric, nil, "fabric_subnet_vni_conflict", fmt.Sprintf("VRF %s 的网段在不同 VNI 上重叠，需核对迁移或隔离设计", record.String(network.vrf)), evidence)
			}
			active = append(active, network)
		}
	}
}
