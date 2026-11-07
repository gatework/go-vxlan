package vxlan

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Fingerprint is the Ruby-compatible canonical JSON SHA-256. Maps are sorted;
// arrays retain order and Unicode/HTML characters are not escaped.
func Fingerprint(value any) string { return fmt.Sprintf("%x", sha256.Sum256(domainJSON(value))) }
func domainJSON(value any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(value) != nil {
		return nil
	}
	encoded := bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
	// Ruby emits the Unicode line/paragraph separators literally. Preserve
	// escaped backslashes, which can precede the text "u2028" in user strings.
	out := make([]byte, 0, len(encoded))
	for i := 0; i < len(encoded); {
		if encoded[i] != '\\' {
			out = append(out, encoded[i])
			i++
			continue
		}
		start := i
		for i < len(encoded) && encoded[i] == '\\' {
			i++
		}
		count := i - start
		if count%2 == 1 && i+5 <= len(encoded) && (string(encoded[i:i+5]) == "u2028" || string(encoded[i:i+5]) == "u2029") {
			out = append(out, encoded[start:i-1]...)
			if encoded[i+4] == '8' {
				out = append(out, []byte("\u2028")...)
			} else {
				out = append(out, []byte("\u2029")...)
			}
			i += 5
		} else {
			out = append(out, encoded[start:i]...)
		}
	}
	return out
}
func domainCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := Record{}
		for k, v := range x {
			m[k] = domainCopy(v)
		}
		return m
	case []Record:
		r := make([]Record, len(x))
		for i, v := range x {
			r[i] = domainCopy(v).(Record)
		}
		return r
	case []any:
		r := make([]any, len(x))
		for i, v := range x {
			r[i] = domainCopy(v)
		}
		return r
	case []string:
		return append([]string{}, x...)
	default:
		return x
	}
}
func domainEq(a, b any) bool {
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case int:
		switch y := b.(type) {
		case int:
			return x == y
		case int64:
			return int64(x) == y
		case float64:
			return float64(x) == y
		}
		return false
	case int64:
		switch y := b.(type) {
		case int:
			return x == int64(y)
		case int64:
			return x == y
		case float64:
			return float64(x) == y
		}
		return false
	case float64:
		switch y := b.(type) {
		case int:
			return x == float64(y)
		case int64:
			return x == float64(y)
		case float64:
			return x == y
		}
		return false
	}
	return bytes.Equal(domainJSON(a), domainJSON(b))
}
func domainMerge(a, b Record) Record {
	m := Record{}
	for k, v := range a {
		m[k] = v
	}
	for k, v := range b {
		m[k] = v
	}
	return m
}
func domainSlice(a Record, keys ...string) Record {
	m := Record{}
	for _, k := range keys {
		if v, ok := a[k]; ok {
			m[k] = v
		}
	}
	return m
}
func domainCompact(a Record) Record {
	m := Record{}
	for k, v := range a {
		if v != nil {
			m[k] = v
		}
	}
	return m
}
func domainString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func domainTruthy(v any) bool { return v != nil && v != false }
func domainUniq(rows []any) []any {
	out := []any{}
	seen := map[string]bool{}
	for _, r := range rows {
		k := string(domainJSON(r))
		if !seen[k] {
			out = append(out, r)
			seen[k] = true
		}
	}
	return out
}
func domainHas(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
func domainInteger(v any, min, max int) bool {
	switch n := v.(type) {
	case int:
		return n >= min && n <= max
	case int64:
		return n >= int64(min) && n <= int64(max)
	case float64:
		return n >= float64(min) && n <= float64(max) && math.Trunc(n) == n
	default:
		return false
	}
}
func domainRows(v any) ([]Record, bool) {
	switch rows := v.(type) {
	case []Record:
		return rows, true
	case []any:
		r := []Record{}
		for _, x := range rows {
			m, ok := x.(map[string]any)
			if !ok {
				return nil, false
			}
			r = append(r, m)
		}
		return r, true
	default:
		return nil, false
	}
}
func domainStrings(v any) ([]string, bool) {
	switch s := v.(type) {
	case []string:
		return s, true
	case []any:
		r := []string{}
		for _, x := range s {
			v, ok := x.(string)
			if !ok {
				return nil, false
			}
			r = append(r, v)
		}
		return r, true
	default:
		return nil, false
	}
}
func domainAt(v Record, keys ...string) any {
	var a any = v
	for _, k := range keys {
		a = cfgMap(a)[k]
	}
	return a
}
func domainNetwork(address string) (netip.Prefix, error) {
	if !strings.Contains(address, "/") {
		a, e := netip.ParseAddr(address)
		if e != nil {
			return netip.Prefix{}, e
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, e := netip.ParsePrefix(address)
	return p.Masked(), e
}
func domainOverlap(a, b netip.Prefix) bool {
	return a.Addr().Is4() == b.Addr().Is4() && (a.Contains(b.Addr()) || b.Contains(a.Addr()))
}

// CompleteConfig returns the single complete configuration evidence record.
func CompleteConfig(document Record) Record {
	o := cfgMap(domainAt(document, "snapshot", "dimensions", "configuration"))
	if o["status"] != "complete" {
		return nil
	}
	r, ok := domainRows(o["records"])
	if !ok || len(r) != 1 || r[0]["review_status"] != "complete" {
		return nil
	}
	return r[0]
}

// ACLRules projects ordered forwarding semantics, preserving unknown as nil.
func ACLRules(entries any) []Record {
	rows, ok := domainRows(entries)
	if !ok {
		return nil
	}
	seen := map[int]bool{}
	for _, r := range rows {
		n := cfgNumber(r["sequence"])
		_, str := r["expression"].(string)
		if !domainInteger(r["sequence"], 1, 4294967295) || !domainHas([]string{"permit", "deny", "remark"}, domainString(r["action"])) || !str || seen[n] {
			return nil
		}
		seen[n] = true
	}
	ordered := append([]Record{}, rows...)
	sort.SliceStable(ordered, func(i, j int) bool { return cfgNumber(ordered[i]["sequence"]) < cfgNumber(ordered[j]["sequence"]) })
	out := []Record{}
	for _, r := range ordered {
		if r["action"] != "remark" {
			out = append(out, domainSlice(r, "action", "expression"))
		}
	}
	return out
}

var domainGroupRE = regexp.MustCompile(`\baddrgroup\s+(\S+)`)
var domainUnknownACL = regexp.MustCompile(`\b(?:portgroup|object-group|time-range)\b`)

// ResolveACLPolicy returns ordered rules and the validated dependency snapshot.
func ResolveACLPolicy(config Record, entries any) Record {
	rules := ACLRules(entries)
	if rules == nil {
		return nil
	}
	names := []string{}
	for _, r := range rules {
		expr := r["expression"].(string)
		if domainUnknownACL.MatchString(expr) {
			return nil
		}
		for _, m := range domainGroupRE.FindAllStringSubmatch(expr, -1) {
			names = append(names, m[1])
		}
	}
	groups := Record{}
	for _, name := range cfgUniqueSorted(names) {
		members, ok := domainStrings(cfgMap(config["address_groups"])[name])
		if !ok || len(members) == 0 {
			return nil
		}
		for _, v := range members {
			p, e := domainNetwork(v)
			if e != nil || !strings.Contains(v, "/") || !p.Addr().Is4() {
				return nil
			}
		}
		groups[name] = cfgUniqueSorted(members)
	}
	return domainCopy(Record{"rules": rules, "address_groups": groups}).(Record)
}

// ACLBindings enumerates all interfaces/directions affected by an ACL definition.
func ACLBindings(config Record, name string) []Record {
	out := []Record{}
	interfaces := cfgMap(config["interfaces"])
	for _, n := range cfgKeys(interfaces) {
		b := cfgMap(cfgMap(interfaces[n])["acl_bindings"])
		for _, direction := range cfgKeys(b) {
			if b[direction] == name {
				out = append(out, Record{"interface": n, "direction": direction})
			}
		}
	}
	return out
}

type subnetEntry struct {
	name     string
	vni      any
	address  string
	vrf      any
	prefix   netip.Prefix
	err      error
	position int
}
type subnetGroup struct {
	ordered  []*subnetEntry
	prefixes map[int]map[netip.Addr][]*subnetEntry
}

// SubnetIndex owns SVI evidence, grouping VRFs/families and indexing prefix
// ancestors so repeated gateway queries do not allocate a full table scan.
type SubnetIndex struct {
	entries []subnetEntry
	groups  map[string]map[bool]*subnetGroup
	invalid map[string][]*subnetEntry
}

func NewSubnetIndex(config Record) *SubnetIndex {
	idx := &SubnetIndex{groups: map[string]map[bool]*subnetGroup{}, invalid: map[string][]*subnetEntry{}}
	interfaces := cfgMap(config["interfaces"])
	for _, name := range domainNaturalKeys(interfaces) {
		if cfgMatch(`Vlan\d+`, name) == nil {
			continue
		}
		svi := cfgMap(interfaces[name])
		for _, address := range cfgStrings(svi["addresses"]) {
			p, e := domainNetwork(address)
			idx.entries = append(idx.entries, subnetEntry{name: name, vni: cfgMap(config["vlan_vnis"])[strings.TrimPrefix(name, "Vlan")], address: address, vrf: svi["vrf"], prefix: p, err: e, position: len(idx.entries)})
		}
	}
	for i := range idx.entries {
		entry := &idx.entries[i]
		key := string(domainJSON(entry.vrf))
		if entry.err != nil {
			idx.invalid[key] = append(idx.invalid[key], entry)
			continue
		}
		families := idx.groups[key]
		if families == nil {
			families = map[bool]*subnetGroup{}
			idx.groups[key] = families
		}
		family := entry.prefix.Addr().Is4()
		group := families[family]
		if group == nil {
			group = &subnetGroup{prefixes: map[int]map[netip.Addr][]*subnetEntry{}}
			families[family] = group
		}
		group.ordered = append(group.ordered, entry)
		prefix := entry.prefix.Bits()
		subnets := group.prefixes[prefix]
		if subnets == nil {
			subnets = map[netip.Addr][]*subnetEntry{}
			group.prefixes[prefix] = subnets
		}
		addr := entry.prefix.Addr()
		subnets[addr] = append(subnets[addr], entry)
	}
	for _, families := range idx.groups {
		for _, group := range families {
			sort.SliceStable(group.ordered, func(i, j int) bool { return group.ordered[i].prefix.Addr().Less(group.ordered[j].prefix.Addr()) })
		}
	}
	return idx
}
func (idx *SubnetIndex) Conflicts(address string, vrf, vni any, exceptInterface string) ([]Record, error) {
	network, err := domainNetwork(address)
	if err != nil {
		return nil, err
	}
	key := string(domainJSON(vrf))
	relevant := func(e *subnetEntry) bool { return !domainEq(e.vni, vni) && e.name != exceptInterface }
	for _, entry := range idx.invalid[key] {
		if relevant(entry) {
			return nil, entry.err
		}
	}
	group := idx.groups[key][network.Addr().Is4()]
	out := []Record{}
	if group == nil {
		return out, nil
	}
	first := network.Addr()
	left := sort.Search(len(group.ordered), func(i int) bool { return !group.ordered[i].prefix.Addr().Less(first) })
	right := sort.Search(len(group.ordered), func(i int) bool { a := group.ordered[i].prefix.Addr(); return !a.Less(first) && !network.Contains(a) })
	entries := append([]*subnetEntry{}, group.ordered[left:right]...)
	for prefix, subnets := range group.prefixes {
		if prefix >= network.Bits() {
			continue
		}
		ancestor := netip.PrefixFrom(first, prefix).Masked().Addr()
		if ancestor != first {
			entries = append(entries, subnets[ancestor]...)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].position < entries[j].position })
	positions := map[string]int{}
	for _, entry := range entries {
		if !relevant(entry) {
			continue
		}
		i, ok := positions[entry.name]
		if !ok {
			i = len(out)
			positions[entry.name] = i
			out = append(out, Record{"interface": entry.name, "vni": entry.vni, "value": []string{}})
		}
		out[i]["value"] = append(cfgStrings(out[i]["value"]), entry.address)
	}
	return out, nil
}

// BGPNeighbors resolves supported peer-template inheritance without session inference.
func BGPNeighbors(bgp Record) []Record {
	out := []Record{}
	templates := cfgMap(bgp["templates"])
	scopes := domainMerge(Record{"default": bgp}, cfgMap(bgp["vrfs"]))
	for _, vrf := range cfgKeys(scopes) {
		neighbors := cfgMap(cfgMap(scopes[vrf])["neighbors"])
		for _, peer := range cfgKeys(neighbors) {
			n := cfgMap(neighbors[peer])
			name := domainString(n["inherit_peer"])
			t := cfgMap(templates[name])
			if name != "" && templates[name] == nil || t["inherit_peer"] != nil {
				continue
			}
			families := domainMerge(cfgMap(t["address_families"]), cfgMap(n["address_families"]))
			for family, nv := range cfgMap(n["address_families"]) {
				if tv, ok := cfgMap(t["address_families"])[family]; ok {
					m := domainMerge(cfgMap(tv), domainCompact(cfgMap(nv)))
					m["route_maps"] = domainMerge(cfgMap(cfgMap(tv)["route_maps"]), cfgMap(cfgMap(nv)["route_maps"]))
					families[family] = m
				}
			}
			v := domainMerge(t, domainCompact(n))
			v["address_families"] = families
			out = append(out, Record{"vrf": vrf, "peer": peer, "settings": v})
		}
	}
	return out
}

// PrefixListReferences associates policy selectors with all supported routing consumers.
func PrefixListReferences(config Record, family string) (Record, error) {
	if family != "ipv4" && family != "ipv6" {
		return nil, fmt.Errorf("Unsupported address family")
	}
	consumers := Record{}
	add := func(name any, context Record) {
		n := domainString(name)
		rows := cfgRows(consumers[n])
		for _, row := range rows {
			if domainEq(row, context) {
				return
			}
		}
		consumers[n] = append(rows, context)
	}
	redistribute := func(settings, context Record) {
		for _, entry := range cfgRows(settings["redistribute"]) {
			if entry["route_map"] != nil {
				add(entry["route_map"], domainCompact(domainMerge(context, Record{"usage": "redistribute", "source_protocol": entry["protocol"], "source_process": entry["process"]})))
			}
		}
	}
	bgp := cfgMap(config["bgp"])
	scopes := domainMerge(Record{"default": bgp}, cfgMap(bgp["vrfs"]))
	for _, vrf := range cfgKeys(scopes) {
		afs := cfgMap(cfgMap(scopes[vrf])["address_families"])
		for _, af := range cfgKeys(afs) {
			v := cfgMap(afs[af])
			context := Record{"protocol": "bgp", "process": domainString(bgp["asn"]), "vrf": vrf, "address_family": af}
			redistribute(v, context)
			for _, n := range cfgRows(v["networks"]) {
				if n["route_map"] != nil {
					add(n["route_map"], domainMerge(context, Record{"usage": "network", "prefix": n["prefix"]}))
				}
			}
			retain := domainString(v["retain_route_target"])
			if strings.HasPrefix(retain, "route-map ") {
				add(strings.TrimPrefix(retain, "route-map "), domainMerge(context, Record{"usage": "retain_route_target"}))
			}
		}
	}
	for _, neighbor := range BGPNeighbors(bgp) {
		afs := cfgMap(cfgMap(neighbor["settings"])["address_families"])
		for _, af := range cfgKeys(afs) {
			maps := cfgMap(cfgMap(afs[af])["route_maps"])
			for _, direction := range cfgKeys(maps) {
				add(maps[direction], Record{"protocol": "bgp", "process": domainString(bgp["asn"]), "vrf": neighbor["vrf"], "address_family": af, "usage": "neighbor_route_map", "peer": neighbor["peer"], "direction": direction})
			}
		}
	}
	ospf := cfgMap(config["ospf"])
	for _, process := range cfgKeys(ospf) {
		settings := cfgMap(ospf[process])
		scopes := domainMerge(Record{"default": settings}, cfgMap(settings["vrfs"]))
		for _, vrf := range cfgKeys(scopes) {
			redistribute(cfgMap(scopes[vrf]), Record{"protocol": "ospf", "process": process, "vrf": vrf})
		}
	}
	vrfs := cfgMap(config["vrfs"])
	for _, vrf := range cfgKeys(vrfs) {
		for _, entry := range cfgRows(cfgMap(vrfs[vrf])["exports"]) {
			add(entry["route_map"], Record{"protocol": "vrf", "vrf": vrf, "address_family": entry["address_family"], "usage": "export", "target_vrf": entry["vrf"]})
		}
	}
	out := Record{}
	maps := cfgMap(config["route_maps"])
	for _, name := range cfgKeys(maps) {
		entries := append([]Record{}, cfgRows(maps[name])...)
		sort.SliceStable(entries, func(i, j int) bool { return cfgNumber(entries[i]["sequence"]) < cfgNumber(entries[j]["sequence"]) })
		for _, entry := range entries {
			matches, ok := entry["prefix_list_matches"]
			if !ok {
				matches = []Record{{"address_family": "ipv4", "selector": "address", "names": entry["prefix_lists"]}}
			}
			for _, match := range cfgRows(matches) {
				if match["address_family"] != family {
					continue
				}
				reference := Record{"type": "route_map", "name": name, "sequence": entry["sequence"], "action": entry["action"], "bindings": cfgRows(consumers[name])}
				if match["selector"] != "address" {
					reference["selector"] = match["selector"]
				}
				for _, list := range cfgStrings(match["names"]) {
					rows := cfgRows(out[list])
					duplicate := false
					for _, r := range rows {
						if domainEq(r, reference) {
							duplicate = true
						}
					}
					if !duplicate {
						out[list] = append(rows, reference)
					}
				}
			}
		}
	}
	return out, nil
}
