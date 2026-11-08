package configuration

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/internal/textparse"
)

func Network(address string) (netip.Prefix, error) {
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

func Overlap(a, b netip.Prefix) bool {
	return a.Addr().Is4() == b.Addr().Is4() && (a.Contains(b.Addr()) || b.Contains(a.Addr()))
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
	err     error
	entries []subnetEntry
	groups  map[string]map[bool]*subnetGroup
	invalid map[string][]*subnetEntry
}

func NewSubnetIndex(config vxlan.Record) *SubnetIndex {
	idx := &SubnetIndex{groups: map[string]map[bool]*subnetGroup{}, invalid: map[string][]*subnetEntry{}}
	_, err := vxlan.ProjectRecord(config)
	if err != nil {
		idx.err = err
		return idx
	}
	config = record.Copy(config).(vxlan.Record)
	interfaces := record.Map(config["interfaces"])
	for _, name := range record.NaturalKeys(interfaces) {
		if textparse.Match(`Vlan\d+`, name) == nil {
			continue
		}
		svi := record.Map(interfaces[name])
		addresses, valid := record.Strings(svi["addresses"])
		if svi["addresses"] != nil && !valid {
			idx.err = record.ErrEvidence
			return idx
		}
		for _, address := range addresses {
			p, e := Network(address)
			idx.entries = append(idx.entries, subnetEntry{name: name, vni: record.Map(config["vlan_vnis"])[strings.TrimPrefix(name, "Vlan")], address: address, vrf: svi["vrf"], prefix: p, err: e, position: len(idx.entries)})
		}
	}
	for i := range idx.entries {
		entry := &idx.entries[i]
		encoded, err := record.CanonicalJSON(entry.vrf)
		if err != nil {
			idx.err = err
			return idx
		}
		key := string(encoded)
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

func (idx *SubnetIndex) Conflicts(address string, vrf, vni any, exceptInterface string) ([]vxlan.Record, error) {
	if idx == nil {
		return nil, record.ErrEvidence
	}
	if idx.err != nil {
		return nil, idx.err
	}
	network, err := Network(address)
	if err != nil {
		return nil, err
	}
	checked, err := vxlan.ProjectRecord(vxlan.Record{"vrf": vrf, "vni": vni})
	if err != nil {
		return nil, err
	}
	encoded, err := record.CanonicalJSON(checked["vrf"])
	if err != nil {
		return nil, err
	}
	key := string(encoded)
	relevant := func(e *subnetEntry) bool { return !record.Equal(e.vni, vni) && e.name != exceptInterface }
	for _, entry := range idx.invalid[key] {
		if relevant(entry) {
			return nil, entry.err
		}
	}
	group := idx.groups[key][network.Addr().Is4()]
	out := []vxlan.Record{}
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
			out = append(out, vxlan.Record{"interface": entry.name, "vni": entry.vni, "value": []string{}})
		}
		out[i]["value"] = append(record.StringSlice(out[i]["value"]), entry.address)
	}
	return out, nil
}
