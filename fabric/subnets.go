package fabric

import (
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// ErrInvalidAddress reports an SVI address that is not a valid prefix, which
// makes overlap with it unknowable rather than absent.
var ErrInvalidAddress = errors.New("fabric: invalid interface address")

// SubnetConflict is one SVI whose addresses overlap a queried network.
type SubnetConflict struct {
	Interface string   `json:"interface"`
	VNI       *int     `json:"vni"`
	Addresses []string `json:"value"`
}

var sviPattern = regexp.MustCompile(`^Vlan(\d+)$`)

func networkOf(address string) (netip.Prefix, error) {
	if !strings.Contains(address, "/") {
		a, err := netip.ParseAddr(address)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(address)
	return p.Masked(), err
}

type subnetEntry struct {
	iface    string
	vni      *int
	address  string
	prefix   netip.Prefix
	position int
}

type subnetGroup struct {
	ordered  []*subnetEntry                        // by network address
	byLength map[int]map[netip.Addr][]*subnetEntry // prefix length -> network -> entries
}

// SubnetIndex answers repeated overlap queries over one configuration's SVI
// addresses without rescanning them: entries are grouped by VRF and family,
// ordered by network address and indexed by prefix length.
type SubnetIndex struct {
	groups  map[string]map[bool]*subnetGroup
	invalid map[string][]*subnetEntry
}

// NewSubnetIndex indexes the SVI addresses of c.
func NewSubnetIndex(c *Configuration) *SubnetIndex {
	idx := &SubnetIndex{groups: map[string]map[bool]*subnetGroup{}, invalid: map[string][]*subnetEntry{}}
	type svi struct {
		name string
		id   int
	}
	var svis []svi
	for name := range c.Interfaces {
		if m := sviPattern.FindStringSubmatch(name); m != nil {
			id, _ := strconv.Atoi(m[1])
			svis = append(svis, svi{name, id})
		}
	}
	slices.SortFunc(svis, func(a, b svi) int { return a.id - b.id })
	position := 0
	for _, s := range svis {
		iface := c.Interfaces[s.name]
		mapped := c.VLANVNIs[strconv.Itoa(s.id)]
		for _, a := range iface.Addresses {
			e := &subnetEntry{iface: s.name, vni: mapped, address: a, position: position}
			position++
			p, err := networkOf(a)
			if err != nil {
				idx.invalid[iface.VRF] = append(idx.invalid[iface.VRF], e)
				continue
			}
			e.prefix = p
			families := idx.groups[iface.VRF]
			if families == nil {
				families = map[bool]*subnetGroup{}
				idx.groups[iface.VRF] = families
			}
			g := families[p.Addr().Is4()]
			if g == nil {
				g = &subnetGroup{byLength: map[int]map[netip.Addr][]*subnetEntry{}}
				families[p.Addr().Is4()] = g
			}
			g.ordered = append(g.ordered, e)
			if g.byLength[p.Bits()] == nil {
				g.byLength[p.Bits()] = map[netip.Addr][]*subnetEntry{}
			}
			g.byLength[p.Bits()][p.Addr()] = append(g.byLength[p.Bits()][p.Addr()], e)
		}
	}
	for _, families := range idx.groups {
		for _, g := range families {
			slices.SortStableFunc(g.ordered, func(a, b *subnetEntry) int { return a.prefix.Addr().Compare(b.prefix.Addr()) })
		}
	}
	return idx
}

// Conflicts lists SVIs of the VRF whose addresses overlap address and that
// are not mapped to vni, excluding the interface except, in configuration
// order. An unparseable relevant address is an error: it could hide a
// conflict.
func (idx *SubnetIndex) Conflicts(address, vrf string, vni *int, except string) ([]SubnetConflict, error) {
	network, err := networkOf(address)
	if err != nil {
		return nil, err
	}
	relevant := func(e *subnetEntry) bool {
		same := (e.vni == nil) == (vni == nil) && (e.vni == nil || *e.vni == *vni)
		return !same && e.iface != except
	}
	for _, e := range idx.invalid[vrf] {
		if relevant(e) {
			return nil, ErrInvalidAddress
		}
	}
	g := idx.groups[vrf][network.Addr().Is4()]
	if g == nil {
		return nil, nil
	}
	first := network.Addr()
	// Entries inside the queried network form one contiguous run.
	left := sort.Search(len(g.ordered), func(i int) bool { return g.ordered[i].prefix.Addr().Compare(first) >= 0 })
	right := sort.Search(len(g.ordered), func(i int) bool {
		a := g.ordered[i].prefix.Addr()
		return a.Compare(first) >= 0 && !network.Contains(a)
	})
	hits := slices.Clone(g.ordered[left:right])
	// Supernets containing the queried network, one lookup per shorter length.
	for bits, networks := range g.byLength {
		if bits >= network.Bits() {
			continue
		}
		if ancestor := netip.PrefixFrom(first, bits).Masked().Addr(); ancestor != first {
			hits = append(hits, networks[ancestor]...)
		}
	}
	slices.SortFunc(hits, func(a, b *subnetEntry) int { return a.position - b.position })
	var out []SubnetConflict
	at := map[string]int{}
	for _, e := range hits {
		if !relevant(e) {
			continue
		}
		i, ok := at[e.iface]
		if !ok {
			i = len(out)
			at[e.iface] = i
			out = append(out, SubnetConflict{Interface: e.iface, VNI: e.vni})
		}
		out[i].Addresses = append(out[i].Addresses, e.address)
	}
	return out, nil
}

// SubnetConflicts is a one-off Conflicts query; repeated queries should share
// a NewSubnetIndex.
func (c *Configuration) SubnetConflicts(address, vrf string, vni *int, except string) ([]SubnetConflict, error) {
	return NewSubnetIndex(c).Conflicts(address, vrf, vni, except)
}
