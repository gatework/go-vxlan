package nxos

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/internal/textparse"
)

func (s *cfgState) policy(d vxlan.Record, collection, name string, seq int, b *cfgBlock, fn func() vxlan.Record) {
	dest := record.Map(d[collection])
	rows := record.Rows(dest[name])
	key := fmt.Sprintf("policy:%s:%s:%d", collection, name, seq)
	if s.seen[key] {
		s.mark(s.sources[key], LineInvalid)
		out := []vxlan.Record{}
		for _, r := range rows {
			if r["sequence"] != seq {
				out = append(out, r)
			}
		}
		dest[name] = out
		code := "invalid_configuration_value"
		if collection == "route_maps" {
			code = "duplicate_route_map_entry"
		}
		s.issue(b, code)
		return
	}
	s.seen[key] = true
	s.sources[key] = b
	dest[name] = rows
	entry := fn()
	s.policies[fmt.Sprintf("%p", entry)] = b
	dest[name] = append(rows, entry)
}
func (s *cfgState) prefixList(b *cfgBlock, d vxlan.Record) {
	if textparse.Match(`(?:ip|ipv6) prefix-list \S+ description .+`, b.text) != nil {
		s.ignore(b)
		return
	}
	m := textparse.Match(`(ip|ipv6) prefix-list (\S+) seq (\d+) (permit|deny) (\S+)(?: ge (\d+))?(?: le (\d+))?`, b.text)
	if m == nil {
		panic("invalid_configuration_value")
	}
	family, collection, width := "ipv4", "prefix_lists", 32
	if m[1] == "ipv6" {
		family, collection, width = "ipv6", "ipv6_prefix_lists", 128
	}
	seq := cfgInt(m[3], 1, 4294967295)
	s.policy(d, collection, m[2], seq, b, func() vxlan.Record {
		prefix := cfgPrefix(m[5], family, false)
		parts := strings.Split(prefix, "/")
		length, _ := strconv.Atoi(parts[1])
		var ge, le any
		minimum := length
		if m[6] != "" {
			n := cfgInt(m[6], length, width)
			ge = n
			minimum = n
		}
		if m[7] != "" {
			le = cfgInt(m[7], minimum, width)
		}
		return vxlan.Record{"sequence": seq, "action": m[4], "prefix": prefix, "ge": ge, "le": le}
	})
	s.leaf(b)
}
func (s *cfgState) routeMap(b *cfgBlock) vxlan.Record {
	v := vxlan.Record{"prefix_lists": []string{}, "additional_matches": []string{}, "sets": []string{}}
	for _, c := range b.children {
		s.enter(c)
		t := c.text
		if m := textparse.Match(`match (ip|ipv6) (address|next-hop|route-source) prefix-list (.+)`, t); m != nil {
			family := "ipv4"
			if m[1] == "ipv6" {
				family = "ipv6"
			}
			names := strings.Fields(m[3])
			if family == "ipv4" && m[2] == "address" {
				v["prefix_lists"] = append(record.StringSlice(v["prefix_lists"]), names...)
			}
			v["prefix_list_matches"] = append(record.Rows(v["prefix_list_matches"]), vxlan.Record{"address_family": family, "selector": m[2], "names": names})
		} else if strings.HasPrefix(t, "match ") {
			v["additional_matches"] = append(record.StringSlice(v["additional_matches"]), t)
		} else if strings.HasPrefix(t, "set ") {
			v["sets"] = append(record.StringSlice(v["sets"]), t)
		} else if strings.HasPrefix(t, "description ") {
			s.ignore(c)
			continue
		} else {
			s.issue(c, "unsupported_configuration")
			continue
		}
		s.leaf(c)
	}
	return v
}
func (s *cfgState) addressGroup(b *cfgBlock) []string {
	seq := map[int]bool{}
	members := map[string]bool{}
	for _, c := range b.children {
		s.enter(c)
		m := textparse.Match(`(\d+) (host )?(\S+)`, c.text)
		if m == nil {
			s.issue(c, "unsupported_configuration")
			continue
		}
		n := cfgInt(m[1], 1, 4294967295)
		if seq[n] {
			panic("invalid_configuration_value")
		}
		seq[n] = true
		v := m[3]
		if m[2] != "" {
			v = cfgIP(v) + "/32"
		}
		members[cfgPrefix(v, "ipv4", false)] = true
		s.leaf(c)
	}
	r := []string{}
	for k := range members {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}
