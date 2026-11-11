package nxos

import (
	"fmt"
	"strings"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/internal/textparse"
)

func (s *cfgState) routing(b *cfgBlock, protocol, context, family, parent string) vxlan.Record {
	v := vxlan.Record{"vrfs": vxlan.Record{}, "neighbors": vxlan.Record{}, "templates": vxlan.Record{}, "address_families": vxlan.Record{}, "redistribute": []vxlan.Record{}}
	neighbors := map[string]string{}
	for _, c := range b.children {
		s.enter(c)
		t := c.text
		if !cfgRoutingLeaf(t, protocol, context, family, parent) {
			s.issue(c, "unsupported_configuration")
			continue
		}
		if m := textparse.Match(`(vrf|template peer|neighbor|address-family) (.+)`, t); m != nil {
			s.routingSection(c, v, protocol, context, m, neighbors)
			continue
		}
		if !s.routingValue(c, v, protocol, context, family, parent) {
			continue
		}
		s.leaf(c)
	}
	return v
}
func cfgRoutingLeaf(t, p, c, f, parent string) bool {
	processAF := c == "address_families" && (parent == "process" || parent == "vrfs")
	switch {
	case textparse.Match(`(?:no )?(?:send-community|next-hop-self|route-reflector-client|advertise-pip|advertise l2vpn evpn)\b.*`, t) != nil:
		return p == "bgp" && c == "address_families"
	case textparse.Match(`(?:remote-as|inherit peer|update-source)\b.*`, t) != nil:
		return p == "bgp" && (c == "neighbors" || c == "templates")
	case textparse.Match(`route-map\b.*`, t) != nil:
		return p == "bgp" && c == "address_families" && (parent == "neighbors" || parent == "templates")
	case textparse.Match(`redistribute\b.*`, t) != nil:
		if p == "ospf" {
			return c == "process" || c == "vrfs"
		}
		return processAF && textparse.Match(`ipv[46] (?:unicast|multicast)`, f) != nil
	case textparse.Match(`retain route-target\b.*`, t) != nil:
		return p == "bgp" && processAF && f == "l2vpn evpn"
	case textparse.Match(`router-id\b.*`, t) != nil:
		return c == "process" || c == "vrfs"
	}
	return true
}

func (s *cfgState) routingSection(c *cfgBlock, v vxlan.Record, protocol, context string, m []string, neighbors map[string]string) {
	kind := map[string]string{"vrf": "vrfs", "template peer": "templates", "neighbor": "neighbors", "address-family": "address_families"}[m[1]]
	name := m[2]
	supported := false
	switch kind {
	case "vrfs":
		supported = context == "process"
	case "templates":
		supported = protocol == "bgp" && context == "process"
	case "neighbors":
		supported = protocol == "bgp" && (context == "process" || context == "vrfs")
	case "address_families":
		supported = protocol == "bgp" && (context == "process" || context == "vrfs" || context == "neighbors" || context == "templates") && textparse.Match(`(?:ipv[46] (?:unicast|multicast)|vpnv[46] unicast|l2vpn evpn)`, name) != nil
	}
	if !supported {
		s.issue(c, "unsupported_configuration")
		return
	}
	if kind == "neighbors" {
		canonical, valid := cfgNeighborIdentity(name)
		if !valid {
			s.issue(c, "invalid_configuration_value")
			return
		}
		if prior := neighbors[canonical]; prior != "" {
			name = prior
		} else {
			neighbors[canonical] = name
		}
	}
	before := s.conflicts
	af := ""
	if kind == "address_families" {
		af = name
	}
	dest := record.Map(v[kind])
	s.store(dest, name, c, "duplicate_identity", sourcePath(s.path, kind, name), func() any { return s.routing(c, protocol, kind, af, context) })
	if protocol == "bgp" && (kind == "neighbors" || kind == "templates") && s.conflicts > before {
		delete(dest, name)
		s.seen[fmt.Sprintf("%p:%s", dest, name)] = true
		s.conflicts++
		s.issue(c, "conflicting_configuration_value")
	}
}

func (s *cfgState) routingValue(c *cfgBlock, v vxlan.Record, protocol, context, family, parent string) bool {
	t := c.text
	if m := textparse.Match(`router-id (\S+)`, t); m != nil {
		ip := cfgIP(m[1])
		cfgPrefix(ip+"/32", "ipv4", true)
		s.assign(v, "router_id", ip, c)
	} else if m = textparse.Match(`remote-as (\S+)`, t); m != nil {
		if m[1] != "internal" && m[1] != "external" {
			cfgInt(m[1], 1, 4294967295)
		}
		s.assign(v, "remote_as", m[1], c)
	} else if m = textparse.Match(`inherit peer (\S+)`, t); m != nil {
		s.assign(v, "inherit_peer", m[1], c)
	} else if m = textparse.Match(`update-source (\S+)`, t); m != nil {
		s.assign(v, "update_source", m[1], c)
	} else if m = textparse.Match(`description (.+)`, t); m != nil {
		s.assign(v, "description", m[1], c)
	} else if m = textparse.Match(`route-map (\S+) (in|out)`, t); m != nil {
		if v["route_maps"] == nil {
			v["route_maps"] = vxlan.Record{}
		}
		s.assign(record.Map(v["route_maps"]), m[2], m[1], c)
	} else if m = textparse.Match(`(no )?next-hop-self( all)?`, t); m != nil {
		s.assign(v, "next_hop_self", m[1] == "", c)
		s.assign(v, "next_hop_self_all", m[1] == "" && m[2] != "", c)
	} else if m = textparse.Match(`(no )?(bfd|route-reflector-client|advertise-pip|advertise l2vpn evpn)`, t); m != nil {
		k := map[string]string{"bfd": "bfd", "route-reflector-client": "route_reflector_client", "advertise-pip": "advertise_pip", "advertise l2vpn evpn": "advertise_l2vpn_evpn"}[m[2]]
		s.assign(v, k, m[1] == "", c)
	} else if m = textparse.Match(`(no )?send-community(?: (extended|both))?`, t); m != nil {
		if m[2] != "extended" {
			s.assign(v, "standard_community", m[1] == "", c)
		}
		if m[2] != "" {
			s.assign(v, "extended_community", m[1] == "", c)
		}
	} else if m = textparse.Match(`network (\S+)(?: route-map (\S+))?`, t); m != nil {
		return s.routingNetwork(c, v, m, protocol, context, family, parent)
	} else if strings.HasPrefix(t, "redistribute ") {
		return s.routingRedistribute(c, v, t)
	} else if m = textparse.Match(`retain route-target (all|route-map \S+)`, t); m != nil {
		s.assign(v, "retain_route_target", m[1], c)
	} else if textparse.Match(`(?:no )?(?:log-neighbor-changes|log-adjacency-changes|soft-reconfiguration inbound|passive-interface)\b.*|(?:maximum-paths|default-information originate|auto-cost reference-bandwidth)\b.*`, t) != nil {
		s.ignore(c)
		return false
	} else {
		s.issue(c, "unsupported_configuration")
		return false
	}
	return true
}

func cfgNeighborIdentity(name string) (canonical string, valid bool) {
	valid = true

	func() {
		defer func() {
			if recover() != nil {
				valid = false
			}
		}()
		if strings.Contains(name, "/") {
			canonical = cfgPrefix(name, "", false)
		} else {
			canonical = cfgIP(name)
		}
	}()
	return canonical, valid
}

func (s *cfgState) routingNetwork(c *cfgBlock, v vxlan.Record, m []string, protocol, context, family, parent string) bool {
	if protocol != "bgp" || context != "address_families" || (parent != "process" && parent != "vrfs") || textparse.Match(`ipv[46] (?:unicast|multicast)`, family) == nil {
		s.issue(c, "unsupported_configuration")
		return false
	}
	r := vxlan.Record{"prefix": cfgPrefix(m[1], strings.Fields(family)[0], false)}
	if m[2] != "" {
		r["route_map"] = m[2]
	}
	v["networks"] = append(record.Rows(v["networks"]), r)
	return true
}

func (s *cfgState) routingRedistribute(c *cfgBlock, v vxlan.Record, t string) bool {
	w := strings.Fields(t)
	if len(w) < 2 {
		s.issue(c, "unsupported_configuration")
		return false
	}
	r := vxlan.Record{"protocol": w[1]}
	i := 2
	if i < len(w) && w[i] != "route-map" {
		r["process"] = w[i]
		i++
	}
	if i < len(w) {
		if i+2 != len(w) || w[i] != "route-map" {
			s.issue(c, "unsupported_configuration")
			return false
		}
		r["route_map"] = w[i+1]
	}
	v["redistribute"] = append(record.Rows(v["redistribute"]), r)
	return true
}
