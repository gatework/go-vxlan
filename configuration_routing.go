package vxlan

import (
	"fmt"
	"strings"
)

func (s *cfgState) routing(b *cfgBlock, protocol, context, family, parent string) Record {
	v := Record{"vrfs": Record{}, "neighbors": Record{}, "templates": Record{}, "address_families": Record{}, "redistribute": []Record{}}
	neighbors := map[string]string{}
	for _, c := range b.children {
		s.enter(c)
		t := c.text
		if !cfgRoutingLeaf(t, protocol, context, family, parent) {
			s.issue(c, "unsupported_configuration")
			continue
		}
		if m := cfgMatch(`(vrf|template peer|neighbor|address-family) (.+)`, t); m != nil {
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
				supported = protocol == "bgp" && (context == "process" || context == "vrfs" || context == "neighbors" || context == "templates") && cfgMatch(`(?:ipv[46] (?:unicast|multicast)|vpnv[46] unicast|l2vpn evpn)`, name) != nil
			}
			if !supported {
				s.issue(c, "unsupported_configuration")
				continue
			}
			if kind == "neighbors" {
				valid := true
				canonical := ""
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
				if !valid {
					s.issue(c, "invalid_configuration_value")
					continue
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
			dest := cfgMap(v[kind])
			s.store(dest, name, c, "duplicate_identity", sourcePath(s.path, kind, name), func() any { return s.routing(c, protocol, kind, af, context) })
			if protocol == "bgp" && (kind == "neighbors" || kind == "templates") && s.conflicts > before {
				delete(dest, name)
				s.seen[fmt.Sprintf("%p:%s", dest, name)] = true
				s.conflicts++
				s.issue(c, "conflicting_configuration_value")
			}
			continue
		} else if m = cfgMatch(`router-id (\S+)`, t); m != nil {
			ip := cfgIP(m[1])
			cfgPrefix(ip+"/32", "ipv4", true)
			s.assign(v, "router_id", ip, c)
		} else if m = cfgMatch(`remote-as (\S+)`, t); m != nil {
			if m[1] != "internal" && m[1] != "external" {
				cfgInt(m[1], 1, 4294967295)
			}
			s.assign(v, "remote_as", m[1], c)
		} else if m = cfgMatch(`inherit peer (\S+)`, t); m != nil {
			s.assign(v, "inherit_peer", m[1], c)
		} else if m = cfgMatch(`update-source (\S+)`, t); m != nil {
			s.assign(v, "update_source", m[1], c)
		} else if m = cfgMatch(`description (.+)`, t); m != nil {
			s.assign(v, "description", m[1], c)
		} else if m = cfgMatch(`route-map (\S+) (in|out)`, t); m != nil {
			if v["route_maps"] == nil {
				v["route_maps"] = Record{}
			}
			s.assign(cfgMap(v["route_maps"]), m[2], m[1], c)
		} else if m = cfgMatch(`(no )?next-hop-self( all)?`, t); m != nil {
			s.assign(v, "next_hop_self", m[1] == "", c)
			s.assign(v, "next_hop_self_all", m[1] == "" && m[2] != "", c)
		} else if m = cfgMatch(`(no )?(bfd|route-reflector-client|advertise-pip|advertise l2vpn evpn)`, t); m != nil {
			k := map[string]string{"bfd": "bfd", "route-reflector-client": "route_reflector_client", "advertise-pip": "advertise_pip", "advertise l2vpn evpn": "advertise_l2vpn_evpn"}[m[2]]
			s.assign(v, k, m[1] == "", c)
		} else if m = cfgMatch(`(no )?send-community(?: (extended|both))?`, t); m != nil {
			if m[2] != "extended" {
				s.assign(v, "standard_community", m[1] == "", c)
			}
			if m[2] != "" {
				s.assign(v, "extended_community", m[1] == "", c)
			}
		} else if m = cfgMatch(`network (\S+)(?: route-map (\S+))?`, t); m != nil {
			if protocol != "bgp" || context != "address_families" || (parent != "process" && parent != "vrfs") || cfgMatch(`ipv[46] (?:unicast|multicast)`, family) == nil {
				s.issue(c, "unsupported_configuration")
				continue
			}
			r := Record{"prefix": cfgPrefix(m[1], strings.Fields(family)[0], false)}
			if m[2] != "" {
				r["route_map"] = m[2]
			}
			v["networks"] = append(cfgRows(v["networks"]), r)
		} else if strings.HasPrefix(t, "redistribute ") {
			w := strings.Fields(t)
			if len(w) < 2 {
				s.issue(c, "unsupported_configuration")
				continue
			}
			r := Record{"protocol": w[1]}
			i := 2
			if i < len(w) && w[i] != "route-map" {
				r["process"] = w[i]
				i++
			}
			if i < len(w) {
				if i+2 != len(w) || w[i] != "route-map" {
					s.issue(c, "unsupported_configuration")
					continue
				}
				r["route_map"] = w[i+1]
			}
			v["redistribute"] = append(cfgRows(v["redistribute"]), r)
		} else if m = cfgMatch(`retain route-target (all|route-map \S+)`, t); m != nil {
			s.assign(v, "retain_route_target", m[1], c)
		} else if cfgMatch(`(?:no )?(?:log-neighbor-changes|log-adjacency-changes|soft-reconfiguration inbound|passive-interface)\b.*|(?:maximum-paths|default-information originate|auto-cost reference-bandwidth)\b.*`, t) != nil {
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
func cfgRoutingLeaf(t, p, c, f, parent string) bool {
	processAF := c == "address_families" && (parent == "process" || parent == "vrfs")
	switch {
	case cfgMatch(`(?:no )?(?:send-community|next-hop-self|route-reflector-client|advertise-pip|advertise l2vpn evpn)\b.*`, t) != nil:
		return p == "bgp" && c == "address_families"
	case cfgMatch(`(?:remote-as|inherit peer|update-source)\b.*`, t) != nil:
		return p == "bgp" && (c == "neighbors" || c == "templates")
	case cfgMatch(`route-map\b.*`, t) != nil:
		return p == "bgp" && c == "address_families" && (parent == "neighbors" || parent == "templates")
	case cfgMatch(`redistribute\b.*`, t) != nil:
		if p == "ospf" {
			return c == "process" || c == "vrfs"
		}
		return processAF && cfgMatch(`ipv[46] (?:unicast|multicast)`, f) != nil
	case cfgMatch(`retain route-target\b.*`, t) != nil:
		return p == "bgp" && processAF && f == "l2vpn evpn"
	case cfgMatch(`router-id\b.*`, t) != nil:
		return c == "process" || c == "vrfs"
	}
	return true
}
