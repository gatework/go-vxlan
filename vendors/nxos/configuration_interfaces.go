package nxos

import (
	"strconv"
	"strings"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/internal/textparse"
)

func (s *cfgState) iface(b *cfgBlock) vxlan.Record {
	v := vxlan.Record{"addresses": []string{}, "acl_bindings": vxlan.Record{}, "anycast": false}
	for _, c := range b.children {
		s.enter(c)
		t := c.text
		if m := textparse.Match(`ip address (\S+)(?: secondary)?`, t); m != nil {
			v["addresses"] = append(record.StringSlice(v["addresses"]), cfgPrefix(m[1], "ipv4", true))
		} else if m = textparse.Match(`(?i)ip unnumbered (loopback\d+)`, t); m != nil {
			s.assign(v, "unnumbered_interface", m[1], c)
		} else if m = textparse.Match(`vrf member (\S+)`, t); m != nil {
			s.assign(v, "vrf", m[1], c)
		} else if m = textparse.Match(`ip router ospf (\S+) area (\S+)`, t); m != nil {
			s.assign(v, "ospf", m[1]+" area "+m[2], c)
		} else if m = textparse.Match(`ip ospf network (point-to-point|broadcast)`, t); m != nil {
			s.assign(v, "ospf_network_type", m[1], c)
		} else if m = textparse.Match(`mtu (\d+)`, t); m != nil {
			s.assign(v, "mtu", cfgInt(m[1], 1, 65535), c)
		} else if m = textparse.Match(`switchport mode (access|trunk|dot1q-tunnel|fex-fabric)`, t); m != nil {
			s.assign(v, "switchport_mode", m[1], c)
		} else if m = textparse.Match(`switchport access vlan (\d+)`, t); m != nil {
			s.assign(v, "access_vlan", cfgInt(m[1], 1, 4094), c)
		} else if t == "switchport" || t == "no switchport" {
			s.assign(v, "switchport", t == "switchport", c)
		} else if t == "ip forward" || t == "no ip forward" {
			s.assign(v, "ip_forward", t == "ip forward", c)
		} else if t == "fabric forwarding mode anycast-gateway" {
			v["anycast"] = true
		} else if m = textparse.Match(`ip access-group (\S+) (in|out)`, t); m != nil {
			s.assign(record.Map(v["acl_bindings"]), m[2], m[1], c)
		} else if m = textparse.Match(`vpc (\d+)`, t); m != nil {
			s.assign(v, "vpc_id", cfgInt(m[1], 1, 4096), c)
		} else if t == "vpc peer-link" {
			v["peer_link"] = true
		} else if m = textparse.Match(`channel-group (\d+)(?: mode \S+)?`, t); m != nil {
			s.assign(v, "channel_group", cfgInt(m[1], 1, 4096), c)
		} else if m = textparse.Match(`description (.+)`, t); m != nil {
			s.assign(v, "description", m[1], c)
		} else if t == "shutdown" || t == "no shutdown" {
			s.assign(v, "shutdown", t == "shutdown", c)
		} else {
			s.unhandled(c)
			continue
		}
		s.leaf(c)
	}
	return v
}
func (s *cfgState) nve(b *cfgBlock) vxlan.Record {
	v := vxlan.Record{"members": vxlan.Record{}}
	for _, c := range b.children {
		s.enter(c)
		t := c.text
		if m := textparse.Match(`member vni (\d+)(?: (associate-vrf)| mcast-group (\S+))?`, t); m != nil {
			s.nveMember(c, v, m)
			continue
		} else if m = textparse.Match(`description (.+)`, t); m != nil {
			s.assign(v, "description", m[1], c)
		} else if m = textparse.Match(`global mcast-group (\S+)`, t); m != nil {
			s.assign(v, "multicast_group", cfgMulticast(m[1]), c)
		} else if m = textparse.Match(`source-interface (\S+)`, t); m != nil {
			s.assign(v, "source_interface", m[1], c)
		} else if m = textparse.Match(`host-reachability protocol (\S+)`, t); m != nil {
			s.assign(v, "host_reachability", m[1], c)
		} else if t == "shutdown" || t == "no shutdown" {
			s.assign(v, "shutdown", t == "shutdown", c)
		} else if t == "advertise virtual-rmac" || t == "no advertise virtual-rmac" {
			s.assign(v, "advertise_virtual_rmac", t == "advertise virtual-rmac", c)
		} else {
			s.issue(c, "unsupported_configuration")
			continue
		}
		s.leaf(c)
	}
	return v
}
func (s *cfgState) vrf(b *cfgBlock, afs bool) vxlan.Record {
	v := vxlan.Record{"route_targets": []vxlan.Record{}, "routes": []vxlan.Record{}}
	for _, c := range b.children {
		s.enter(c)
		t := c.text
		if m := textparse.Match(`vni (\d+)`, t); m != nil {
			s.assign(v, "vni", cfgInt(m[1], 1, 16777215), c)
		} else if m = textparse.Match(`rd (\S+)`, t); m != nil {
			s.assign(v, "rd", m[1], c)
		} else if strings.HasPrefix(t, "route-target ") {
			v["route_targets"] = append(record.Rows(v["route_targets"]), s.routeTarget(c))
		} else if m = textparse.Match(`address-family (.+)`, t); m != nil {
			family := m[1]
			if !afs || (family != "ipv4 unicast" && family != "ipv6 unicast") {
				s.issue(c, "unsupported_configuration")
				continue
			}
			s.vrfAddressFamily(c, v, family)
			continue
		} else if strings.HasPrefix(t, "ip route ") {
			value := s.scope(c, sourcePath(s.path, "routes", len(record.Rows(v["routes"]))), func() any { return s.staticRoute(c) })
			route, ok := value.(vxlan.Record)
			if !ok {
				panic("nxos: route scope returned an invalid type")
			}
			v["routes"] = append(record.Rows(v["routes"]), route)
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
func (s *cfgState) routeTarget(b *cfgBlock) vxlan.Record {
	m := textparse.Match(`route-target (import|export|both) (\S+)( evpn)?`, b.text)
	if m == nil {
		panic("invalid_configuration_value")
	}
	return vxlan.Record{"direction": m[1], "target": m[2], "evpn": m[3] != ""}
}
func (s *cfgState) vpc(b *cfgBlock) vxlan.Record {
	v := vxlan.Record{"peer_keepalive": vxlan.Record{}, "virtual_peer_link": vxlan.Record{}, "peer_gateway": false, "peer_switch": false, "layer3_peer_router": false}
	for _, c := range b.children {
		s.enter(c)
		t := c.text
		if m := textparse.Match(`peer-keepalive (.+)`, t); m != nil {
			s.assign(v, "peer_keepalive", cfgPairs(m[1], []string{"destination", "source", "vrf"}), c)
		} else if m = textparse.Match(`virtual peer-link (.+)`, t); m != nil {
			s.assign(v, "virtual_peer_link", cfgPairs(m[1], []string{"destination", "source", "dscp"}), c)
		} else if t == "peer-gateway" {
			v["peer_gateway"] = true
		} else if t == "peer-switch" {
			v["peer_switch"] = true
		} else if t == "layer3 peer-router" {
			v["layer3_peer_router"] = true
		} else if t == "fast-convergence" || textparse.Match(`(?:role priority|system-priority|auto-recovery|delay restore|ip arp synchronize)\b.*`, t) != nil {
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
func cfgPairs(t string, allowed []string) vxlan.Record {
	w := strings.Fields(t)
	if len(w)%2 != 0 {
		panic("invalid_configuration_value")
	}
	r := vxlan.Record{}
	for i := 0; i < len(w); i += 2 {
		ok := false
		for _, a := range allowed {
			if w[i] == a {
				ok = true
			}
		}
		if !ok || r[w[i]] != nil {
			panic("invalid_configuration_value")
		}
		v := w[i+1]
		if w[i] == "source" || w[i] == "destination" {
			v = cfgIP(v)
		}
		if w[i] == "dscp" {
			cfgInt(v, 0, 63)
		}
		r[w[i]] = v
	}
	return r
}
func (s *cfgState) staticRoute(b *cfgBlock) vxlan.Record {
	w := strings.Fields(b.text)
	if len(w) < 4 {
		panic("invalid_configuration_value")
	}
	hop := w[3]
	offset := 0
	pattern := `(?i)(?:ethernet\d+(?:/\d+){1,2}(?:\.\d+)?|port-channel\d+(?:\.\d+)?|vlan\d+|mgmt\d+|null0)`
	if textparse.Match(pattern, hop) != nil {
		offset = 1
	} else if textparse.Match(`(?i)(?:ethernet|port-channel|vlan|mgmt|null)`, hop) != nil {
		if len(w) < 5 || textparse.Match(pattern, hop+w[4]) == nil {
			panic("invalid_configuration_value")
		}
		offset = 2
	}
	if offset == 0 {
		cfgPrefix(cfgIP(hop)+"/32", "ipv4", false)
	} else if len(w) > 3+offset && textparse.Match(`(?:name|tag|track|vrf|\d+)`, w[3+offset]) == nil {
		cfgPrefix(cfgIP(w[3+offset])+"/32", "ipv4", false)
	}
	return vxlan.Record{"prefix": cfgPrefix(w[2], "ipv4", false), "next_hop": hop, "options": strings.Join(w[4:], " ")}
}

func (s *cfgState) nveMember(c *cfgBlock, v vxlan.Record, m []string) {
	id := cfgInt(m[1], 1, 16777215)
	member := vxlan.Record{"associate_vrf": m[2] != ""}
	if m[3] != "" {
		member["multicast_group"] = cfgMulticast(m[3])
	}
	for _, x := range c.children {
		s.enter(x)
		if x.text == "ingress-replication protocol bgp" {
			member["replication"] = "bgp"
		} else if g := textparse.Match(`mcast-group (\S+)`, x.text); g != nil {
			group := cfgMulticast(g[1])
			if old := member["multicast_group"]; old != nil && old != group {
				panic("invalid_configuration_value")
			}
			member["multicast_group"] = group
		} else if x.text == "suppress-arp" || x.text == "no suppress-arp" {
			s.assign(member, "suppress_arp", x.text == "suppress-arp", x)
		} else {
			s.issue(x, "unsupported_configuration")
			continue
		}
		s.leaf(x)
	}
	s.current = c
	if member["replication"] == "bgp" && member["multicast_group"] != nil {
		panic("invalid_configuration_value")
	}
	s.store(record.Map(v["members"]), strconv.Itoa(id), c, "duplicate_identity", sourcePath(s.path, "members", strconv.Itoa(id)), func() any { return member })
}

func (s *cfgState) vrfAddressFamily(c *cfgBlock, v vxlan.Record, family string) {
	targetsStart, exportsStart := len(record.Rows(v["route_targets"])), len(record.Rows(v["exports"]))
	for _, x := range c.children {
		s.enter(x)
		if strings.HasPrefix(x.text, "route-target ") {
			r := s.routeTarget(x)
			r["address_family"] = family
			v["route_targets"] = append(record.Rows(v["route_targets"]), r)
		} else if z := textparse.Match(`export vrf default(?: (\d+))? map (\S+)( allow-vpn)?`, x.text); z != nil {
			var limit any
			if z[1] != "" {
				limit = cfgInt(z[1], 1, 2147483647)
			}
			v["exports"] = append(record.Rows(v["exports"]), vxlan.Record{"vrf": "default", "prefix_limit": limit, "route_map": z[2], "allow_vpn": z[3] != "", "address_family": family})
		} else {
			s.issue(x, "unsupported_configuration")
			continue
		}
		s.leaf(x)
	}
	for i, r := range record.Rows(v["route_targets"])[targetsStart:] {
		s.capture(c, r, sourcePath(s.path, "route_targets", targetsStart+i))
	}
	for i, r := range record.Rows(v["exports"])[exportsStart:] {
		s.capture(c, r, sourcePath(s.path, "exports", exportsStart+i))
	}
}
