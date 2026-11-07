package vxlan

import (
	"strconv"
	"strings"
)

func (p *rtParser) interfaces(text string) {
	layout := ""
	p.lines(text, false, func(line string, n int) {
		if rtMatch(`(?i)^(?:Port\s+VRF\s+Status\s+IP Address(?:\s+Speed\s+MTU)?|(?:Port|Interface)\s+Name\s+Status\s+Vlan\s+Duplex\s+Speed\s+Type|(?:Ethernet|Port-channel)\s+VLAN\s+Type\s+Mode\s+Status\s+Reason\s+Speed\s+(?:Port|Protocol)|Interface\s+Status\s+Description|Interface\s+Secondary VLAN\(Type\)\s+Status Reason|Port\s+Status Reason\s+MTU)$`, line) {
			layout = line
			p.header = true
			return
		}
		if rtMatch(`(?i)^Interface(?:\s+Ch #)?$`, line) {
			return
		}
		words := rtWords(line)
		state := -1
		for i, w := range words {
			if rtMatch(`^(?:up|down|connected|notconnect|disabled|admin-down)$`, strings.ToLower(w)) {
				state = i
				break
			}
		}
		if layout == "" || state < 0 || !rtMatch(`(?i)^(?:mgmt\d+|Eth(?:ernet)?\d[\w/.-]*|Po\d+|port-channel\d+|Vlan\d+|Lo\d+|loopback\d+|nve\d+)$`, words[0]) {
			p.unparsed(n)
			return
		}
		r := Record{"interface": words[0], "state": strings.ToLower(words[state]), "detail": strings.Join(words[state+1:], " ")}
		switch {
		case rtMatch(`(?i)^Port\s+VRF`, layout):
			if state != 2 || (len(words) != 4 && len(words) != 6) || (len(words) == 6 && !rtMatch(`^\d+$`, words[5])) || (words[3] != "--" && !rtValidIP(words[3])) {
				p.unparsed(n)
				return
			}
			r["vrf"] = words[1]
			r["ip_address"] = words[3]
			if len(words) == 6 {
				r["speed"] = words[4]
				r["mtu"] = rtNum(words[5])
			}
		case rtMatch(`(?i)^(?:Ethernet|Port-channel)\s+VLAN`, layout):
			if state != 4 || len(words) < 8 {
				p.unparsed(n)
				return
			}
			r["vlan"] = words[1]
			r["type"] = words[2]
			r["mode"] = words[3]
			r["reason"] = strings.Join(words[5:len(words)-2], " ")
			r["speed"] = words[len(words)-2]
			key := "protocol"
			if strings.HasPrefix(layout, "Ethernet") {
				key = "port_channel"
			}
			r[key] = words[len(words)-1]
		case rtMatch(`(?i)^Interface\s+Status`, layout):
			if state != 1 {
				p.unparsed(n)
				return
			}
			r["description"] = strings.Join(words[2:], " ")
		case rtMatch(`(?i)^Interface\s+Secondary`, layout):
			if state < 2 {
				p.unparsed(n)
				return
			}
			r["secondary_vlan"] = strings.Join(words[1:state], " ")
			r["reason"] = strings.Join(words[state+1:], " ")
		case rtMatch(`(?i)^Port\s+Status Reason`, layout):
			if state != 1 || len(words) < 4 || !rtMatch(`^\d+$`, words[len(words)-1]) {
				p.unparsed(n)
				return
			}
			r["reason"] = strings.Join(words[2:len(words)-1], " ")
			r["mtu"] = rtNum(words[len(words)-1])
		default:
			m := rtFind(`(?i)^\S+\s+(.*?)\s+(connected|notconnect|disabled|admin-down|up|down)\s+(\d+|routed|trunk|unassigned|--)\s+(full|half|a-full|a-half|auto|--)\s+(\S+)\s+(.+)$`, line)
			if m == nil {
				p.unparsed(n)
				return
			}
			r["name"] = m[1]
			r["state"] = strings.ToLower(m[2])
			r["vlan"] = m[3]
			r["duplex"] = m[4]
			r["speed"] = m[5]
			r["type"] = m[6]
			r["detail"] = strings.Join(m[3:], " ")
		}
		p.rows = append(p.rows, r)
	})
}

func (p *rtParser) members(text string) []Record {
	out := []Record{}
	if text == "" || text == "--" {
		return out
	}
	for _, word := range rtWords(text) {
		m := rtFind(`(?i)^(Eth(?:ernet)?[\d/]+)\(([^\s()]+)\)$`, word)
		if m == nil {
			p.issue("invalid_port_channel_member")
		} else {
			out = append(out, Record{"interface": m[1], "flags": m[2]})
		}
	}
	return out
}
func (p *rtParser) ports(text string) {
	totals := []any{}
	var previous Record
	p.lines(text, false, func(line string, n int) {
		before := len(p.issues)
		if rtMatch(`(?i)^Group\s+Port-(?:Channel)?\s+Type\s+Protocol\s+Member Ports$`, line) {
			p.header = true
			previous = nil
		} else if line == "Channel" && p.header {
			previous = nil
			return
		} else if m := rtFind(`(?i)^(\d+)\s+(Po\d+)\(([^\s()]+)\)\s+(\S+)\s+(\S+)\s*(.*)$`, line); m != nil {
			previous = Record{"group": rtNum(m[1]), "interface": m[2], "flags": m[3], "type": m[4], "protocol": m[5], "members": p.members(m[6])}
			p.rows = append(p.rows, previous)
		} else if rtMatch(`(?i)^(?:Eth(?:ernet)?\S+\([^)]+\)\s*)+$`, line) && previous != nil {
			previous["members"] = append(previous["members"].([]Record), p.members(line)...)
		} else if m := rtFind(`(?i)^Number of port-channels\s*:\s*(\d+)$`, line); m != nil {
			totals = append(totals, rtNum(m[1]))
			previous = nil
		} else if !rtMatch(`^(?:Flags:\s+D - Down\s+P - Up in port-channel \(members\)|I - Individual\s+H - Hot-standby \(LACP only\)|s - Suspended\s+r - Module-removed|b - BFD Session Wait|S - Switched\s+R - Routed|U - Up \(port-channel\)|p - Up in delay-lacp mode \(member\)|M - Not in use\. Min-links not met)$`, line) {
			p.unparsed(n)
			previous = nil
		}
		if len(p.issues) > before {
			previous = nil
		}
	})
	all := []Record{}
	for _, r := range p.rows {
		all = append(all, r["members"].([]Record)...)
	}
	keyFn := func(r Record) string {
		return rtRE(`(?i)^Eth(?:ernet)?`).ReplaceAllString(r["interface"].(string), "Eth")
	}
	valid := p.dedup(all, nil, keyFn)
	keys := map[string]bool{}
	for _, r := range valid {
		keys[keyFn(r)] = true
	}
	for _, r := range p.rows {
		members := []Record{}
		for _, m := range r["members"].([]Record) {
			if keys[keyFn(m)] {
				members = append(members, m)
			}
		}
		r["members"] = members
	}
	for _, n := range totals {
		p.count(n, int64(len(p.rows)))
	}
	if len(totals) == 1 && rtEqualNumber(totals[0], "0") && len(p.rows) == 0 {
		p.empty = true
	}
}

func (p *rtParser) macs(text string) {
	p.lines(text, false, func(line string, n int) {
		if rtMatch(`(?i)^VLAN\s+MAC Address\s+Type\s+age\s+Secure\s+NTFY\s+Ports$`, line) {
			p.header = true
			return
		}
		m := rtFind(`(?i)^(?:([*+GOCR~])\s+)?(\d+|-)\s+([\da-f]{4}(?:\.[\da-f]{4}){2})\s+(dynamic|static)\s+(\S+)\s+([TF])\s+([TF])\s+(.+)$`, line)
		if m != nil {
			var vlan any
			if m[2] != "-" {
				i, e := strconv.ParseInt(m[2], 10, 64)
				if e != nil || i < 1 || i > 4094 {
					p.unparsed(n)
					return
				}
				vlan = i
			}
			var flag any
			if m[1] != "" && rtMatch(`^[*+GOCR~]$`, m[1]) {
				flag = m[1]
			}
			p.rows = append(p.rows, Record{"vlan_id": vlan, "mac": rtMAC(m[3]), "type": strings.ToLower(m[4]), "age": m[5], "secure": strings.EqualFold(m[6], "T"), "notify": strings.EqualFold(m[7], "T"), "destination": m[8], "flags": flag})
			return
		}
		if !rtMatch(`(?i)^(?:Legend:|\* - primary entry, G - Gateway MAC, \(R\) - Routed MAC, O - Overlay MAC|age - seconds since last seen,\+ - primary entry using vPC Peer-Link,|\(T\) - True, \(F\) - False, C - ControlPlane MAC, ~ - vsan,?|\(NA\)- Not Applicable(?: A [–-] ESI Active Path, S [–-] ESI Standby Path)?|TL - True Learned, PS - Peer Sync, RO - Re-originate)$`, line) {
			p.unparsed(n)
		}
	})
	p.rows = p.dedup(p.rows, nil, func(r Record) string {
		base := rtKey(r, []string{"vlan_id", "mac"})
		if r["flags"] == "G" && r["type"] == "static" {
			dest := r["destination"].(string)
			gateway := rtMatch(`(?i)^sup-eth\d+\(R\)$`, dest)
			if m := rtFind(`(?i)^(Lo\d+)\(R\)(?: \((Lo\d+)\))?$`, dest); m != nil {
				gateway = m[2] == "" || strings.EqualFold(m[1], m[2])
			}
			if gateway {
				return base + "gateway" + dest
			}
		}
		return base
	})
}
