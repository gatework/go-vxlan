package vxlan

import "strings"

func (p *rtParser) cdp(text string) {
	var row Record
	scope := ""
	totals := []any{}
	conflicts := map[string]bool{}
	attributesConflicts := map[string]bool{}
	rowConflicts := []map[string]bool{}
	assign := func(values Record, conf map[string]bool, key string, value any, n int) {
		if conf[key] {
			return
		}
		if prev, exists := values[key]; exists && prev != value {
			delete(values, key)
			conf[key] = true
			p.issues = append(p.issues, Record{"code": "conflicting_cdp_value", "line": n, "field": key})
		} else {
			values[key] = value
		}
	}
	p.lines(text, true, func(line string, n int) {
		if rtMatch(`^[-=+\s]+$`, line) {
			scope = ""
			return
		}
		if m := rtFind(`(?i)^Total (?:entries|cdp entries) displayed\s*:\s*(\d+)$`, line); m != nil {
			totals = append(totals, rtNum(m[1]))
			scope = ""
			return
		}
		if m := rtFind(`(?i)^Device ID:\s*(\S.*)$`, line); m != nil {
			if row != nil {
				p.rows = append(p.rows, row)
				rowConflicts = append(rowConflicts, conflicts)
			}
			row = Record{"device_id": m[1], "interface_addresses": []string{}, "management_addresses": []string{}, "attributes": Record{}}
			conflicts = map[string]bool{}
			attributesConflicts = map[string]bool{}
			scope = ""
			p.header = true
			return
		}
		if row == nil {
			p.unparsed(n)
			return
		}
		switch {
		case rtMatch(`(?i)^--More--`, line):
			p.unparsed(n)
		case rtMatch(`(?i)^System Name:\s*(\S.*)$`, line):
			m := rtFind(`(?i)^System Name:\s*(\S.*)$`, line)
			assign(row, conflicts, "neighbor_name", m[1], n)
		case rtMatch(`(?i)^Interface address\(es\):(?:\s+\d+)?$`, line):
			scope = "interface_addresses"
		case rtMatch(`(?i)^Mgmt address\(es\):(?:\s+\d+)?$`, line):
			scope = "management_addresses"
		case rtMatch(`(?i)^IP(?:v[46])? Address:\s*(\S+)$`, line):
			m := rtFind(`(?i)^IP(?:v[46])? Address:\s*(\S+)$`, line)
			ip, ok := rtIP(m[1])
			if (scope == "interface_addresses" || scope == "management_addresses") && ok {
				row[scope] = append(row[scope].([]string), ip)
			} else {
				p.unparsed(n)
			}
		case rtMatch(`(?i)^Platform:\s*(.+?),\s*Capabilities:\s*(.+)$`, line):
			m := rtFind(`(?i)^Platform:\s*(.+?),\s*Capabilities:\s*(.+)$`, line)
			assign(row, conflicts, "platform", m[1], n)
			assign(row, conflicts, "capabilities", m[2], n)
			scope = ""
		case rtMatch(`(?i)^Interface:\s*(\S+),\s*Port ID \(outgoing port\):\s*(\S.*)$`, line):
			m := rtFind(`(?i)^Interface:\s*(\S+),\s*Port ID \(outgoing port\):\s*(\S.*)$`, line)
			assign(row, conflicts, "interface", m[1], n)
			assign(row, conflicts, "neighbor_interface", m[2], n)
			scope = ""
		case rtMatch(`(?i)^Holdtime:\s*(\d+) sec$`, line):
			m := rtFind(`(?i)^Holdtime:\s*(\d+) sec$`, line)
			assign(row, conflicts, "holdtime", rtNum(m[1]), n)
		case rtMatch(`(?i)^Version:$`, line):
			scope = "version"
			row["version"] = ""
		case rtMatch(`(?i)^((?:Local|Remote) Interface MAC):\s*([\da-f]{2}(?::[\da-f]{2}){5})$`, line):
			m := rtFind(`(?i)^((?:Local|Remote) Interface MAC):\s*([\da-f]{2}(?::[\da-f]{2}){5})$`, line)
			assign(row["attributes"].(Record), attributesConflicts, rtAttribute(m[1]), strings.ToLower(m[2]), n)
			scope = ""
		case rtMatch(`(?i)^DC_UUID:\s*(.*?)$`, line):
			m := rtFind(`(?i)^DC_UUID:\s*(.*?)$`, line)
			var value any
			if m[1] != "" {
				value = m[1]
			}
			assign(row["attributes"].(Record), attributesConflicts, "dc_uuid", value, n)
			scope = ""
		case rtMatch(`(?i)^(Advertisement Version|Duplex|MTU|Native VLAN|VTP Management Domain|Physical Location):\s*(.+)$`, line):
			m := rtFind(`(?i)^(Advertisement Version|Duplex|MTU|Native VLAN|VTP Management Domain|Physical Location):\s*(.+)$`, line)
			assign(row["attributes"].(Record), attributesConflicts, rtAttribute(m[1]), m[2], n)
			scope = ""
		default:
			if scope == "version" {
				if row["version"] != "" {
					row["version"] = row["version"].(string) + "\n" + line
				} else {
					row["version"] = line
				}
			} else {
				p.unparsed(n)
			}
		}
	})
	if row != nil {
		p.rows = append(p.rows, row)
		rowConflicts = append(rowConflicts, conflicts)
	}
	for _, n := range totals {
		p.count(n, int64(len(p.rows)))
	}
	if len(totals) == 1 && rtEqualNumber(totals[0], "0") && len(p.rows) == 0 {
		p.empty = true
	}
	valid := []Record{}
	for i, r := range p.rows {
		conf := rowConflicts[i]
		if conf["neighbor_name"] || conf["interface"] || conf["neighbor_interface"] {
			continue
		}
		if r["neighbor_name"] == nil {
			device := rtRE(`\([^)]*\)$`).ReplaceAllString(r["device_id"].(string), "")
			r["neighbor_name"] = strings.Split(device, ".")[0]
		}
		missing := false
		for _, key := range []string{"neighbor_name", "interface", "neighbor_interface"} {
			if r[key] == nil || r[key] == "" {
				missing = true
			}
		}
		if missing {
			p.issue("incomplete_cdp_neighbor")
		} else {
			valid = append(valid, r)
		}
	}
	p.rows = valid
}
func rtAttribute(label string) string { return strings.ReplaceAll(strings.ToLower(label), " ", "_") }

func (p *rtParser) vpc(text string) {
	values := Record{"attributes": Record{}, "peer_links": []Record{}, "members": []Record{}}
	section := ""
	labels := map[string]string{"vPC domain id": "domain_id", "Peer status": "peer_status", "vPC keep-alive status": "keepalive_status", "Configuration consistency status": "consistency_status", "vPC role": "role"}
	p.lines(text, false, func(line string, n int) {
		if rtMatch(`(?i)^id\s+Port\s+Status\s+Active vlans$`, line) {
			section = "peer_links"
			return
		}
		if rtMatch(`(?i)^id\s+Port\s+Status\s+Consistency\s+Reason\s+Active vlans$`, line) {
			section = "members"
			return
		}
		if m := rtFind(`(?i)^(\d+)\s+(Po\d+)\s+(up|down\*?)\s+(.+)$`, line); m != nil && section != "" {
			r := Record{"id": rtNum(m[1]), "interface": m[2], "state": strings.TrimSuffix(strings.ToLower(m[3]), "*")}
			if strings.HasSuffix(m[3], "*") {
				r["forwarding_via_peer_link"] = true
			}
			if section == "members" {
				member := rtFind(`^(\S+)\s+(.+?)\s+([\d, .-]+)$`, m[4])
				if member == nil {
					p.unparsed(n)
					return
				}
				r["consistency"] = member[1]
				r["reason"] = member[2]
				r["active_vlans_summary"] = member[3]
			} else if rtMatch(`^[\d, .-]+$`, m[4]) {
				r["active_vlans_summary"] = strings.Join(rtRE(`\s{2,}`).Split(m[4], -1), "")
			} else {
				p.unparsed(n)
				return
			}
			values[section] = append(values[section].([]Record), r)
			return
		}
		if section == "members" && rtMatch(`^Applicable\s+Performed$`, line) {
			rows := values["members"].([]Record)
			if len(rows) > 0 {
				last := rows[len(rows)-1]
				if last["consistency"] == "Not" && last["reason"] == "Consistency Check Not" {
					last["consistency"] = "Not Applicable"
					last["reason"] = "Consistency Check Not Performed"
					return
				}
			}
		}
		if section != "" && rtMatch(`^[\d, .-]+$`, line) {
			rows := values[section].([]Record)
			if len(rows) > 0 {
				last := rows[len(rows)-1]
				last["active_vlans_summary"] = last["active_vlans_summary"].(string) + line
				return
			}
		}
		if line == "Legend:" {
			return
		}
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			label, value := rtTrim(parts[0]), rtTrim(parts[1])
			if key, ok := labels[label]; ok {
				p.header = true
				_, exists := values[key]
				validDomain := key != "domain_id" || rtMatch(`^\d+$`, value) && rtInRange(value, 1, 1000)
				if exists || value == "" || !validDomain {
					p.unparsed(n)
				} else if key == "domain_id" {
					values[key] = rtNum(value)
				} else {
					values[key] = value
				}
			} else if rtMatch(`^(?:Per-vlan consistency status|Type-2 consistency status|Number of vPCs configured|Peer Gateway|Dual-active excluded VLANs|Graceful Consistency Check|Auto-recovery status|Delay-restore(?: SVI| Orphan-port)? status|Operational Layer3 Peer-router|Virtual-peerlink mode)$`, label) && value != "" {
				attrs := values["attributes"].(Record)
				if _, exists := attrs[label]; exists {
					p.unparsed(n)
				}
				attrs[label] = value
			} else {
				p.unparsed(n)
			}
			return
		}
		if !rtMatch(`(?i)^(?:vPC Peer-link status|vPC status|Legend:|\(\*\) - local vPC is down, forwarding via vPC peer-link|Please check "show vpc consistency-parameters vpc <vpc-num>" for the|consistency reason of down vpc and for type-2 consistency reasons for|any vpc\.)$`, line) {
			p.unparsed(n)
		}
	})
	if !p.header {
		return
	}
	missing := []string{}
	for _, k := range []string{"domain_id", "peer_status", "keepalive_status", "consistency_status"} {
		if _, ok := values[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		p.issues = append(p.issues, Record{"code": "missing_vpc_fields", "fields": missing})
	}
	for _, r := range values["members"].([]Record) {
		if r["consistency"] == "Not" {
			p.issue("incomplete_vpc_member")
			break
		}
	}
	for _, key := range []string{"peer_links", "members"} {
		for _, r := range values[key].([]Record) {
			r["active_vlans_truncated"] = strings.Contains(r["active_vlans_summary"].(string), "...")
		}
	}
	if count, ok := values["attributes"].(Record)["Number of vPCs configured"]; ok {
		if rtMatch(`^\d+$`, count.(string)) {
			p.count(rtNum(count.(string)), int64(len(values["members"].([]Record))))
		} else {
			p.issue("invalid_vpc_count")
		}
	}
	for _, key := range []string{"peer_links", "members"} {
		values[key] = p.dedup(values[key].([]Record), []string{"id"}, nil)
	}
	p.rows = append(p.rows, values)
}
func rtInRange(s string, min, max int64) bool {
	n := rtNum(s)
	if _, ok := n.(int64); !ok {
		return false
	}
	return rtInt(n) >= min && rtInt(n) <= max
}
