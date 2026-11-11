package nxos

import (
	"strings"

	vxlan "github.com/gatework/go-vxlan"
)

func (p *rtParser) cdp(text string) {
	c := cdpParser{parser: p, conflicts: map[string]bool{}, attributesConflicts: map[string]bool{}}
	p.lines(text, true, c.line)
	c.finish()
}

type cdpParser struct {
	parser                         *rtParser
	row                            vxlan.Record
	scope                          string
	totals                         []any
	conflicts, attributesConflicts map[string]bool
	rowConflicts                   []map[string]bool
}

func (c *cdpParser) assign(values vxlan.Record, conf map[string]bool, key string, value any, n int) {
	if conf[key] {
		return
	}
	if prev, exists := values[key]; exists && prev != value {
		delete(values, key)
		conf[key] = true
		c.parser.issues = append(c.parser.issues, vxlan.Record{"code": "conflicting_cdp_value", "line": n, "field": key})
	} else {
		values[key] = value
	}
}

func (c *cdpParser) line(line string, n int) {
	if rtMatch(`^[-=+\s]+$`, line) {
		c.scope = ""
		return
	}
	if m := rtFind(`(?i)^Total (?:entries|cdp entries) displayed\s*:\s*(\d+)$`, line); m != nil {
		c.totals = append(c.totals, rtNum(m[1]))
		c.scope = ""
		return
	}
	if m := rtFind(`(?i)^Device ID:\s*(\S.*)$`, line); m != nil {
		if c.row != nil {
			c.parser.rows = append(c.parser.rows, c.row)
			c.rowConflicts = append(c.rowConflicts, c.conflicts)
		}
		c.row = vxlan.Record{"device_id": m[1], "interface_addresses": []string{}, "management_addresses": []string{}, "attributes": vxlan.Record{}}
		c.conflicts = map[string]bool{}
		c.attributesConflicts = map[string]bool{}
		c.scope = ""
		c.parser.header = true
		return
	}
	if c.row == nil {
		c.parser.unparsed(n)
		return
	}
	c.fields(line, n)
}

func (c *cdpParser) finish() {

	if c.row != nil {
		c.parser.rows = append(c.parser.rows, c.row)
		c.rowConflicts = append(c.rowConflicts, c.conflicts)
	}
	for _, n := range c.totals {
		c.parser.count(n, int64(len(c.parser.rows)))
	}
	if len(c.totals) == 1 && rtEqualNumber(c.totals[0], "0") && len(c.parser.rows) == 0 {
		c.parser.empty = true
	}
	valid := []vxlan.Record{}
	for i, r := range c.parser.rows {
		conf := c.rowConflicts[i]
		if conf["neighbor_name"] || conf["interface"] || conf["neighbor_interface"] {
			continue
		}
		if r["neighbor_name"] == nil {
			device := rtRE(`\([^)]*\)$`).ReplaceAllString(parsedValue[string](r["device_id"]), "")
			r["neighbor_name"] = strings.Split(device, ".")[0]
		}
		missing := false
		for _, key := range []string{"neighbor_name", "interface", "neighbor_interface"} {
			if r[key] == nil || r[key] == "" {
				missing = true
			}
		}
		if missing {
			c.parser.issue("incomplete_cdp_neighbor")
		} else {
			valid = append(valid, r)
		}
	}
	c.parser.rows = valid
}

func (p *rtParser) vpc(text string) {
	v := vpcParser{parser: p, values: vxlan.Record{"attributes": vxlan.Record{}, "peer_links": []vxlan.Record{}, "members": []vxlan.Record{}}, labels: map[string]string{"vPC domain id": "domain_id", "Peer status": "peer_status", "vPC keep-alive status": "keepalive_status", "Configuration consistency status": "consistency_status", "vPC role": "role"}}
	p.lines(text, false, v.line)
	v.finish()
}

type vpcParser struct {
	parser  *rtParser
	values  vxlan.Record
	section string
	labels  map[string]string
}

func (v *vpcParser) line(line string, n int) {
	if rtMatch(`(?i)^id\s+Port\s+Status\s+Active vlans$`, line) {
		v.section = "peer_links"
		return
	}
	if rtMatch(`(?i)^id\s+Port\s+Status\s+Consistency\s+Reason\s+Active vlans$`, line) {
		v.section = "members"
		return
	}
	if m := rtFind(`(?i)^(\d+)\s+(Po\d+)\s+(up|down\*?)\s+(.+)$`, line); m != nil && v.section != "" {
		v.tableRow(m, n)
		return
	}
	if v.section == "members" && rtMatch(`^Applicable\s+Performed$`, line) {
		rows := parsedValue[[]vxlan.Record](v.values["members"])
		if len(rows) > 0 {
			last := rows[len(rows)-1]
			if last["consistency"] == "Not" && last["reason"] == "Consistency Check Not" {
				last["consistency"] = "Not Applicable"
				last["reason"] = "Consistency Check Not Performed"
				return
			}
		}
	}
	if v.section != "" && rtMatch(`^[\d, .-]+$`, line) {
		rows := parsedValue[[]vxlan.Record](v.values[v.section])
		if len(rows) > 0 {
			last := rows[len(rows)-1]
			last["active_vlans_summary"] = parsedValue[string](last["active_vlans_summary"]) + line
			return
		}
	}
	if line == "Legend:" {
		return
	}
	if strings.Contains(line, ":") {
		v.label(line, n)
		return
	}
	if !rtMatch(`(?i)^(?:vPC Peer-link status|vPC status|Legend:|\(\*\) - local vPC is down, forwarding via vPC peer-link|Please check "show vpc consistency-parameters vpc <vpc-num>" for the|consistency reason of down vpc and for type-2 consistency reasons for|any vpc\.)$`, line) {
		v.parser.unparsed(n)
	}
}

func (v *vpcParser) finish() {

	if !v.parser.header {
		return
	}
	missing := []string{}
	for _, k := range []string{"domain_id", "peer_status", "keepalive_status", "consistency_status"} {
		if _, ok := v.values[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		v.parser.issues = append(v.parser.issues, vxlan.Record{"code": "missing_vpc_fields", "fields": missing})
	}
	for _, r := range parsedValue[[]vxlan.Record](v.values["members"]) {
		if r["consistency"] == "Not" {
			v.parser.issue("incomplete_vpc_member")
			break
		}
	}
	for _, key := range []string{"peer_links", "members"} {
		for _, r := range parsedValue[[]vxlan.Record](v.values[key]) {
			r["active_vlans_truncated"] = strings.Contains(parsedValue[string](r["active_vlans_summary"]), "...")
		}
	}
	if count, ok := parsedValue[vxlan.Record](v.values["attributes"])["Number of vPCs configured"]; ok {
		if rtMatch(`^\d+$`, parsedValue[string](count)) {
			v.parser.count(rtNum(parsedValue[string](count)), int64(len(parsedValue[[]vxlan.Record](v.values["members"]))))
		} else {
			v.parser.issue("invalid_vpc_count")
		}
	}
	for _, key := range []string{"peer_links", "members"} {
		v.values[key] = v.parser.dedup(parsedValue[[]vxlan.Record](v.values[key]), []string{"id"}, nil)
	}
	v.parser.rows = append(v.parser.rows, v.values)
}

func rtInRange(s string, minimum, maximum int64) bool {
	n := rtNum(s)
	if _, ok := n.(int64); !ok {
		return false
	}
	return rtInt(n) >= minimum && rtInt(n) <= maximum
}

func (c *cdpParser) fields(line string, n int) {
	switch {
	case rtMatch(`(?i)^--More--`, line):
		c.parser.unparsed(n)
	case rtMatch(`(?i)^System Name:\s*(\S.*)$`, line):
		m := rtFind(`(?i)^System Name:\s*(\S.*)$`, line)
		c.assign(c.row, c.conflicts, "neighbor_name", m[1], n)
	case rtMatch(`(?i)^Interface address\(es\):(?:\s+\d+)?$`, line):
		c.scope = "interface_addresses"
	case rtMatch(`(?i)^Mgmt address\(es\):(?:\s+\d+)?$`, line):
		c.scope = "management_addresses"
	case rtMatch(`(?i)^IP(?:v[46])? Address:\s*(\S+)$`, line):
		m := rtFind(`(?i)^IP(?:v[46])? Address:\s*(\S+)$`, line)
		ip, ok := rtIP(m[1])
		if (c.scope == "interface_addresses" || c.scope == "management_addresses") && ok {
			c.row[c.scope] = append(parsedValue[[]string](c.row[c.scope]), ip)
		} else {
			c.parser.unparsed(n)
		}
	case rtMatch(`(?i)^Platform:\s*(.+?),\s*Capabilities:\s*(.+)$`, line):
		m := rtFind(`(?i)^Platform:\s*(.+?),\s*Capabilities:\s*(.+)$`, line)
		c.assign(c.row, c.conflicts, "platform", m[1], n)
		c.assign(c.row, c.conflicts, "capabilities", m[2], n)
		c.scope = ""
	case rtMatch(`(?i)^Interface:\s*(\S+),\s*Port ID \(outgoing port\):\s*(\S.*)$`, line):
		m := rtFind(`(?i)^Interface:\s*(\S+),\s*Port ID \(outgoing port\):\s*(\S.*)$`, line)
		c.assign(c.row, c.conflicts, "interface", m[1], n)
		c.assign(c.row, c.conflicts, "neighbor_interface", m[2], n)
		c.scope = ""
	case rtMatch(`(?i)^Holdtime:\s*(\d+) sec$`, line):
		m := rtFind(`(?i)^Holdtime:\s*(\d+) sec$`, line)
		c.assign(c.row, c.conflicts, "holdtime", rtNum(m[1]), n)
	case rtMatch(`(?i)^Version:$`, line):
		c.scope = "version"
		c.row["version"] = ""
	case rtMatch(`(?i)^((?:Local|Remote) Interface MAC):\s*([\da-f]{2}(?::[\da-f]{2}){5})$`, line):
		m := rtFind(`(?i)^((?:Local|Remote) Interface MAC):\s*([\da-f]{2}(?::[\da-f]{2}){5})$`, line)
		c.assign(parsedValue[vxlan.Record](c.row["attributes"]), c.attributesConflicts, rtAttribute(m[1]), strings.ToLower(m[2]), n)
		c.scope = ""
	case rtMatch(`(?i)^DC_UUID:\s*(.*?)$`, line):
		m := rtFind(`(?i)^DC_UUID:\s*(.*?)$`, line)
		var value any
		if m[1] != "" {
			value = m[1]
		}
		c.assign(parsedValue[vxlan.Record](c.row["attributes"]), c.attributesConflicts, "dc_uuid", value, n)
		c.scope = ""
	case rtMatch(`(?i)^(Advertisement Version|Duplex|MTU|Native VLAN|VTP Management Domain|Physical Location):\s*(.+)$`, line):
		m := rtFind(`(?i)^(Advertisement Version|Duplex|MTU|Native VLAN|VTP Management Domain|Physical Location):\s*(.+)$`, line)
		c.assign(parsedValue[vxlan.Record](c.row["attributes"]), c.attributesConflicts, rtAttribute(m[1]), m[2], n)
		c.scope = ""
	default:
		if c.scope == "version" {
			if c.row["version"] != "" {
				c.row["version"] = parsedValue[string](c.row["version"]) + "\n" + line
			} else {
				c.row["version"] = line
			}
		} else {
			c.parser.unparsed(n)
		}
	}
}

func (v *vpcParser) tableRow(m []string, n int) {
	r := vxlan.Record{"id": rtNum(m[1]), "interface": m[2], "state": strings.TrimSuffix(strings.ToLower(m[3]), "*")}
	if strings.HasSuffix(m[3], "*") {
		r["forwarding_via_peer_link"] = true
	}
	if v.section == "members" {
		member := rtFind(`^(\S+)\s+(.+?)\s+([\d, .-]+)$`, m[4])
		if member == nil {
			v.parser.unparsed(n)
			return
		}
		r["consistency"] = member[1]
		r["reason"] = member[2]
		r["active_vlans_summary"] = member[3]
	} else if rtMatch(`^[\d, .-]+$`, m[4]) {
		r["active_vlans_summary"] = strings.Join(rtRE(`\s{2,}`).Split(m[4], -1), "")
	} else {
		v.parser.unparsed(n)
		return
	}
	v.values[v.section] = append(parsedValue[[]vxlan.Record](v.values[v.section]), r)
}

func (v *vpcParser) label(line string, n int) {
	parts := strings.SplitN(line, ":", 2)
	label, value := rtTrim(parts[0]), rtTrim(parts[1])
	if key, ok := v.labels[label]; ok {
		v.parser.header = true
		_, exists := v.values[key]
		validDomain := key != "domain_id" || rtMatch(`^\d+$`, value) && rtInRange(value, 1, 1000)
		if exists || value == "" || !validDomain {
			v.parser.unparsed(n)
		} else if key == "domain_id" {
			v.values[key] = rtNum(value)
		} else {
			v.values[key] = value
		}
	} else if rtMatch(`^(?:Per-vlan consistency status|Type-2 consistency status|Number of vPCs configured|Peer Gateway|Dual-active excluded VLANs|Graceful Consistency Check|Auto-recovery status|Delay-restore(?: SVI| Orphan-port)? status|Operational Layer3 Peer-router|Virtual-peerlink mode)$`, label) && value != "" {
		attrs := parsedValue[vxlan.Record](v.values["attributes"])
		if _, exists := attrs[label]; exists {
			v.parser.unparsed(n)
		}
		attrs[label] = value
	} else {
		v.parser.unparsed(n)
	}
}

func rtAttribute(label string) string { return strings.ReplaceAll(strings.ToLower(label), " ", "_") }
