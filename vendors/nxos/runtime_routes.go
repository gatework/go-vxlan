package nxos

import (
	"strconv"
	"strings"

	vxlan "github.com/gatework/go-vxlan"
)

const rtRouteHeader = `(?i)Topology ID|Topology|Mac Address|Host IP|Prod|Flags|Seq No|Next-Hops|Next Hop \(s\)|Next Hop\(s\)`

func (p *rtParser) routes(text string) {
	labels := map[string]string{"topology": "topology_id", "topology id": "topology_id", "mac address": "mac", "host ip": "host_ip", "prod": "producer", "flags": "flags", "seq no": "sequence", "next-hops": "next_hops", "next hop (s)": "next_hops", "next hop(s)": "next_hops"}
	var fields []string
	var previous vxlan.Record
	var hopIndex map[string]bool
	for i, source := range strings.Split(text, "\n") {
		line := rtTrim(source)
		n := i + 1
		if line == "" || rtMatch(`^[-=\s]+$`, line) || rtMatch(`^(?:(?:NH\s+)?Flags\s*-\s*)?(?:\([A-Za-z0-9]+\):[A-Za-z0-9 ,/-]+\s*)+$`, line) {
			continue
		}
		if rtMatch(`(?i)^Topology\b`, line) {
			header := strings.Join(rtWords(line), " ")
			matches := rtRE(rtRouteHeader).FindAllString(header, -1)
			fields = []string{}
			seen := map[string]bool{}
			valid := true
			required := map[string]bool{"topology_id": true, "mac": true, "producer": true, "next_hops": true}
			if p.name == "l2route_mac_ips" {
				required["host_ip"] = true
			}
			for _, label := range matches {
				key := labels[strings.ToLower(label)]
				fields = append(fields, key)
				if seen[key] || (!required[key] && key != "flags" && key != "sequence") {
					valid = false
				}
				seen[key] = true
			}
			for key := range required {
				if !seen[key] {
					valid = false
				}
			}
			valid = valid && rtTrim(rtRE(rtRouteHeader).ReplaceAllString(header, "")) == "" && len(fields) >= 2 && fields[0] == "topology_id" && fields[1] == "mac" && fields[len(fields)-1] == "next_hops"
			if !valid {
				fields = nil
				p.issues = append(p.issues, vxlan.Record{"code": "unknown_header", "line": n})
			}
			previous = nil
			continue
		}
		if rtMatch(`(?i)^No (?:MAC(?:-IP)? )?(?:routes|entries)(?: found)?\.?$`, line) {
			p.empty = true
			previous = nil
			continue
		}
		if m := rtFind(`(?i)^Total (?:number of )?(?:MAC(?:-IP)? )?(?:routes|entries)(?: displayed)?\s*:\s*(\d+)$`, line); m != nil {
			p.totals = append(p.totals, rtNum(m[1]))
			previous = nil
			continue
		}
		valid := false
		if fields != nil && rtMatch(`^\d+\s`, line) {
			values := rtRE(`\s+`).Split(line, len(fields))
			if len(values) == len(fields) {
				row := vxlan.Record{}
				for i, k := range fields {
					row[k] = values[i]
				}
				if route, ok := p.routeFields(row); ok {
					previous = route
					hopIndex = nil
					p.rows = append(p.rows, route)
					valid = true
				}
			}
		} else if previous != nil && len(source) > 0 && (source[0] == ' ' || source[0] == '\t') {
			if hops, ok := rtNextHops(line); ok {
				if hopIndex == nil {
					hopIndex = map[string]bool{}
					unique := []vxlan.Record{}
					for _, hop := range previous["next_hops"].([]vxlan.Record) {
						key := rtHopKey(hop)
						if !hopIndex[key] {
							unique = append(unique, hop)
							hopIndex[key] = true
						}
					}
					previous["next_hops"] = unique
				}
				for _, hop := range hops {
					key := rtHopKey(hop)
					if !hopIndex[key] {
						previous["next_hops"] = append(previous["next_hops"].([]vxlan.Record), hop)
						hopIndex[key] = true
					}
				}
				valid = true
			}
		}
		if !valid {
			previous = nil
			p.unparsed(n)
		}
	}
}
func rtHopKey(r vxlan.Record) string {
	return rtKey(r, []string{"address", "interface", "local", "ifindex", "label"})
}
func (p *rtParser) routeFields(r vxlan.Record) (vxlan.Record, bool) {
	n, ok := rtUint32(r["topology_id"].(string))
	if !ok {
		return nil, false
	}
	r["topology_id"] = n
	mac := r["mac"].(string)
	if !rtMatch(`(?i)^(?:[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2})$`, mac) {
		return nil, false
	}
	r["mac"] = rtMAC(mac)
	if s, exists := r["sequence"]; exists {
		n, ok := rtUint32(s.(string))
		if !ok {
			return nil, false
		}
		r["sequence"] = n
	}
	if p.name == "l2route_mac_ips" {
		ip, ok := rtIP(r["host_ip"].(string))
		if !ok {
			return nil, false
		}
		r["host_ip"] = ip
	}
	hops, ok := rtNextHops(r["next_hops"].(string))
	if !ok {
		return nil, false
	}
	r["next_hops"] = hops
	return r, true
}
func rtUint32(s string) (int64, bool) {
	if !rtMatch(`^\d+$`, s) {
		return 0, false
	}
	n, e := strconv.ParseUint(s, 10, 32)
	return int64(n), e == nil
}
func rtNextHops(text string) ([]vxlan.Record, bool) {
	result := []vxlan.Record{}
	offset := 0
	for offset < len(text) {
		m := rtFind(`(?i)^(Ifindex\s+\d+|Local|(?:Eth(?:ernet)?|Po(?:rt-channel)?|nve|Lo(?:opback)?|Vlan|vPC)[\d/.:-]+|[\da-f:.]+)(?:\s*\(Label:\s*(\d+)\))?`, text[offset:])
		if m == nil {
			return nil, false
		}
		end := offset + len(m[0])
		if end < len(text) && text[end] != ',' && text[end] != ' ' && text[end] != '\t' {
			return nil, false
		}
		token := m[1]
		r := vxlan.Record{}
		if strings.EqualFold(token, "Local") {
			r["local"] = true
		} else if rtMatch(`(?i)^Ifindex\s+\d+$`, token) {
			n, ok := rtUint32(rtWords(token)[1])
			if !ok {
				return nil, false
			}
			r["ifindex"] = n
		} else if rtMatch(`(?i)^(?:Eth|Po|nve|Lo|Vlan|vPC)`, token) {
			r["interface"] = token
		} else {
			ip, ok := rtIP(token)
			if !ok {
				return nil, false
			}
			r["address"] = ip
		}
		if m[2] != "" {
			n, ok := rtUint32(m[2])
			if !ok {
				return nil, false
			}
			r["label"] = n
		}
		result = append(result, r)
		offset = end
		if offset == len(text) {
			break
		}
		sep := rtFind(`^(?:\s*,\s*|\s+)`, text[offset:])
		if sep == nil || offset+len(sep[0]) >= len(text) {
			return nil, false
		}
		offset += len(sep[0])
	}
	return result, len(result) > 0
}
func (p *rtParser) finishRoutes(complete bool) {
	for _, n := range p.totals {
		p.count(n, int64(len(p.rows)))
	}
	p.rows = p.dedup(p.rows, []string{"topology_id", "mac", "host_ip", "producer"}, nil)
	if p.empty && len(p.rows) > 0 {
		p.issue("contradictory_empty")
	}
	zeroTotal := len(p.totals) == 1 && rtEqualNumber(p.totals[0], "0")
	if len(p.rows) == 0 && !p.empty && !zeroTotal {
		p.issue("missing_completeness_evidence")
	}
	if !complete {
		p.issue("output_incomplete")
	}
}
