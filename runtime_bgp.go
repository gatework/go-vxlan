package vxlan

import (
	"math/big"
	"net/netip"
	"strconv"
	"strings"
)

const rtBGPScope = `^BGP summary information for VRF (\S+), address family (.+)$`
const rtBGPRouter = `^BGP router identifier (\S+), local AS number (\S+)$`

func (p *rtParser) bgp(text string) {
	scope := Record{}
	var columns []string
	total := false
	seen := map[int]bool{}
	peers := map[string]int{}
	p.lines(text, false, func(line string, n int) {
		if rtMatch(`(?i)^Neighbor\s+V\s+AS\s+MsgRcvd\s+MsgSent\s+TblVer\s+InQ\s+OutQ\s+Up/Down\s+State/PfxRcd$`, line) {
			p.header = true
			return
		}
		if m := rtFind(rtBGPScope, line); m != nil {
			scope = Record{"vrf": m[1], "address_family": m[2]}
			if m[2] != "L2VPN EVPN" {
				p.unparsed(n)
			}
			columns = nil
			return
		}
		if m := rtFind(rtBGPRouter, line); m != nil {
			scope["router_id"] = m[1]
			scope["local_as"] = m[2]
			return
		}
		if m := rtFind(`^Neighbor\s+T\s+AS\s+(?:(PfxRcd)\s+)?(Type-[1-9]\d*(?:\s+Type-[1-9]\d*)*)$`, line); m != nil {
			total = m[1] != ""
			columns = []string{}
			unique := map[string]bool{}
			valid := true
			for _, w := range rtWords(m[2]) {
				c := strings.ReplaceAll(strings.ToLower(w), "-", "")
				if unique[c] || !rtMatch(`^type(?:[1-8]|12)$`, c) {
					valid = false
				}
				unique[c] = true
				columns = append(columns, c)
			}
			if !valid {
				p.unparsed(n)
				columns = nil
			}
			return
		}
		if columns != nil {
			words := rtWords(line)
			offset := 3
			if total {
				offset = 4
			}
			valid := len(words) == len(columns)+offset
			var peer Record
			idx := -1
			if len(words) > 0 {
				if address, ok := rtIP(words[0]); ok {
					keyScope := Record{"vrf": scope["vrf"], "address_family": scope["address_family"], "peer_ip": address}
					if i, exists := peers[rtKey(keyScope, []string{"vrf", "address_family", "peer_ip"})]; exists {
						idx = i
						peer = p.rows[i]
					}
				}
			}
			if valid {
				valid = (words[1] == "I" || words[1] == "E")
				for _, w := range words[2:] {
					valid = valid && rtMatch(`^\d+$`, w)
				}
				valid = valid && peer != nil && peer["prefixes_received"] != nil && !seen[idx]
				if valid {
					valid = rtEqualNumber(peer["remote_as"], words[2]) && (!total || rtEqualNumber(peer["prefixes_received"], words[3]))
				}
			}
			if valid {
				sum := new(big.Int)
				counts := Record{}
				for i, c := range columns {
					v := rtNum(words[offset+i])
					counts[c] = v
					b, _ := new(big.Int).SetString(words[offset+i], 10)
					sum.Add(sum, b)
				}
				max, _ := new(big.Int).SetString(rtNumberString(peer["prefixes_received"]), 10)
				if sum.Cmp(max) > 0 {
					p.issues = append(p.issues, Record{"code": "inconsistent_prefix_statistics", "line": n})
				} else {
					peer["prefixes_by_type"] = counts
				}
				seen[idx] = true
			} else {
				p.unparsed(n)
			}
			return
		}
		if m := rtFind(`(?i)^([\da-f:.]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+)$`, line); m != nil {
			r := rtFields("peer_ip version remote_as messages_received messages_sent table_version input_queue output_queue uptime state", m[1:])
			for k, v := range scope {
				r[k] = v
			}
			for _, k := range []string{"version", "remote_as", "messages_received", "messages_sent", "table_version", "input_queue", "output_queue"} {
				r[k] = rtNum(r[k].(string))
			}
			asn, e := strconv.ParseUint(m[3], 10, 32)
			if r["vrf"] == nil || r["address_family"] != "L2VPN EVPN" || !rtValidIP(m[1]) || !rtEqualNumber(r["version"], "4") || e != nil || asn == 0 || !rtMatch(`(?i)^(?:\d+|Idle(?: \(Admin\))?|Active|Connect|OpenSent|OpenConfirm|Shutdown)$`, m[10]) {
				p.unparsed(n)
				return
			}
			r["peer_ip"], _ = rtIP(m[1])
			state := strings.ReplaceAll(strings.ToLower(m[10]), " ", "_")
			r["state"] = state
			r["prefixes_received"] = nil
			if rtMatch(`^\d+$`, state) {
				r["prefixes_received"] = rtNum(state)
				r["state"] = "established"
			}
			p.rows = append(p.rows, r)
			key := rtKey(r, []string{"vrf", "address_family", "peer_ip"})
			if _, ok := peers[key]; !ok {
				peers[key] = len(p.rows) - 1
			}
			return
		}
		if !rtMatch(`(?i)^(?:BGP table version is \d+(?:, L2VPN EVPN config peers \d+, capable peers \d+)?|\d+ network entries and \d+ paths using \d+ bytes of memory|BGP attribute entries \[\d+/\d+\], BGP AS path entries \[\d+/\d+\]|BGP community entries \[\d+/\d+\], BGP clusterlist entries \[\d+/\d+\])$`, line) {
			p.unparsed(n)
		}
	})
	if columns != nil && len(seen) != len(p.rows) {
		p.issues = append(p.issues, Record{"code": "missing_prefix_statistics", "expected": len(p.rows), "observed": len(seen)})
	}
}
func rtNumberString(v any) string { return rtTrim(rtString(v)) }
func rtEqualNumber(v any, s string) bool {
	a, ok := new(big.Int).SetString(rtNumberString(v), 10)
	b, ok2 := new(big.Int).SetString(s, 10)
	return ok && ok2 && a.Cmp(b) == 0
}
func rtRouterIdentity(router, asn string) (string, bool) {
	ip, e := netip.ParseAddr(router)
	if e != nil || !ip.Is4() || !rtMatch(`^\d+(?:\.\d+)?$`, asn) {
		return "", false
	}
	parts := strings.Split(asn, ".")
	n, e := strconv.ParseUint(parts[0], 10, 32)
	if e != nil {
		return "", false
	}
	if len(parts) == 2 {
		m, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil || n > 65535 {
			return "", false
		}
		n = n*65536 + m
	}
	if n < 1 || n > 4294967295 {
		return "", false
	}
	return ip.String() + "/" + strconv.FormatUint(n, 10), true
}
func (p *rtParser) bgpIdentities(text string) {
	scope := Record{}
	identities := map[string]string{}
	invalid := map[string]Record{}
	order := []string{}
	scopeKey := "null"
	for _, s := range strings.Split(text, "\n") {
		line := rtTrim(s)
		if m := rtFind(rtBGPScope, line); m != nil {
			scope = Record{"vrf": m[1], "address_family": m[2]}
			scopeKey = rtKey(scope, []string{"vrf", "address_family"})
		} else if m := rtFind(rtBGPRouter, line); m != nil {
			identity, ok := rtRouterIdentity(m[1], m[2])
			code := ""
			if !ok {
				code = "invalid_bgp_identity"
			} else if prev, exists := identities[scopeKey]; exists && prev != identity {
				code = "conflicting_bgp_identity"
			} else {
				identities[scopeKey] = identity
			}
			if code != "" {
				if _, exists := invalid[scopeKey]; !exists {
					invalid[scopeKey] = Record{"code": code, "vrf": scope["vrf"], "address_family": scope["address_family"]}
					order = append(order, scopeKey)
				}
			}
		}
	}
	for _, k := range order {
		issue := invalid[k]
		exists := false
		for _, prev := range p.issues {
			if rtKey(prev, []string{"code", "vrf", "address_family"}) == rtKey(issue, []string{"code", "vrf", "address_family"}) {
				exists = true
				break
			}
		}
		if !exists {
			p.issues = append(p.issues, issue)
		}
	}
	out := []Record{}
	for _, r := range p.rows {
		if _, bad := invalid[rtKey(r, []string{"vrf", "address_family"})]; !bad {
			out = append(out, r)
		}
	}
	p.rows = out
}
