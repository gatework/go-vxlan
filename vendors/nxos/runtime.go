package nxos

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	vxlan "github.com/gatework/go-vxlan"
)

type rtParser struct {
	name          string
	rows, issues  []vxlan.Record
	empty, header bool
	totals        []any
}

var rtRegexes sync.Map

func rtRE(pattern string) *regexp.Regexp {
	if v, ok := rtRegexes.Load(pattern); ok {
		compiled, ok := v.(*regexp.Regexp)
		if !ok {
			panic("nxos: invalid compiled expression cache entry")
		}
		return compiled
	}
	re := regexp.MustCompile(pattern)
	v, _ := rtRegexes.LoadOrStore(pattern, re)
	compiled, ok := v.(*regexp.Regexp)
	if !ok {
		panic("nxos: invalid compiled expression cache entry")
	}
	return compiled
}
func rtMatch(pattern, s string) bool    { return rtRE(pattern).MatchString(s) }
func rtFind(pattern, s string) []string { return rtRE(pattern).FindStringSubmatch(s) }
func rtNum(s string) any {
	n, err := strconv.ParseInt(s, 10, 64)
	if err == nil {
		return n
	}
	return json.Number(strings.TrimLeft(s, "0"))
}
func rtString(v any) string { return fmt.Sprint(v) }
func rtInt(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case json.Number:
		i, _ := strconv.ParseInt(string(n), 10, 64)
		return i
	}
	return 0
}

// Ruby Input and String#split recognize ASCII whitespace rather than Unicode spaces.
func rtTrim(s string) string { return strings.Trim(s, " \t\r\n\v\f\x00") }
func rtWords(s string) []string {
	s = rtTrim(s)
	if s == "" {
		return []string{}
	}
	return rtRE(`[ \t\r\n\v\f]+`).Split(s, -1)
}
func rtIP(s string) (string, bool) {
	if strings.Contains(s, "/") {
		return "", false
	}
	bracketed := strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]")
	if bracketed {
		s = s[1 : len(s)-1]
	}
	if i := strings.IndexByte(s, '%'); i >= 0 {
		if !rtMatch(`^\w+$`, s[i+1:]) {
			return "", false
		}
	}
	a, e := netip.ParseAddr(s)
	if e != nil || bracketed && a.Is4() {
		return "", false
	}
	result := a.WithZone("").String()
	// IPAddr renders IPv4-compatible IPv6 suffixes in dotted decimal notation.
	if m := rtFind(`^::([\da-f]{1,4}):([\da-f]{1,4})$`, result); m != nil {
		high, _ := strconv.ParseUint(m[1], 16, 16)
		low, _ := strconv.ParseUint(m[2], 16, 16)
		result = fmt.Sprintf("::%d.%d.%d.%d", high/256, high%256, low/256, low%256)
	}
	if a.Zone() != "" {
		result += "%" + a.Zone()
	}
	return result, true
}
func rtValidIP(s string) bool { _, ok := rtIP(s); return ok }
func rtMAC(s string) string {
	s = strings.ToLower(strings.NewReplacer(".", "", ":", "", "-", "").Replace(s))
	parts := make([]string, 0, 6)
	for i := 0; i+2 <= len(s); i += 2 {
		parts = append(parts, s[i:i+2])
	}
	return strings.Join(parts, ":")
}
func rtFields(names string, values []string) vxlan.Record {
	r := vxlan.Record{}
	for i, k := range rtWords(names) {
		if i < len(values) {
			r[k] = values[i]
		}
	}
	return r
}
func rtKey(r vxlan.Record, fields []string) string {
	v := make([]any, len(fields))
	for i, k := range fields {
		v[i] = r[k]
	}
	b, _ := json.Marshal(v)
	return string(b)
}
func (p *rtParser) issue(code string) { p.issues = append(p.issues, vxlan.Record{"code": code}) }
func (p *rtParser) unparsed(n int) {
	p.issues = append(p.issues, vxlan.Record{"code": "unparsed_row", "line": n})
}
func (p *rtParser) count(expected any, observed int64) {
	if !rtEqualNumber(expected, strconv.FormatInt(observed, 10)) {
		p.issues = append(p.issues, vxlan.Record{"code": "count_mismatch", "expected": expected, "observed": observed})
	}
}
func (p *rtParser) dedup(rows []vxlan.Record, fields []string, keyFn func(vxlan.Record) string) []vxlan.Record {
	if keyFn == nil {
		keyFn = func(r vxlan.Record) string { return rtKey(r, fields) }
	}
	keys := make([]string, len(rows))
	counts := map[string]int{}
	for i, r := range rows {
		keys[i] = keyFn(r)
		counts[keys[i]]++
	}
	out := []vxlan.Record{}
	dups := 0
	for _, n := range counts {
		if n > 1 {
			dups++
		}
	}
	for i, r := range rows {
		if counts[keys[i]] == 1 {
			out = append(out, r)
		}
	}
	if dups > 0 {
		p.issues = append(p.issues, vxlan.Record{"code": "duplicate_identity", "count": dups})
	}
	return out
}

var rtIdentity = map[string][]string{"nve_peers": {"interface", "peer_ip"}, "nve_vnis": {"interface", "vni"}, "bgp_neighbors": {"vrf", "address_family", "peer_ip"}, "ospf_neighbors": {"process", "vrf", "neighbor_id", "interface"}, "interfaces": {"interface"}, "cdp_neighbors": {"device_id", "interface", "neighbor_interface"}, "port_channels": {"group"}}
var rtEmpty = map[string]string{"nve_peers": "peers", "nve_vnis": "VNIs", "bgp_neighbors": "(?:BGP )?neighbors", "ospf_neighbors": "(?:OSPF )?neighbors", "interfaces": "interfaces", "cdp_neighbors": "(?:CDP neighbors|CDP entries|neighbors|entries)", "port_channels": "port-channels", "mac_addresses": "(?:MAC addresses|entries)"}

func rtTerminalLine(text string) int {
	lines := strings.Split(text, "\n")
	for i, s := range lines {
		if rtMatch(`(?i)--[ \t]*More[ \t]*--`, s) {
			return i + 1
		}
		for j := range len(s) {
			c := s[j]
			if c < 32 && c != '\t' && (c != '\r' || j != len(s)-1 || len(lines) == 1) {
				return i + 1
			}
			if c == 127 {
				return i + 1
			}
			if c == '\r' && (j != len(s)-1 || i == len(lines)-1) {
				return i + 1
			}
		}
	}
	return 0
}

// ParseRuntime parses one NX-OS runtime dimension without accessing a transport.
func ParseRuntime(name, text string, complete bool) (vxlan.Observation, error) {
	if name == "configuration" || rtIndex(name) < 0 {
		return vxlan.Observation{}, fmt.Errorf("unsupported runtime dimension: %s", name)
	}
	p := &rtParser{name: name, rows: []vxlan.Record{}, issues: []vxlan.Record{}}
	if !utf8.ValidString(text) {
		p.issue("invalid_encoding")
		return p.result("partial"), nil
	}
	if line := rtTerminalLine(text); line > 0 {
		p.issues = append(p.issues, vxlan.Record{"code": "invalid_terminal_output", "line": line})
		return p.result("partial"), nil
	}
	if rtMatch(`(?im)^\s*(?:%\s*)?(?:Invalid (?:command|input)\b.*|(?:This command is )?not supported\.?|(?:ERROR:\s*)?Feature\b.*not enabled\.?)\s*$`, text) {
		p.issue("command_unsupported")
		return p.result("unsupported"), nil
	}
	text = strings.ReplaceAll(text, "\r", "")
	if name == "nve_peers" || name == "bgp_neighbors" {
		text = rtNormalizeWrapped(name, text)
	}
	p.content(text, complete)
	if strings.HasPrefix(name, "l2route_") {
		p.finishRoutes(complete)
	} else {
		p.finish(complete)
	}
	status := "complete"
	if len(p.issues) > 0 {
		status = "partial"
	}
	return p.result(status), nil
}
func rtIndex(name string) int {
	for i, query := range querySpecs() {
		if query.Dimension == name {
			return i
		}
	}
	return -1
}
func (p *rtParser) result(status string) vxlan.Observation {
	return observation(p.name, status, p.rows, p.issues)
}
func (p *rtParser) finish(complete bool) {
	if len(p.rows) == 0 && !p.empty {
		p.issue("missing_completeness_evidence")
	}
	if !p.header && !p.empty {
		p.issue("format_unrecognized")
	}
	if p.empty && len(p.rows) > 0 {
		p.issue("contradictory_empty")
	}
	if !complete {
		p.issue("output_incomplete")
	}
	if fields, ok := rtIdentity[p.name]; ok {
		p.rows = p.dedup(p.rows, fields, nil)
	}
}
func rtNormalizeWrapped(name, text string) string {
	lines := strings.SplitAfter(text, "\n")
	out := []string{}
	for _, line := range lines {
		tail := rtTrim(line)
		prev := ""
		if len(out) > 0 {
			prev = rtTrim(out[len(out)-1])
		}
		var join bool
		if name == "bgp_neighbors" {
			join = strings.HasSuffix(prev, "State/") && tail == "PfxRcd"
		} else {
			join = strings.HasSuffix(prev, "Route") && tail == "r-Mac" || rtMatch(`(?i)^[\da-f]{4}\.[\da-f]{4}$`, tail) && rtMatch(`(?i)^nve\d+\s+\d+(?:\.\d+){3}\s+(?:Up|Down)\s+\S+\s+\S+\s+[\da-f]{4}\.$`, prev)
		}
		if join {
			out[len(out)-1] = strings.TrimRight(out[len(out)-1], " \t\r\n") + tail + "\n"
		} else {
			out = append(out, line)
		}
	}
	return strings.Join(out, "")
}
func (p *rtParser) lines(text string, separators bool, fn func(string, int)) {
	for i, source := range strings.Split(text, "\n") {
		line := rtTrim(source)
		if line == "" || !separators && rtMatch(`^[-=+\s]+$`, line) {
			continue
		}
		if e := rtEmpty[p.name]; e != "" && rtMatch(`(?i)^(?:No `+e+`(?: found)?|0 `+e+`)\.?$`, line) {
			p.empty = true
			continue
		}
		fn(line, i+1)
	}
}
func (p *rtParser) content(text string, complete bool) {
	scoped := false
	if p.name == "bgp_neighbors" || p.name == "ospf_neighbors" {
		boundary := "BGP summary information for VRF "
		if p.name == "ospf_neighbors" {
			boundary = "OSPF Process ID "
		}
		blocks := []string{}
		start := 0
		offset := 0
		for _, line := range strings.SplitAfter(text, "\n") {
			if strings.HasPrefix(strings.TrimLeft(line, " \t\r\n"), boundary) && offset > start {
				b := text[start:offset]
				if rtTrim(b) != "" {
					blocks = append(blocks, b)
				}
				start = offset
			}
			offset += len(line)
		}
		if b := text[start:]; rtTrim(b) != "" {
			blocks = append(blocks, b)
		}
		if len(blocks) > 1 {
			scoped = true
			allComplete, allEmpty := true, true
			for _, block := range blocks {
				o, _ := ParseRuntime(p.name, block, complete)
				p.rows = append(p.rows, o.Records...)
				p.issues = append(p.issues, o.Issues...)
				allComplete = allComplete && o.Complete()
				allEmpty = allEmpty && o.Complete() && len(o.Records) == 0
			}
			p.header = allComplete || len(p.rows) > 0
			p.empty = allEmpty
		}
	}
	if !scoped {
		p.parseContent(text)
	}
	if p.name == "bgp_neighbors" {
		p.bgpIdentities(text)
	}
}
func (p *rtParser) nvePeers(text string) {
	p.lines(text, false, func(line string, n int) {
		if rtMatch(`(?i)^Interface\s+Peer-IP\s+State\s+LearnType\s+Uptime\s+Router-Mac$`, line) {
			p.header = true
			return
		}
		m := rtFind(`(?i)^(nve\d+)\s+(\d+(?:\.\d+){3})\s+(Up|Down)\s+(\S+)\s+(\S+)\s+([\da-f]{4}(?:\.[\da-f]{4}){2}|n/a)$`, line)
		if m == nil || !rtValidIP(m[2]) {
			p.unparsed(n)
			return
		}
		r := rtFields("interface peer_ip state learn_type uptime router_mac", m[1:])
		r["state"] = strings.ToLower(m[3])
		if strings.EqualFold(m[6], "n/a") {
			r["router_mac"] = nil
		}
		p.rows = append(p.rows, r)
	})
}
func (p *rtParser) nveVnis(text string) {
	p.lines(text, false, func(line string, n int) {
		if rtMatch(`(?i)^Interface\s+VNI\s+Multicast-group\s+State\s+Mode\s+Type\s+\[BD/VRF\](?:\s+Flags)?$`, line) {
			p.header = true
			return
		}
		m := rtFind(`(?i)^(nve\d+)\s+(\d+)\s+(\S+)\s+(Up|Down)\s+(\S+)\s+(L[23])\s+\[([^\]]+)\](?:\s+(\S+))?$`, line)
		if m != nil {
			vni, e := strconv.ParseInt(m[2], 10, 64)
			group := m[3] == "UnicastBGP" || m[3] == "UnicastStatic" || m[3] == "n/a"
			if a, err := netip.ParseAddr(m[3]); err == nil {
				group = a.Is4() && a.IsMulticast()
			}
			if e != nil || vni < 1 || vni > 16777215 || !group || m[8] != "" && !rtMatch(`^(?:SA|S-ND|SU|Xconn|MS-IR|HYB)$`, m[8]) {
				p.unparsed(n)
				return
			}
			r := rtFields("interface vni multicast_group state mode type association", m[1:8])
			r["vni"] = vni
			r["state"] = strings.ToLower(m[4])
			r["type"] = strings.ToLower(m[6])
			if m[8] != "" {
				r["flags"] = m[8]
			}
			p.rows = append(p.rows, r)
			return
		}
		if !rtMatch(`^(?:Codes: CP - Control Plane DP - Data Plane|UC - Unconfigured SA - Suppress ARP|S-ND - Suppress ND|SU - Suppress Unknown Unicast|Xconn - Crossconnect|MS-IR - Multisite Ingress Replication|HYB - Hybrid IRB mode)$`, strings.Join(rtWords(line), " ")) {
			p.unparsed(n)
		}
	})
}
func (p *rtParser) ospf(text string) {
	scope := vxlan.Record{}
	totals := []any{}
	p.lines(text, false, func(line string, n int) {
		if rtMatch(`(?i)^Neighbor ID\s+Pri\s+State\s+Up Time\s+Address\s+Interface$`, line) {
			p.header = true
			return
		}
		if m := rtFind(`(?i)^OSPF Process ID (\S+) VRF (\S+)$`, line); m != nil {
			scope = vxlan.Record{"process": m[1], "vrf": m[2]}
			return
		}
		if m := rtFind(`(?i)^Total number of neighbors:\s*(\d+)$`, line); m != nil {
			totals = append(totals, rtNum(m[1]))
			return
		}
		m := rtFind(`^([\d.]+)\s+(\d+)\s+(\S+(?:/\s*\S+)?)\s+(\S+)\s+([\d.]+)\s+(\S+)$`, line)
		if m == nil {
			p.unparsed(n)
			return
		}
		priority, e := strconv.ParseInt(m[2], 10, 64)
		if !rtValidIP(m[1]) || !rtValidIP(m[5]) || e != nil || priority > 255 || !rtMatch(`(?i)^(?:DOWN|ATTEMPT|INIT|2WAY|EXSTART|EXCHANGE|LOADING|FULL)/(?:\s*(?:DR|BDR|DROTHER|-))$`, m[3]) {
			p.unparsed(n)
			return
		}
		r := rtFields("neighbor_id priority state uptime address interface", m[1:])
		maps.Copy(r, scope)
		r["priority"] = priority
		r["state"] = strings.ReplaceAll(strings.ToLower(m[3]), " ", "")
		p.rows = append(p.rows, r)
	})
	for _, n := range totals {
		p.count(n, int64(len(p.rows)))
	}
	if len(p.rows) == 0 && len(totals) == 1 && rtEqualNumber(totals[0], "0") {
		p.empty = true
	}
}

func (p *rtParser) parseContent(text string) {
	switch p.name {
	case "nve_peers":
		p.nvePeers(text)
	case "nve_vnis":
		p.nveVnis(text)
	case "interfaces":
		p.interfaces(text)
	case "ospf_neighbors":
		p.ospf(text)
	case "bgp_neighbors":
		p.bgp(text)
	case "port_channels":
		p.ports(text)
	case "mac_addresses":
		p.macs(text)
	case "cdp_neighbors":
		p.cdp(text)
	case "vpc":
		p.vpc(text)
	case "l2route_macs", "l2route_mac_ips":
		p.routes(text)
	}
}

// parsedValue enforces parser-owned field types without silently accepting malformed internal state.
func parsedValue[T any](value any) T {
	result, ok := value.(T)
	if !ok {
		panic("nxos: parser field has an invalid internal type")
	}
	return result
}
