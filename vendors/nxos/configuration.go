package nxos

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/configuration"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/internal/textparse"
)

type cfgBlock struct {
	text               string
	line, indent, last int
	children           []*cfgBlock
}
type cfgState struct {
	document      *ConfigurationDocument
	current       *cfgBlock
	invalidSource *cfgBlock
	path          []any
	sources       map[string]*cfgBlock
	policies      map[string]*cfgBlock
	features      []cfgFeatureSource
	issues        []vxlan.Record
	seen          map[string]bool
	assigned      map[string]bool
	conflicts     int
	orders        map[string][]string
}

func cfgInt(s string, minimum, maximum int) int {
	n, e := strconv.Atoi(s)
	if e != nil || n < minimum || n > maximum {
		panic("invalid_configuration_value")
	}
	return n
}

func cfgIP(v string) string {
	a, e := netip.ParseAddr(v)
	if e != nil {
		panic("invalid_configuration_value")
	}
	return a.String()
}
func cfgPrefix(v, family string, host bool) string {
	p, e := netip.ParsePrefix(v)
	if e != nil || (family == "ipv4" && !p.Addr().Is4()) || (family == "ipv6" && !p.Addr().Is6()) {
		panic("invalid_configuration_value")
	}
	if !host {
		p = p.Masked()
	}
	return p.String()
}
func cfgMulticast(v string) string {
	s := cfgIP(v)
	a, _ := netip.ParseAddr(s)
	if !a.Is4() || !a.IsMulticast() {
		panic("invalid_configuration_value")
	}
	return s
}
func (s *cfgState) issue(b *cfgBlock, code string) {
	s.issues = append(s.issues, vxlan.Record{"code": code, "line": b.line})
	state := LineInvalid
	if code == "unsupported_configuration" {
		state = LineUnsupported
	}
	source := b
	if code == "invalid_configuration_value" && s.invalidSource != nil {
		source = s.invalidSource
	}
	s.mark(source, state)
}
func (s *cfgState) assign(m vxlan.Record, k string, v any, b *cfgBlock) {
	id := fmt.Sprintf("%p:%s", m, k)
	if s.assigned[id] && !reflect.DeepEqual(m[k], v) {
		delete(m, k)
		s.mark(s.sources[id], LineInvalid)
		s.conflicts++
		s.issue(b, "conflicting_configuration_value")
		return
	}
	s.assigned[id] = true
	if s.sources[id] == nil {
		s.sources[id] = b
	}
	m[k] = v
}
func (s *cfgState) store(m vxlan.Record, k string, b *cfgBlock, code string, path []any, fn func() any) {
	id := fmt.Sprintf("%p:%s", m, k)
	if s.seen[id] {
		delete(m, k)
		s.mark(s.sources[id], LineInvalid)
		s.conflicts++
		s.issue(b, code)
		return
	}
	s.seen[id] = true
	s.sources[id] = b
	identity := fmt.Sprintf("%p", m)
	s.orders[identity] = append(s.orders[identity], k)
	m[k] = s.scope(b, path, fn)
}
func (s *cfgState) leaf(b *cfgBlock) {
	for _, ch := range b.children {
		s.unhandled(ch)
	}
}

var cfgModeled = regexp.MustCompile(`^(?:no )?(?:hostname|interface|vlan|vrf|router|vpc|evpn|feature|object-group|ip address|ip router ospf|ip access-group|ip prefix-list|ipv6 prefix-list|ip access-list|route-map|vn-segment|member vni|route-target|channel-group|fabric forwarding|mtu|ip unnumbered|ip ospf network|switchport mode|switchport access vlan|ip forward|ipv6 address)\b`)

func (s *cfgState) unhandled(b *cfgBlock) {
	if cfgModeled.MatchString(b.text) {
		s.issue(b, "unsupported_configuration")
	} else {
		s.mark(b, LineIgnored)
	}
	for _, ch := range b.children {
		s.unhandled(ch)
	}
}
func (s *cfgState) ignore(b *cfgBlock) {
	s.mark(b, LineIgnored)
	var visit func(*cfgBlock)
	visit = func(c *cfgBlock) {
		s.issue(c, "unsupported_configuration")
		for _, x := range c.children {
			s.enter(x)
			visit(x)
		}
	}
	for _, c := range b.children {
		s.enter(c)
		visit(c)
	}
}
func cfgDocument(text string, document *ConfigurationDocument) ([]*cfgBlock, []vxlan.Record, string) {
	if document == nil {
		document = newConfigurationDocument(text)
	}
	roots := []*cfgBlock{}
	stack := []*cfgBlock{}
	issues := []vxlan.Record{}
	digest := []string{}
	banner := ""
	for i, source := range document.lines {
		raw := strings.TrimRight(source.raw, "\r\n")
		line := strings.Trim(raw, " \t\r\n\v\f\x00")
		if line != "" && !strings.HasPrefix(line, "!") {
			digest = append(digest, strings.TrimRight(raw, " \t\r\n\v\f\x00"))
		}
		if banner != "" {
			document.states[i] = LineIgnored
			if strings.Contains(line, banner) {
				banner = ""
			}
			continue
		}
		if m := textparse.Match(`(?:banner\s+\S+|header\s+\S+(?:\s+information)?)\s+(.+)`, line); m != nil {
			document.states[i] = LineIgnored
			banner = cfgBannerDelimiter(m[1])
			continue
		}
		if regexp.MustCompile(`(?i)--[ \t]*More[ \t]*--|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`).MatchString(raw) {
			document.states[i] = LineInvalid
			issues = append(issues, vxlan.Record{"code": "incomplete_configuration", "line": i + 1})
			continue
		}
		if line == "" || strings.HasPrefix(line, "!") {
			document.states[i] = LineIgnored
			continue
		}
		if line == "end" {
			document.states[i] = LineIgnored
			for _, b := range stack {
				b.last = i
			}
			stack = nil
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		b := &cfgBlock{text: line, line: i + 1, indent: indent}
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack[len(stack)-1].last = i
			stack = stack[:len(stack)-1]
		}
		if len(stack) == 0 {
			roots = append(roots, b)
		} else {
			p := stack[len(stack)-1]
			p.children = append(p.children, b)
		}
		stack = append(stack, b)
	}
	for _, b := range stack {
		b.last = document.Size()
	}
	if banner != "" {
		issues = append(issues, vxlan.Record{"code": "incomplete_banner"})
	}
	return roots, issues, fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(digest, "\n"))))
}

// ParseConfig returns configuration facts; complete describes the transport only.
// Invalid UTF-8 or NUL input returns partial diagnostics. Use ParseConfigChecked
// or ConfigurationParser.Parse when invalid input must return an error.
func ParseConfig(text string, complete bool) vxlan.Observation {
	if err := validateConfigInput(text); err != nil {
		code := "invalid_configuration_input"
		if strings.Contains(err.Error(), "UTF-8") {
			code = "invalid_encoding"
		}
		return observation("configuration", "partial", nil, []vxlan.Record{{"code": code}})
	}
	return parseConfig(text, complete, nil)
}
func parseConfig(text string, complete bool, document *ConfigurationDocument) vxlan.Observation {
	s := &cfgState{document: document, sources: map[string]*cfgBlock{}, policies: map[string]*cfgBlock{}, issues: []vxlan.Record{}, seen: map[string]bool{}, assigned: map[string]bool{}, orders: map[string][]string{}}
	d := vxlan.Record{"hostname": nil, "features": []string{}, "disabled_features": []string{}, "breakouts": vxlan.Record{}, "interfaces": vxlan.Record{}, "vlan_vnis": vxlan.Record{}, "vrfs": vxlan.Record{}, "nve": vxlan.Record{"members": vxlan.Record{}}, "evpn": vxlan.Record{}, "bgp": vxlan.Record{}, "ospf": vxlan.Record{}, "vpc_domain": nil, "unnumbered_addresses": vxlan.Record{}, "prefix_lists": vxlan.Record{}, "ipv6_prefix_lists": vxlan.Record{}, "route_maps": vxlan.Record{}, "acls": vxlan.Record{}, "address_groups": vxlan.Record{}, "static_routes": []vxlan.Record{}}
	blocks, issues, digest := cfgDocument(text, document)
	for _, b := range blocks {
		s.block(b, d)
	}
	s.issues = append(s.issues, issues...)
	s.finalize(d)
	s.finishSources(d, blocks)
	d["config_digest"] = digest
	if ops := extractOperations(blocks); ops != nil {
		d["operations"] = ops
	}
	if !complete {
		s.issues = append(s.issues, vxlan.Record{"code": "output_incomplete"})
	}
	status := "complete"
	if len(s.issues) > 0 {
		status = "partial"
	}
	d["review_status"] = status
	d["review_findings"] = configuration.ReviewOrdered(d, status == "complete", s.keys(record.Map(d["vrfs"])))
	return observation("configuration", status, []vxlan.Record{d}, s.issues)
}
func (s *cfgState) block(b *cfgBlock, d vxlan.Record) {
	s.enter(b)
	defer s.recoverBlock(b)
	t := b.text
	if m := textparse.Match(`hostname (\S+)`, t); m != nil {
		s.global(d, "hostname", nil, b, "duplicate_hostname", func() any { return m[1] })
		s.leaf(b)
	} else if m = textparse.Match(`(no )?feature (.+)`, t); m != nil {
		k := "features"
		if m[1] != "" {
			k = "disabled_features"
		}
		d[k] = append(record.StringSlice(d[k]), m[2])
		s.features = append(s.features, cfgFeatureSource{collection: k, name: m[2], block: b})
		s.leaf(b)
	} else if m = textparse.Match(`interface breakout module (\d+) port (\d+) map (\d+g-\d+x)`, t); m != nil {
		a, c := cfgInt(m[1], 1, 65535), cfgInt(m[2], 1, 65535)
		s.store(record.Map(d["breakouts"]), fmt.Sprintf("%d/%d", a, c), b, "duplicate_identity", []any{"breakouts", fmt.Sprintf("%d/%d", a, c)}, func() any { return vxlan.Record{"module_id": a, "port": c, "map": m[3]} })
		s.leaf(b)
	} else if m = textparse.Match(`interface (\S+)`, t); m != nil {
		s.blockInterface(b, d, m[1])
	} else if m = textparse.Match(`vlan ([\d,-]+)`, t); m != nil {
		s.blockVLAN(b, d, m[1])
	} else if m = textparse.Match(`vrf context (\S+)`, t); m != nil {
		s.store(record.Map(d["vrfs"]), m[1], b, "duplicate_identity", []any{"vrfs", m[1]}, func() any { return s.vrf(b, true) })
	} else if t == "evpn" {
		s.blockEVPN(b, d)
	} else if m = textparse.Match(`vpc domain (\d+)`, t); m != nil {
		s.global(d, "vpc_domain", nil, b, "duplicate_vpc_domain", func() any { id := cfgInt(m[1], 1, 1000); v := s.vpc(b); v["id"] = id; return v })
	} else if m = textparse.Match(`router bgp (\d+)`, t); m != nil {
		s.global(d, "bgp", vxlan.Record{}, b, "duplicate_bgp_process", func() any {
			asn := cfgInt(m[1], 1, 4294967295)
			v := s.routing(b, "bgp", "process", "", "")
			v["asn"] = asn
			return v
		})
	} else if m = textparse.Match(`router ospf (\S+)`, t); m != nil {
		s.store(record.Map(d["ospf"]), m[1], b, "duplicate_identity", []any{"ospf", m[1]}, func() any { return s.routing(b, "ospf", "process", "", "") })
	} else if strings.HasPrefix(t, "ip prefix-list ") || strings.HasPrefix(t, "ipv6 prefix-list ") {
		s.prefixList(b, d)
	} else if m = textparse.Match(`route-map (\S+) (permit|deny) (\d+)`, t); m != nil {
		s.policy(d, "route_maps", m[1], cfgInt(m[3], 1, 65535), b, func() vxlan.Record {
			v := s.routeMap(b)
			v["action"] = m[2]
			v["sequence"] = cfgInt(m[3], 1, 65535)
			return v
		})
	} else if m = textparse.Match(`object-group ip address (\S+)`, t); m != nil {
		s.store(record.Map(d["address_groups"]), m[1], b, "duplicate_identity", []any{"address_groups", m[1]}, func() any { return s.addressGroup(b) })
	} else if m = textparse.Match(`ip access-list (\S+)`, t); m != nil {
		s.blockACL(b, d, m[1])
	} else if strings.HasPrefix(t, "ip route ") {
		value := s.scope(b, []any{"static_routes", len(record.Rows(d["static_routes"]))}, func() any { return s.staticRoute(b) })
		route, ok := value.(vxlan.Record)
		if !ok {
			panic("nxos: route scope returned an invalid type")
		}
		d["static_routes"] = append(record.Rows(d["static_routes"]), route)
		s.leaf(b)
	} else if t == "nv overlay evpn" || t == "no nv overlay evpn" {
		s.assign(d, "nv_overlay_evpn", t == "nv overlay evpn", b)
		if value, ok := d["nv_overlay_evpn"]; ok {
			s.capture(b, value, []any{"nv_overlay_evpn"})
		}
		s.leaf(b)
	} else if m = textparse.Match(`fabric forwarding anycast-gateway-mac (\S+)`, t); m != nil {
		s.blockAnycastMAC(b, d, m[1])
	} else if regexp.MustCompile(`^(?:interface|vlan|vrf|router|vpc|evpn|feature|ip prefix-list|ipv6 prefix-list|route-map)\b`).MatchString(t) {
		s.issue(b, "unsupported_configuration")
	} else if regexp.MustCompile(`(?i)^(?:%|ERROR:|Invalid command|--More--)`).MatchString(t) {
		s.issue(b, "invalid_command_output")
	} else {
		s.unhandled(b)
	}
}
func (s *cfgState) global(d vxlan.Record, k string, empty any, b *cfgBlock, code string, fn func() any) {
	id := "global:" + k
	if s.seen[id] {
		d[k] = empty
		s.mark(s.sources[id], LineInvalid)
		s.conflicts++
		s.issue(b, code)
		return
	}
	s.seen[id] = true
	s.sources[id] = b
	d[k] = s.scope(b, []any{k}, fn)
}

func (s *cfgState) keys(m vxlan.Record) []string {
	out := []string{}
	for _, k := range s.orders[fmt.Sprintf("%p", m)] {
		if _, ok := m[k]; ok {
			out = append(out, k)
		}
	}
	return out
}

func (s *cfgState) blockInterface(b *cfgBlock, d vxlan.Record, name string) {
	if strings.HasPrefix(strings.ToLower(name), "vlan") {
		name = "Vlan" + name[4:]
	}
	if textparse.Match(`(?i)nve\d+`, name) != nil {
		s.global(d, "nve", vxlan.Record{"members": vxlan.Record{}}, b, "multiple_nve_interfaces", func() any { v := s.nve(b); v["interface"] = name; return v })
	} else {
		dest := record.Map(d["interfaces"])
		s.store(dest, name, b, "duplicate_identity", []any{"interfaces", name}, func() any { return s.iface(b) })
		v := record.Map(dest[name])
		if s.assigned[fmt.Sprintf("%p:vrf", v)] && v["vrf"] == nil {
			delete(dest, name)
			s.conflicts++
			s.issue(b, "conflicting_configuration_value")
		}
	}
}

func (s *cfgState) blockVLAN(b *cfgBlock, d vxlan.Record, name string) {
	ids := cfgVLANIDs(name)
	if len(b.children) == 0 {
		return
	}
	maps := []*cfgBlock{}
	for _, c := range b.children {
		if strings.HasPrefix(c.text, "vn-segment") {
			maps = append(maps, c)
		}
	}
	for _, id := range ids {
		s.store(record.Map(d["vlan_vnis"]), strconv.Itoa(id), b, "duplicate_identity", []any{"vlan_vnis", strconv.Itoa(id)}, func() any {
			if len(maps) > 1 {
				panic("invalid_configuration_value")
			}
			if len(maps) == 0 {
				return nil
			}
			s.enter(maps[0])
			v := cfgInt(strings.TrimPrefix(maps[0].text, "vn-segment "), 1, 16777215)
			s.leaf(maps[0])
			if len(ids) != 1 {
				s.current = b
				panic("invalid_configuration_value")
			}
			return v
		})
	}
	for _, c := range b.children {
		if !strings.HasPrefix(c.text, "vn-segment") {
			s.ignore(c)
		}
	}
}

func (s *cfgState) blockACL(b *cfgBlock, d vxlan.Record, name string) {
	rows := []vxlan.Record{}
	seq := map[int]bool{}
	for _, c := range b.children {
		s.enter(c)
		if textparse.Match(`(?:(?:\d+ )?remark\b.*|statistics per-entry)`, c.text) != nil {
			s.ignore(c)
			continue
		}
		x := textparse.Match(`(\d+) (permit|deny) (.+)`, c.text)
		if x == nil {
			s.issue(c, "unsupported_configuration")
			continue
		}
		n := cfgInt(x[1], 1, 4294967295)
		seq[n] = true
		rows = append(rows, vxlan.Record{"sequence": n, "action": x[2], "expression": x[3]})
		s.leaf(c)
	}
	s.store(record.Map(d["acls"]), name, b, "duplicate_identity", []any{"acls", name}, func() any {
		s.current = b
		if len(seq) != len(rows) {
			panic("invalid_configuration_value")
		}
		return rows
	})
}

func (s *cfgState) blockEVPN(b *cfgBlock, d vxlan.Record) {
	for _, c := range b.children {
		s.enter(c)
		m := textparse.Match(`(?i)vni (\d+) (l[23])`, c.text)
		if m == nil {
			s.issue(c, "unsupported_configuration")
			continue
		}
		id := cfgInt(m[1], 1, 16777215)
		s.store(record.Map(d["evpn"]), strconv.Itoa(id), c, "duplicate_identity", []any{"evpn", strconv.Itoa(id)}, func() any { v := s.vrf(c, false); v["type"] = strings.ToLower(m[2]); return v })
	}
}

func cfgVLANIDs(value string) []int {
	ids := []int{}
	for part := range strings.SplitSeq(value, ",") {
		a := strings.Split(part, "-")
		first := cfgInt(a[0], 1, 4094)
		last := first
		if len(a) == 2 {
			last = cfgInt(a[1], first, 4094)
		} else if len(a) != 1 {
			panic("invalid_configuration_value")
		}
		for n := first; n <= last; n++ {
			found := false
			for _, x := range ids {
				if x == n {
					found = true
				}
			}
			if !found {
				ids = append(ids, n)
			}
		}
	}
	return ids
}

func cfgBannerDelimiter(value string) string {
	runes := []rune(value)
	d := string(runes[:1])
	if strings.HasPrefix(value, "^") && len(runes) >= 2 {
		d = string(runes[:2])
	}
	if !strings.Contains(strings.TrimPrefix(value, d), d) {
		return d
	}
	return ""
}

func (s *cfgState) recoverBlock(b *cfgBlock) {
	if r := recover(); r != nil {
		if r != "invalid_configuration_value" {
			panic(r)
		}
		s.issues = append(s.issues, vxlan.Record{"code": "invalid_configuration_value", "line": b.line})
		s.invalidSource = s.current
		s.mark(s.current, LineInvalid)
	}
}

func (s *cfgState) blockAnycastMAC(b *cfgBlock, d vxlan.Record, mac string) {
	if textparse.Match(`(?i)(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}|(?:[0-9a-f]{4}-){2}[0-9a-f]{4}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|(?:[0-9a-f]{2}-){5}[0-9a-f]{2}|[0-9a-f]{12}`, mac) == nil {
		panic("invalid_configuration_value")
	}
	s.assign(d, "anycast_mac", mac, b)
	if value, ok := d["anycast_mac"]; ok {
		s.capture(b, value, []any{"anycast_mac"})
	}
	s.leaf(b)
}
