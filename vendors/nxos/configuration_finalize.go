package nxos

import (
	"strconv"
	"strings"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/internal/textparse"
)

func (s *cfgState) finalize(d vxlan.Record) {
	bgp := record.Map(d["bgp"])
	templates := record.Map(bgp["templates"])
	for _, v := range templates {
		if record.Map(v)["inherit_peer"] != nil {
			s.issues = append(s.issues, vxlan.Record{"code": "unsupported_peer_inheritance"})
			break
		}
	}
	scopes := []vxlan.Record{bgp}
	for _, k := range s.keys(record.Map(bgp["vrfs"])) {
		scopes = append(scopes, record.Map(record.Map(bgp["vrfs"])[k]))
	}
	for _, scope := range scopes {
		for _, k := range s.keys(record.Map(scope["neighbors"])) {
			v := record.Map(record.Map(scope["neighbors"])[k])
			if name, ok := v["inherit_peer"].(string); ok && templates[name] == nil {
				s.issues = append(s.issues, vxlan.Record{"code": "missing_peer_template"})
			}
		}
	}
	interfaces := record.Map(d["interfaces"])
	s.resolveUnnumbered(d, interfaces)
	enabled, disabled := record.StringSlice(d["features"]), record.StringSlice(d["disabled_features"])
	conflict := false
	for _, a := range enabled {
		for _, b := range disabled {
			if a == b {
				conflict = true
			}
		}
	}
	if conflict {
		s.issues = append(s.issues, vxlan.Record{"code": "conflicting_feature_state"})
	}
	if d["hostname"] == nil {
		s.issues = append(s.issues, vxlan.Record{"code": "hostname_missing"})
	}
	d["features"] = record.UniqueSorted(enabled)
	d["disabled_features"] = record.UniqueSorted(disabled)
	segments := []vxlan.Record{}
	for _, name := range s.keys(interfaces) {
		v := record.Map(interfaces[name])
		m := textparse.Match(`Vlan(\d+)`, name)
		if m == nil {
			continue
		}
		id, _ := strconv.Atoi(m[1])
		vni := record.Map(d["vlan_vnis"])[strconv.Itoa(id)]
		addresses := record.StringSlice(v["addresses"])
		if vni == nil || len(addresses) == 0 {
			continue
		}
		if len(addresses) != 1 || v["vrf"] == nil {
			s.issues = append(s.issues, vxlan.Record{"code": "unsupported_svi", "interface": name})
			continue
		}
		segments = append(segments, vxlan.Record{"vlan_id": id, "vni": vni, "vrf": v["vrf"], "prefix": cfgPrefix(addresses[0], "ipv4", false), "gateway": strings.Split(addresses[0], "/")[0], "anycast": v["anycast"], "acl_bindings": v["acl_bindings"]})
	}
	d["segments"] = segments
}

func (s *cfgState) resolveUnnumbered(d, interfaces vxlan.Record) {
	for _, name := range s.keys(interfaces) {
		v := record.Map(interfaces[name])
		src, ok := v["unnumbered_interface"].(string)
		if !ok {
			continue
		}
		matches := []vxlan.Record{}
		for n, x := range interfaces {
			if strings.EqualFold(n, src) {
				matches = append(matches, record.Map(x))
			}
		}
		valid := false
		if len(matches) == 1 {
			source := matches[0]
			a := record.StringSlice(source["addresses"])
			vrf := v["vrf"]
			if vrf == nil {
				vrf = "default"
			}
			sv := source["vrf"]
			if sv == nil {
				sv = "default"
			}
			if len(a) == 1 && len(record.StringSlice(v["addresses"])) == 0 && source["unnumbered_interface"] == nil && vrf == sv {
				record.Map(d["unnumbered_addresses"])[name] = []string{strings.Split(a[0], "/")[0] + "/32"}
				valid = true
			}
		}
		if !valid {
			s.issues = append(s.issues, vxlan.Record{"code": "unresolved_unnumbered_interface", "interface": name})
		}
	}
}
