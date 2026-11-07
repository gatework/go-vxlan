package vxlan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func (s *cfgState) finalize(d Record) {
	bgp := cfgMap(d["bgp"])
	templates := cfgMap(bgp["templates"])
	for _, v := range templates {
		if cfgMap(v)["inherit_peer"] != nil {
			s.issues = append(s.issues, Record{"code": "unsupported_peer_inheritance"})
			break
		}
	}
	scopes := []Record{bgp}
	for _, k := range s.keys(cfgMap(bgp["vrfs"])) {
		scopes = append(scopes, cfgMap(cfgMap(bgp["vrfs"])[k]))
	}
	for _, scope := range scopes {
		for _, k := range s.keys(cfgMap(scope["neighbors"])) {
			v := cfgMap(cfgMap(scope["neighbors"])[k])
			if name, ok := v["inherit_peer"].(string); ok && templates[name] == nil {
				s.issues = append(s.issues, Record{"code": "missing_peer_template"})
			}
		}
	}
	interfaces := cfgMap(d["interfaces"])
	for _, name := range s.keys(interfaces) {
		v := cfgMap(interfaces[name])
		src, ok := v["unnumbered_interface"].(string)
		if !ok {
			continue
		}
		matches := []Record{}
		for n, x := range interfaces {
			if strings.EqualFold(n, src) {
				matches = append(matches, cfgMap(x))
			}
		}
		valid := false
		if len(matches) == 1 {
			source := matches[0]
			a := cfgStrings(source["addresses"])
			vrf := v["vrf"]
			if vrf == nil {
				vrf = "default"
			}
			sv := source["vrf"]
			if sv == nil {
				sv = "default"
			}
			if len(a) == 1 && len(cfgStrings(v["addresses"])) == 0 && source["unnumbered_interface"] == nil && vrf == sv {
				cfgMap(d["unnumbered_addresses"])[name] = []string{strings.Split(a[0], "/")[0] + "/32"}
				valid = true
			}
		}
		if !valid {
			s.issues = append(s.issues, Record{"code": "unresolved_unnumbered_interface", "interface": name})
		}
	}
	enabled, disabled := cfgStrings(d["features"]), cfgStrings(d["disabled_features"])
	conflict := false
	for _, a := range enabled {
		for _, b := range disabled {
			if a == b {
				conflict = true
			}
		}
	}
	if conflict {
		s.issues = append(s.issues, Record{"code": "conflicting_feature_state"})
	}
	if d["hostname"] == nil {
		s.issues = append(s.issues, Record{"code": "hostname_missing"})
	}
	d["features"] = cfgUniqueSorted(enabled)
	d["disabled_features"] = cfgUniqueSorted(disabled)
	segments := []Record{}
	for _, name := range s.keys(interfaces) {
		v := cfgMap(interfaces[name])
		m := cfgMatch(`Vlan(\d+)`, name)
		if m == nil {
			continue
		}
		id, _ := strconv.Atoi(m[1])
		vni := cfgMap(d["vlan_vnis"])[strconv.Itoa(id)]
		addresses := cfgStrings(v["addresses"])
		if vni == nil || len(addresses) == 0 {
			continue
		}
		if len(addresses) != 1 || v["vrf"] == nil {
			s.issues = append(s.issues, Record{"code": "unsupported_svi", "interface": name})
			continue
		}
		segments = append(segments, Record{"vlan_id": id, "vni": vni, "vrf": v["vrf"], "prefix": cfgPrefix(addresses[0], "ipv4", false), "gateway": strings.Split(addresses[0], "/")[0], "anycast": v["anycast"], "acl_bindings": v["acl_bindings"]})
	}
	d["segments"] = segments
}
func cfgUniqueSorted(x []string) []string {
	m := map[string]bool{}
	for _, v := range x {
		m[v] = true
	}
	out := []string{}
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// ConfigReview checks associations only when configuration evidence is complete.
func ConfigReview(d Record, complete bool) []Record {
	return configReviewOrdered(d, complete, cfgKeys(cfgMap(d["vrfs"])))
}
func configReviewOrdered(d Record, complete bool, vrfOrder []string) []Record {
	out := []Record{}
	if !complete {
		return out
	}
	members := cfgMap(cfgMap(d["nve"])["members"])
	mappings := map[string][]int{}
	for vlan, vni := range cfgMap(d["vlan_vnis"]) {
		if vni == nil {
			continue
		}
		key := fmt.Sprint(vni)
		id, _ := strconv.Atoi(vlan)
		mappings[key] = append(mappings[key], id)
	}
	vrfs := cfgMap(d["vrfs"])
	vrfVNIs := map[string]bool{}
	for _, v := range vrfs {
		if n := cfgMap(v)["vni"]; n != nil {
			vrfVNIs[fmt.Sprint(n)] = true
		}
	}
	evpn := cfgMap(d["evpn"])
	for k, ids := range mappings {
		if members[k] == nil {
			sort.Ints(ids)
			n, _ := strconv.Atoi(k)
			out = append(out, Record{"code": "vlan_vni_without_nve", "vni": n, "vlan_ids": ids})
		}
	}
	for k, value := range members {
		v := cfgMap(value)
		n, _ := strconv.Atoi(k)
		if v["associate_vrf"] == true {
			if !vrfVNIs[k] {
				out = append(out, Record{"code": "nve_l3_without_vrf", "vni": n})
			}
			continue
		}
		if _, ok := mappings[k]; !ok {
			out = append(out, Record{"code": "nve_l2_without_vlan", "vni": n})
		}
		if d["nv_overlay_evpn"] == true && evpn[k] == nil {
			out = append(out, Record{"code": "nve_l2_without_evpn", "vni": n})
		}
	}
	for k, value := range evpn {
		n, _ := strconv.Atoi(k)
		v := cfgMap(value)
		if members[k] == nil {
			out = append(out, Record{"code": "evpn_vni_without_nve", "vni": n})
		} else if (v["type"] == "l3") != (cfgMap(members[k])["associate_vrf"] == true) {
			out = append(out, Record{"code": "vni_layer_conflict", "vni": n, "evpn_type": v["type"]})
		}
	}
	for _, name := range vrfOrder {
		value := vrfs[name]
		v := cfgMap(value)
		if v["vni"] == nil {
			continue
		}
		member, ok := members[fmt.Sprint(v["vni"])]
		code := ""
		if !ok {
			code = "l3_vni_without_nve"
		} else if cfgMap(member)["associate_vrf"] != true {
			code = "vni_layer_conflict"
		}
		if code != "" {
			out = append(out, Record{"code": code, "vni": v["vni"], "vrf": name})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := cfgNumber(out[i]["vni"]), cfgNumber(out[j]["vni"])
		if a != b {
			return a < b
		}
		return fmt.Sprint(out[i]["code"]) < fmt.Sprint(out[j]["code"])
	})
	return out
}
func cfgNumber(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case int64:
		return int(n)
	default:
		i, _ := strconv.Atoi(fmt.Sprint(v))
		return i
	}
}
