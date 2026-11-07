package vxlan

import (
	"fmt"
	"sort"
	"strconv"
)

// ServiceCatalog includes partially deployed L2 services across VLAN/NVE/EVPN.
func ServiceCatalog(configs Record) map[int][]Record {
	return serviceCatalog(configs, cfgKeys(configs))
}
func serviceCatalog(configs Record, hosts []string) map[int][]Record {
	result := map[int][]Record{}
	for _, host := range hosts {
		config := cfgMap(configs[host])
		mappings := cfgMap(config["vlan_vnis"])
		nve := cfgMap(cfgMap(config["nve"])["members"])
		evpn := cfgMap(config["evpn"])
		l3 := map[int]bool{}
		l2 := map[int]bool{}
		for _, v := range cfgMap(config["vrfs"]) {
			if n := cfgMap(v)["vni"]; n != nil {
				l3[cfgNumber(n)] = true
			}
		}
		for k, v := range evpn {
			switch cfgMap(v)["type"] {
			case "l2":
				l2[cfgNumber(k)] = true
			case "l3":
				l3[cfgNumber(k)] = true
			}
		}
		for k, v := range nve {
			if domainTruthy(cfgMap(v)["associate_vrf"]) {
				l3[cfgNumber(k)] = true
			} else {
				l2[cfgNumber(k)] = true
			}
		}
		vnis := map[int]bool{}
		for _, vni := range mappings {
			if vni != nil && !l3[cfgNumber(vni)] {
				vnis[cfgNumber(vni)] = true
			}
		}
		for n := range l2 {
			vnis[n] = true
		}
		// Build the reverse association once per device, as the source catalog
		// does; sorting and scanning every VLAN for every VNI is quadratic.
		mappingsByVNI := map[int][]any{}
		for _, vlan := range domainNaturalKeys(mappings) {
			mapped := mappings[vlan]
			vni := cfgNumber(mapped)
			if domainEq(mapped, vni) {
				mappingsByVNI[vni] = append(mappingsByVNI[vni], vlan)
			}
		}
		ids := []int{}
		for n := range vnis {
			ids = append(ids, n)
		}
		sort.Ints(ids)
		for _, vni := range ids {
			vlans := mappingsByVNI[vni]
			if len(vlans) == 0 {
				vlans = append(vlans, nil)
			}
			for _, vlan := range vlans {
				member := nve[strconv.Itoa(vni)]
				control := evpn[strconv.Itoa(vni)]
				missing := []string{}
				if vlan == nil {
					missing = append(missing, "VLAN")
				}
				if member == nil {
					missing = append(missing, "NVE")
				} else if domainTruthy(cfgMap(member)["associate_vrf"]) {
					missing = append(missing, "NVE L2")
				}
				if domainTruthy(config["nv_overlay_evpn"]) && control == nil {
					missing = append(missing, "EVPN")
				}
				if control != nil && cfgMap(control)["type"] != "l2" {
					missing = append(missing, "EVPN L2")
				}
				var svi any
				if vlan != nil {
					svi = cfgMap(config["interfaces"])["Vlan"+domainString(vlan)]
				}
				result[vni] = append(result[vni], Record{"host": host, "config": config, "vlan": vlan, "svi": svi, "nve": member, "evpn": control, "missing": missing})
			}
		}
	}
	return result
}
func domainNaturalKeys(m Record) []string {
	keys := cfgKeys(m)
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		prefixA, prefixB := a, b
		for len(prefixA) > 0 && prefixA[len(prefixA)-1] >= '0' && prefixA[len(prefixA)-1] <= '9' {
			prefixA = prefixA[:len(prefixA)-1]
		}
		for len(prefixB) > 0 && prefixB[len(prefixB)-1] >= '0' && prefixB[len(prefixB)-1] <= '9' {
			prefixB = prefixB[:len(prefixB)-1]
		}
		if prefixA == prefixB && prefixA != a && prefixB != b {
			return cfgNumber(a[len(prefixA):]) < cfgNumber(b[len(prefixB):])
		}
		return a < b
	})
	return keys
}

// EffectiveNVEMember resolves global multicast inheritance only when appropriate.
func EffectiveNVEMember(config, member Record) Record {
	if member == nil {
		return nil
	}
	inherited := cfgMap(config["nve"])["multicast_group"]
	if domainTruthy(inherited) && !domainTruthy(member["replication"]) && !domainTruthy(member["multicast_group"]) && !domainTruthy(member["associate_vrf"]) {
		return domainMerge(member, Record{"multicast_group": inherited})
	}
	return member
}

// ServiceRouteTargets expands both directions and two-byte ASN auto targets.
func ServiceRouteTargets(entries any, asn, vni any) []any {
	out := []any{}
	for _, entry := range cfgRows(entries) {
		directions := []any{entry["direction"]}
		if entry["direction"] == "both" {
			directions = []any{"import", "export"}
		}
		for _, direction := range directions {
			target := entry["target"]
			if target == "auto" {
				if domainInteger(asn, 1, 65535) {
					target = fmt.Sprintf("%d:%d", cfgNumber(asn), cfgNumber(vni))
				} else {
					target = []any{"auto", asn, vni}
				}
			}
			evpn := entry["evpn"]
			if _, ok := entry["evpn"]; !ok {
				evpn = false
			}
			out = append(out, []any{entry["address_family"], evpn, direction, target})
		}
	}
	out = domainUniq(out)
	sort.SliceStable(out, func(i, j int) bool { return string(domainJSON(out[i])) < string(domainJSON(out[j])) })
	return out
}

// ServiceTenant compares tenant VNI and route-target declarations.
func ServiceTenant(config Record, name string) Record {
	vrf, ok := cfgMap(config["vrfs"])[name].(map[string]any)
	if !ok {
		return nil
	}
	return Record{"vrf": name, "vni": vrf["vni"], "route_targets": ServiceRouteTargets(vrf["route_targets"], cfgMap(config["bgp"])["asn"], vrf["vni"])}
}

// ServiceMappingSignature binds gateway identity and resolved ACL dependencies.
func ServiceMappingSignature(config, svi Record) Record {
	if !domainTruthy(svi["anycast"]) || !domainTruthy(svi["vrf"]) || len(cfgStrings(svi["addresses"])) != 1 || !domainTruthy(config["anycast_mac"]) {
		return nil
	}
	policies := Record{}
	bindings := cfgMap(svi["acl_bindings"])
	for direction, name := range bindings {
		policy := ResolveACLPolicy(config, cfgMap(config["acls"])[domainString(name)])
		if policy == nil {
			return nil
		}
		policies[direction] = policy
	}
	return domainMerge(domainSlice(svi, "addresses", "vrf", "anycast", "shutdown", "mtu"), Record{"anycast_mac": config["anycast_mac"], "policies": policies})
}
func serviceMappingTransport(vni int, row Record, donors []Record) bool {
	values := []any{}
	peers := append([]Record{row}, donors...)
	for _, peer := range peers {
		if peer["nve"] == nil || peer["evpn"] == nil {
			return false
		}
		config := cfgMap(peer["config"])
		vrf := cfgMap(peer["svi"])["vrf"]
		if vrf == nil {
			vrf = cfgMap(donors[0]["svi"])["vrf"]
		}
		values = append(values, []any{EffectiveNVEMember(config, cfgMap(peer["nve"])), cfgMap(peer["evpn"])["type"], ServiceRouteTargets(cfgMap(peer["evpn"])["route_targets"], cfgMap(config["bgp"])["asn"], vni), ServiceTenant(config, domainString(vrf))})
	}
	return len(domainUniq(values)) == 1
}

// InferServiceMapping requires unique complete donors and an existing unmapped VLAN.
func InferServiceMapping(vni int, row Record, peers []Record) *ChangePlan {
	seen := map[string]bool{}
	donors := []Record{}
	for _, peer := range peers {
		host := domainString(peer["host"])
		if seen[host] {
			return nil
		}
		seen[host] = true
		if peer["host"] != row["host"] {
			if len(cfgStrings(peer["missing"])) != 0 || peer["svi"] == nil {
				return nil
			}
			donors = append(donors, peer)
		}
	}
	if len(donors) == 0 {
		return nil
	}
	signatures := []any{}
	for _, peer := range donors {
		signatures = append(signatures, ServiceMappingSignature(cfgMap(peer["config"]), cfgMap(peer["svi"])))
	}
	unique := domainUniq(signatures)
	if len(unique) != 1 || cfgMap(unique[0]) == nil || len(cfgMap(unique[0])) == 0 || !serviceMappingTransport(vni, row, donors) {
		return nil
	}
	expected := cfgMap(unique[0])
	config := cfgMap(row["config"])
	matches := []string{}
	for vlan, mapped := range cfgMap(config["vlan_vnis"]) {
		if mapped == nil {
			svi, ok := cfgMap(config["interfaces"])["Vlan"+vlan].(map[string]any)
			if ok && domainEq(ServiceMappingSignature(config, svi), expected) {
				matches = append(matches, vlan)
			}
		}
	}
	if len(matches) != 1 {
		return nil
	}
	return CandidateChangePlan(Record{"kind": "vlan_vni_add", "vlan": cfgNumber(matches[0]), "vni": vni, "vrf": expected["vrf"], "address": cfgStrings(expected["addresses"])[0]}, config)
}
