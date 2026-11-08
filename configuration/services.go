package configuration

import (
	"fmt"
	"sort"
	"strconv"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

func ServiceCatalog(configs vxlan.Record) map[int][]vxlan.Record {
	return CatalogForHosts(configs, record.Keys(configs))
}
func CatalogForHosts(configs vxlan.Record, hosts []string) map[int][]vxlan.Record {
	result := map[int][]vxlan.Record{}
	for _, host := range hosts {
		config := record.Map(configs[host])
		mappings := record.Map(config["vlan_vnis"])
		nve := record.Map(record.Map(config["nve"])["members"])
		evpn := record.Map(config["evpn"])
		l3 := map[int]bool{}
		l2 := map[int]bool{}
		for _, v := range record.Map(config["vrfs"]) {
			if n := record.Map(v)["vni"]; n != nil {
				l3[record.Number(n)] = true
			}
		}
		for k, v := range evpn {
			switch record.Map(v)["type"] {
			case "l2":
				l2[record.Number(k)] = true
			case "l3":
				l3[record.Number(k)] = true
			}
		}
		for k, v := range nve {
			if record.Truthy(record.Map(v)["associate_vrf"]) {
				l3[record.Number(k)] = true
			} else {
				l2[record.Number(k)] = true
			}
		}
		vnis := map[int]bool{}
		for _, vni := range mappings {
			if vni != nil && !l3[record.Number(vni)] {
				vnis[record.Number(vni)] = true
			}
		}
		for n := range l2 {
			vnis[n] = true
		}
		// Build the reverse association once per device, as the source catalog
		// does; sorting and scanning every VLAN for every VNI is quadratic.
		mappingsByVNI := map[int][]any{}
		for _, vlan := range record.NaturalKeys(mappings) {
			mapped := mappings[vlan]
			vni := record.Number(mapped)
			if record.Equal(mapped, vni) {
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
				} else if record.Truthy(record.Map(member)["associate_vrf"]) {
					missing = append(missing, "NVE L2")
				}
				if record.Truthy(config["nv_overlay_evpn"]) && control == nil {
					missing = append(missing, "EVPN")
				}
				if control != nil && record.Map(control)["type"] != "l2" {
					missing = append(missing, "EVPN L2")
				}
				var svi any
				if vlan != nil {
					svi = record.Map(config["interfaces"])["Vlan"+record.String(vlan)]
				}
				result[vni] = append(result[vni], vxlan.Record{"host": host, "config": config, "vlan": vlan, "svi": svi, "nve": member, "evpn": control, "missing": missing})
			}
		}
	}
	return result
}

// EffectiveNVEMember resolves global multicast inheritance only when appropriate.
func EffectiveNVEMember(config, member vxlan.Record) vxlan.Record {
	if member == nil {
		return nil
	}
	inherited := record.Map(config["nve"])["multicast_group"]
	if record.Truthy(inherited) && !record.Truthy(member["replication"]) && !record.Truthy(member["multicast_group"]) && !record.Truthy(member["associate_vrf"]) {
		return record.Merge(member, vxlan.Record{"multicast_group": inherited})
	}
	return member
}

// ServiceRouteTargets expands both directions and two-byte ASN auto targets.
func ServiceRouteTargets(entries any, asn, vni any) []any {
	out := []any{}
	for _, entry := range record.Rows(entries) {
		directions := []any{entry["direction"]}
		if entry["direction"] == "both" {
			directions = []any{"import", "export"}
		}
		for _, direction := range directions {
			target := entry["target"]
			if target == "auto" {
				if record.Integer(asn, 1, 65535) {
					target = fmt.Sprintf("%d:%d", record.Number(asn), record.Number(vni))
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
	var err error
	out, err = record.UniqueChecked(out)
	if err != nil {
		return nil
	}
	keys := make(map[string]any, len(out))
	ordered := make([]string, 0, len(out))
	for _, row := range out {
		encoded, err := record.CanonicalJSON(row)
		if err != nil {
			return nil
		}
		key := string(encoded)
		ordered = append(ordered, key)
		keys[key] = row
	}
	sort.Strings(ordered)
	for i, key := range ordered {
		out[i] = keys[key]
	}
	return out
}

// ServiceTenant compares tenant VNI and route-target declarations.
func ServiceTenant(config vxlan.Record, name string) vxlan.Record {
	vrf, ok := record.Map(config["vrfs"])[name].(map[string]any)
	if !ok {
		return nil
	}
	return vxlan.Record{"vrf": name, "vni": vrf["vni"], "route_targets": ServiceRouteTargets(vrf["route_targets"], record.Map(config["bgp"])["asn"], vrf["vni"])}
}

// ServiceMappingSignature binds gateway identity and resolved ACL dependencies.
func ServiceMappingSignature(config, svi vxlan.Record) vxlan.Record {
	if !record.Truthy(svi["anycast"]) || !record.Truthy(svi["vrf"]) || len(record.StringSlice(svi["addresses"])) != 1 || !record.Truthy(config["anycast_mac"]) {
		return nil
	}
	policies := vxlan.Record{}
	bindings := record.Map(svi["acl_bindings"])
	for direction, name := range bindings {
		policy := ResolveACLPolicy(config, record.Map(config["acls"])[record.String(name)])
		if policy == nil {
			return nil
		}
		policies[direction] = policy
	}
	return record.Merge(record.Select(svi, "addresses", "vrf", "anycast", "shutdown", "mtu"), vxlan.Record{"anycast_mac": config["anycast_mac"], "policies": policies})
}
