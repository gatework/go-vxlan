package configuration

import (
	"fmt"
	"sort"
	"strconv"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

// Review checks associations only when configuration evidence is complete.
func Review(d vxlan.Record, complete bool) []vxlan.Record {
	return ReviewOrdered(d, complete, record.Keys(record.Map(d["vrfs"])))
}
func ReviewOrdered(d vxlan.Record, complete bool, vrfOrder []string) []vxlan.Record {
	out := []vxlan.Record{}
	if !complete {
		return out
	}
	members := record.Map(record.Map(d["nve"])["members"])
	mappings := map[string][]int{}
	for vlan, vni := range record.Map(d["vlan_vnis"]) {
		if vni == nil {
			continue
		}
		key := fmt.Sprint(vni)
		id, _ := strconv.Atoi(vlan)
		mappings[key] = append(mappings[key], id)
	}
	vrfs := record.Map(d["vrfs"])
	vrfVNIs := map[string]bool{}
	for _, v := range vrfs {
		if n := record.Map(v)["vni"]; n != nil {
			vrfVNIs[fmt.Sprint(n)] = true
		}
	}
	evpn := record.Map(d["evpn"])
	for k, ids := range mappings {
		if members[k] == nil {
			sort.Ints(ids)
			n, _ := strconv.Atoi(k)
			out = append(out, vxlan.Record{"code": "vlan_vni_without_nve", "vni": n, "vlan_ids": ids})
		}
	}
	for k, value := range members {
		v := record.Map(value)
		n, _ := strconv.Atoi(k)
		if v["associate_vrf"] == true {
			if !vrfVNIs[k] {
				out = append(out, vxlan.Record{"code": "nve_l3_without_vrf", "vni": n})
			}
			continue
		}
		if _, ok := mappings[k]; !ok {
			out = append(out, vxlan.Record{"code": "nve_l2_without_vlan", "vni": n})
		}
		if d["nv_overlay_evpn"] == true && evpn[k] == nil {
			out = append(out, vxlan.Record{"code": "nve_l2_without_evpn", "vni": n})
		}
	}
	for k, value := range evpn {
		n, _ := strconv.Atoi(k)
		v := record.Map(value)
		if members[k] == nil {
			out = append(out, vxlan.Record{"code": "evpn_vni_without_nve", "vni": n})
		} else if (v["type"] == "l3") != (record.Map(members[k])["associate_vrf"] == true) {
			out = append(out, vxlan.Record{"code": "vni_layer_conflict", "vni": n, "evpn_type": v["type"]})
		}
	}
	for _, name := range vrfOrder {
		value := vrfs[name]
		v := record.Map(value)
		if v["vni"] == nil {
			continue
		}
		member, ok := members[fmt.Sprint(v["vni"])]
		code := ""
		if !ok {
			code = "l3_vni_without_nve"
		} else if record.Map(member)["associate_vrf"] != true {
			code = "vni_layer_conflict"
		}
		if code != "" {
			out = append(out, vxlan.Record{"code": code, "vni": v["vni"], "vrf": name})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := record.Number(out[i]["vni"]), record.Number(out[j]["vni"])
		if a != b {
			return a < b
		}
		return fmt.Sprint(out[i]["code"]) < fmt.Sprint(out[j]["code"])
	})
	return out
}
