package configuration

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

// BGPNeighbors resolves supported peer-template inheritance without session inference.
func BGPNeighbors(bgp vxlan.Record) []vxlan.Record {
	out := []vxlan.Record{}
	templates := record.Map(bgp["templates"])
	scopes := record.Merge(vxlan.Record{"default": bgp}, record.Map(bgp["vrfs"]))
	for _, vrf := range record.Keys(scopes) {
		neighbors := record.Map(record.Map(scopes[vrf])["neighbors"])
		for _, peer := range record.Keys(neighbors) {
			n := record.Map(neighbors[peer])
			name := record.String(n["inherit_peer"])
			t := record.Map(templates[name])
			if name != "" && templates[name] == nil || t["inherit_peer"] != nil {
				continue
			}
			families := record.Merge(record.Map(t["address_families"]), record.Map(n["address_families"]))
			for family, nv := range record.Map(n["address_families"]) {
				if tv, ok := record.Map(t["address_families"])[family]; ok {
					m := record.Merge(record.Map(tv), record.Compact(record.Map(nv)))
					m["route_maps"] = record.Merge(record.Map(record.Map(tv)["route_maps"]), record.Map(record.Map(nv)["route_maps"]))
					families[family] = m
				}
			}
			v := record.Merge(t, record.Compact(n))
			v["address_families"] = families
			out = append(out, vxlan.Record{"vrf": vrf, "peer": peer, "settings": v})
		}
	}
	return out
}

// PrefixListReferences associates policy selectors with all supported routing consumers.
func PrefixListReferences(config vxlan.Record, family string) (vxlan.Record, error) {
	if family != "ipv4" && family != "ipv6" {
		return nil, fmt.Errorf("Unsupported address family")
	}
	consumers := vxlan.Record{}
	add := func(name any, context vxlan.Record) {
		n := record.String(name)
		rows := record.Rows(consumers[n])
		for _, row := range rows {
			if record.Equal(row, context) {
				return
			}
		}
		consumers[n] = append(rows, context)
	}
	redistribute := func(settings, context vxlan.Record) {
		for _, entry := range record.Rows(settings["redistribute"]) {
			if entry["route_map"] != nil {
				add(entry["route_map"], record.Compact(record.Merge(context, vxlan.Record{"usage": "redistribute", "source_protocol": entry["protocol"], "source_process": entry["process"]})))
			}
		}
	}
	bgp := record.Map(config["bgp"])
	scopes := record.Merge(vxlan.Record{"default": bgp}, record.Map(bgp["vrfs"]))
	for _, vrf := range record.Keys(scopes) {
		afs := record.Map(record.Map(scopes[vrf])["address_families"])
		for _, af := range record.Keys(afs) {
			v := record.Map(afs[af])
			context := vxlan.Record{"protocol": "bgp", "process": record.String(bgp["asn"]), "vrf": vrf, "address_family": af}
			redistribute(v, context)
			for _, n := range record.Rows(v["networks"]) {
				if n["route_map"] != nil {
					add(n["route_map"], record.Merge(context, vxlan.Record{"usage": "network", "prefix": n["prefix"]}))
				}
			}
			retain := record.String(v["retain_route_target"])
			if strings.HasPrefix(retain, "route-map ") {
				add(strings.TrimPrefix(retain, "route-map "), record.Merge(context, vxlan.Record{"usage": "retain_route_target"}))
			}
		}
	}
	for _, neighbor := range BGPNeighbors(bgp) {
		afs := record.Map(record.Map(neighbor["settings"])["address_families"])
		for _, af := range record.Keys(afs) {
			maps := record.Map(record.Map(afs[af])["route_maps"])
			for _, direction := range record.Keys(maps) {
				add(maps[direction], vxlan.Record{"protocol": "bgp", "process": record.String(bgp["asn"]), "vrf": neighbor["vrf"], "address_family": af, "usage": "neighbor_route_map", "peer": neighbor["peer"], "direction": direction})
			}
		}
	}
	ospf := record.Map(config["ospf"])
	for _, process := range record.Keys(ospf) {
		settings := record.Map(ospf[process])
		scopes := record.Merge(vxlan.Record{"default": settings}, record.Map(settings["vrfs"]))
		for _, vrf := range record.Keys(scopes) {
			redistribute(record.Map(scopes[vrf]), vxlan.Record{"protocol": "ospf", "process": process, "vrf": vrf})
		}
	}
	vrfs := record.Map(config["vrfs"])
	for _, vrf := range record.Keys(vrfs) {
		for _, entry := range record.Rows(record.Map(vrfs[vrf])["exports"]) {
			add(entry["route_map"], vxlan.Record{"protocol": "vrf", "vrf": vrf, "address_family": entry["address_family"], "usage": "export", "target_vrf": entry["vrf"]})
		}
	}
	out := vxlan.Record{}
	maps := record.Map(config["route_maps"])
	for _, name := range record.Keys(maps) {
		entries := append([]vxlan.Record{}, record.Rows(maps[name])...)
		sort.SliceStable(entries, func(i, j int) bool {
			return record.Number(entries[i]["sequence"]) < record.Number(entries[j]["sequence"])
		})
		for _, entry := range entries {
			matches, ok := entry["prefix_list_matches"]
			if !ok {
				matches = []vxlan.Record{{"address_family": "ipv4", "selector": "address", "names": entry["prefix_lists"]}}
			}
			for _, match := range record.Rows(matches) {
				if match["address_family"] != family {
					continue
				}
				reference := vxlan.Record{"type": "route_map", "name": name, "sequence": entry["sequence"], "action": entry["action"], "bindings": record.Rows(consumers[name])}
				if match["selector"] != "address" {
					reference["selector"] = match["selector"]
				}
				for _, list := range record.StringSlice(match["names"]) {
					rows := record.Rows(out[list])
					duplicate := false
					for _, r := range rows {
						if record.Equal(r, reference) {
							duplicate = true
						}
					}
					if !duplicate {
						out[list] = append(rows, reference)
					}
				}
			}
		}
	}
	return out, nil
}
