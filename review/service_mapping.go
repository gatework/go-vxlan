package review

import (
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/configuration"
	"github.com/gatework/go-vxlan/internal/record"
)

func serviceMappingTransport(vni int, row vxlan.Record, donors []vxlan.Record) bool {
	values := []any{}
	peers := append([]vxlan.Record{row}, donors...)
	for _, peer := range peers {
		if peer["nve"] == nil || peer["evpn"] == nil {
			return false
		}
		config := record.Map(peer["config"])
		vrf := record.Map(peer["svi"])["vrf"]
		if vrf == nil {
			vrf = record.Map(donors[0]["svi"])["vrf"]
		}
		values = append(values, []any{configuration.EffectiveNVEMember(config, record.Map(peer["nve"])), record.Map(peer["evpn"])["type"], configuration.ServiceRouteTargets(record.Map(peer["evpn"])["route_targets"], record.Map(config["bgp"])["asn"], vni), configuration.ServiceTenant(config, record.String(vrf))})
	}
	unique, err := record.UniqueChecked(values)
	return err == nil && len(unique) == 1
}

// InferServiceMapping requires unique complete donors and an existing unmapped VLAN.
func InferServiceMapping(vni int, row vxlan.Record, peers []vxlan.Record) *change.ChangePlan {
	seen := map[string]bool{}
	donors := []vxlan.Record{}
	for _, peer := range peers {
		host := record.String(peer["host"])
		if seen[host] {
			return nil
		}
		seen[host] = true
		if peer["host"] != row["host"] {
			if len(record.StringSlice(peer["missing"])) != 0 || peer["svi"] == nil {
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
		signatures = append(signatures, configuration.ServiceMappingSignature(record.Map(peer["config"]), record.Map(peer["svi"])))
	}
	unique, err := record.UniqueChecked(signatures)
	if err != nil {
		return nil
	}
	if len(unique) != 1 || record.Map(unique[0]) == nil || len(record.Map(unique[0])) == 0 || !serviceMappingTransport(vni, row, donors) {
		return nil
	}
	expected := record.Map(unique[0])
	config := record.Map(row["config"])
	matches := []string{}
	for vlan, mapped := range record.Map(config["vlan_vnis"]) {
		if mapped == nil {
			svi, ok := record.Map(config["interfaces"])["Vlan"+vlan].(map[string]any)
			if ok && record.Equal(configuration.ServiceMappingSignature(config, svi), expected) {
				matches = append(matches, vlan)
			}
		}
	}
	if len(matches) != 1 {
		return nil
	}
	return change.CandidateChangePlan(vxlan.Record{"kind": "vlan_vni_add", "vlan": record.Number(matches[0]), "vni": vni, "vrf": expected["vrf"], "address": record.StringSlice(expected["addresses"])[0]}, config)
}
