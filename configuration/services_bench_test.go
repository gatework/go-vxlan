package configuration_test

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/configuration"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/rules"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-vxlan/vendors"
)

func benchmarkFabric(devices, services int) (vxlan.Record, []vxlan.Record, vxlan.Record) {
	configs := make(vxlan.Record, devices)
	documents := make([]vxlan.Record, 0, devices)
	hosts := make([]string, 0, devices)
	for device := range devices {
		host := fmt.Sprintf("192.0.2.%d", device+1)
		hosts = append(hosts, host)
		mappings, interfaces, members, evpn := vxlan.Record{}, vxlan.Record{}, vxlan.Record{}, vxlan.Record{}
		for service := range services {
			vlan, vni := strconv.Itoa(service+1), service+10001
			mappings[vlan] = vni
			addresses := []string{}
			if device%4 != 1 {
				addresses = []string{fmt.Sprintf("10.%d.%d.254/24", service/256, service%256)}
			}
			interfaces["Vlan"+vlan] = vxlan.Record{"vrf": "tenant", "anycast": true, "addresses": addresses}
			members[strconv.Itoa(vni)] = vxlan.Record{"associate_vrf": false, "replication": "bgp"}
			evpn[strconv.Itoa(vni)] = vxlan.Record{"type": "l2"}
		}
		config := vxlan.Record{
			"review_status": "complete", "anycast_mac": "0011.0011.0011", "nv_overlay_evpn": true,
			"vlan_vnis": mappings, "interfaces": interfaces, "nve": vxlan.Record{"members": members}, "evpn": evpn,
		}
		configs[host] = config
		documents = append(documents, vxlan.Record{
			"device": vxlan.Record{"host": host, "name": host},
			"snapshot": vxlan.Record{"dimensions": vxlan.Record{
				"configuration": vxlan.Record{"status": "complete", "records": []vxlan.Record{config}},
			}},
		})
	}
	policy := vxlan.Record{"fabrics": vxlan.Record{"A": vxlan.Record{"leaves": hosts}}}
	return configs, documents, policy
}

func BenchmarkServiceCatalog(b *testing.B) {
	for _, services := range []int{64, 256, 1024} {
		b.Run(fmt.Sprintf("vnis=%d", services), func(b *testing.B) {
			configs, _, _ := benchmarkFabric(4, services)
			b.ReportAllocs()
			for b.Loop() {
				if catalog := configuration.ServiceCatalog(configs); len(catalog) != services {
					b.Fatal("service associations lost")
				}
			}
		})
	}
}

func BenchmarkFabricAssessment(b *testing.B) {
	profile, err := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
	if err != nil {
		b.Fatal(err)
	}
	assessor, err := rules.NewAssessor(assess.Policy{}, profile)
	if err != nil {
		b.Fatal(err)
	}
	for _, devices := range []int{4, 16, 64} {
		b.Run(fmt.Sprintf("devices=%d", devices), func(b *testing.B) {
			_, documents, policy := benchmarkFabric(devices, 16)
			var ds []*fabric.Device
			for _, doc := range documents {
				d, err := fabric.EncodeDocument(doc)
				if err != nil {
					b.Fatal(err)
				}
				ds = append(ds, d)
			}
			body, _ := json.Marshal(policy)
			p, _ := fabric.DecodePolicy(body)
			m, err := fabric.Build(ds, &p)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := assessor.Assess(b.Context(), m); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
