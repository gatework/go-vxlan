package vxlan

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestChangePlanOwnsInputsAndAccessorResults(t *testing.T) {
	change := Record{"kind": "svi_acl", "vlan": 8, "vni": 10008, "acl": "protect", "direction": "out", "entries": []Record{{"sequence": 10, "action": "deny", "expression": "ip any any"}}, "create_acl": true, "previous_binding": nil}
	plan, err := NewChangePlan(change)
	if err != nil {
		t.Fatal(err)
	}
	change["acl"] = "different"
	cfgRows(change["entries"])[0]["expression"] = "ip any 192.0.2.0/24"
	returned := plan.Change()
	cfgRows(returned["entries"])[0]["expression"] = "changed"
	returned["acl"] = "changed"
	commands := plan.Commands()
	commands[0] = "reboot"
	rollback := plan.Rollback()
	rollback[0] = "reboot"
	if plan.Change()["acl"] != "protect" || cfgRows(plan.Change()["entries"])[0]["expression"] != "ip any any" || plan.Commands()[0] != "configure terminal" || plan.Rollback()[0] != "configure terminal" {
		t.Fatal("plan retained caller-owned mutable data")
	}
	config := Record{"vlan_vnis": Record{"8": 10008}, "interfaces": Record{"Vlan8": Record{"acl_bindings": Record{}}}, "acls": Record{}}
	if !plan.Eligible(config) {
		t.Fatal("valid immutable plan became ineligible")
	}
}
func TestChangePlanGatewayPreservesUnrelatedConfiguration(t *testing.T) {
	change := Record{"kind": "svi_gateway_add", "vlan": float64(8), "vni": float64(10008), "vrf": "tenant", "address": "192.0.2.254/24"}
	plan, err := NewChangePlan(change)
	if err != nil {
		t.Fatal(err)
	}
	before := Record{"vlan_vnis": Record{"8": 10008}, "interfaces": Record{"Vlan8": Record{"vrf": "tenant", "anycast": true, "addresses": []string{}}}, "acls": Record{"unrelated": []Record{{"sequence": 10, "action": "permit", "expression": "ip any any"}}}}
	after := domainCopy(before).(Record)
	cfgMap(domainAt(after, "interfaces", "Vlan8"))["addresses"] = []string{"192.0.2.254/24"}
	if !plan.Satisfied(after, before) {
		t.Fatal("valid address addition rejected")
	}
	cfgRows(cfgMap(after["acls"])["unrelated"])[0]["sequence"] = 100
	if !plan.Satisfied(after, before) {
		t.Fatal("semantic ACL renumbering is allowed")
	}
	cfgRows(cfgMap(after["acls"])["unrelated"])[0]["action"] = "deny"
	if plan.Satisfied(after, before) {
		t.Fatal("unrelated forwarding rule drift accepted")
	}
}
func TestChangePlanRejectsInvalidParameters(t *testing.T) {
	base := Record{"kind": "svi_gateway_add", "vlan": 8, "vni": 10008, "vrf": "tenant", "address": "192.0.2.254/24"}
	for _, edit := range []Record{{"vlan": 8.5}, {"vni": 10008.2}, {"vlan": "8"}, {"address": "2001:db8::1/64"}, {"address": "192.0.2.1/33"}, {"address": "192.0.2.1/24\nend"}, {"vrf": ""}, {"commands": []string{"reboot"}}} {
		if _, err := NewChangePlan(domainMerge(base, edit)); err == nil {
			t.Fatalf("accepted invalid increment %#v", edit)
		}
	}
}
func TestCompleteConfigRequiresUniqueCompleteEvidence(t *testing.T) {
	record := Record{"review_status": "complete"}
	document := Record{"snapshot": Record{"dimensions": Record{"configuration": Record{"status": "complete", "records": []Record{record}}}}}
	if CompleteConfig(document) == nil {
		t.Fatal("complete record rejected")
	}
	observation := cfgMap(domainAt(document, "snapshot", "dimensions", "configuration"))
	observation["records"] = []Record{record, record}
	if CompleteConfig(document) != nil {
		t.Fatal("ambiguous records accepted")
	}
	observation["records"] = []Record{record}
	record["review_status"] = "partial"
	if CompleteConfig(document) != nil {
		t.Fatal("partial record accepted")
	}
}
func TestSubnetIndexRetainsItsSnapshot(t *testing.T) {
	addresses := []string{"192.0.2.129/25"}
	svi := Record{"vrf": "tenant", "addresses": addresses}
	config := Record{"interfaces": Record{"Vlan9": svi}, "vlan_vnis": Record{"9": 10009}}
	index := NewSubnetIndex(config)
	addresses[0] = "198.51.100.1/24"
	svi["vrf"] = "other"
	cfgMap(config["vlan_vnis"])["9"] = 10008
	conflicts, err := index.Conflicts("192.0.2.254/24", "tenant", 10008, "")
	if err != nil || len(conflicts) != 1 || conflicts[0]["vni"] != 10009 || cfgStrings(conflicts[0]["value"])[0] != "192.0.2.129/25" {
		t.Fatalf("snapshot changed: %#v %v", conflicts, err)
	}
}
func TestFabricRejectsDuplicateIdentity(t *testing.T) {
	doc := Record{"device": Record{"host": "192.0.2.1"}}
	policy := Record{"fabrics": Record{"A": Record{"leaves": []string{"192.0.2.1", "192.0.2.2"}}}}
	if _, err := ReviewFabric([]Record{doc, doc}, policy); err == nil || !strings.Contains(err.Error(), "重复设备身份") {
		t.Fatal("duplicate identity must fail", err)
	}
}

func TestSubnetIndexQueryAllocationGrowth(t *testing.T) {
	allocations := []float64{}
	for _, count := range []int{128, 512} {
		config := Record{"interfaces": Record{}, "vlan_vnis": Record{}}
		addresses := make([]string, count)
		for i := 0; i < count; i++ {
			name := fmt.Sprintf("Vlan%d", i+1)
			addresses[i] = fmt.Sprintf("10.%d.%d.254/24", i/256, i%256)
			cfgMap(config["interfaces"])[name] = Record{"vrf": "tenant", "addresses": []string{addresses[i]}}
			cfgMap(config["vlan_vnis"])[strconv.Itoa(i+1)] = 10001 + i
		}
		index := NewSubnetIndex(config)
		allocations = append(allocations, testing.AllocsPerRun(1, func() {
			for i, address := range addresses {
				conflicts, err := index.Conflicts(address, "tenant", 10001+i, "")
				if err != nil || len(conflicts) != 0 {
					t.Fatalf("unexpected conflicts %v %v", conflicts, err)
				}
			}
		}))
	}
	t.Logf("subnet query allocations for 128/512 entries: %v", allocations)
	if allocations[1] >= allocations[0]*6 {
		t.Fatalf("subnet query allocations grow quadratically: %v", allocations)
	}
}

func TestFabricGatewayAllocationGrowth(t *testing.T) {
	allocations := []float64{}
	for _, count := range []int{32, 128} {
		docs := []Record{}
		for hostIndex, host := range []string{"192.0.2.1", "192.0.2.2"} {
			config := Record{"review_status": "complete", "anycast_mac": "0011.0011.0011", "vlan_vnis": Record{}, "interfaces": Record{}, "nve": Record{"members": Record{}}, "evpn": Record{}}
			for i := 0; i < count; i++ {
				vlan, vni := strconv.Itoa(i+1), strconv.Itoa(i+10001)
				addresses := []string{}
				if hostIndex == 0 {
					addresses = []string{fmt.Sprintf("10.%d.%d.254/24", i/256, i%256)}
				}
				cfgMap(config["vlan_vnis"])[vlan] = 10001 + i
				cfgMap(config["interfaces"])["Vlan"+vlan] = Record{"vrf": "tenant", "anycast": true, "addresses": addresses}
				cfgMap(cfgMap(config["nve"])["members"])[vni] = Record{"associate_vrf": false, "replication": "bgp"}
				cfgMap(config["evpn"])[vni] = Record{"type": "l2"}
			}
			docs = append(docs, Record{"device": Record{"host": host, "name": host}, "snapshot": Record{"dimensions": Record{"configuration": Record{"status": "complete", "records": []Record{config}}}}})
		}
		policy := Record{"fabrics": Record{"A": Record{"leaves": []string{"192.0.2.1", "192.0.2.2"}}}}
		allocations = append(allocations, testing.AllocsPerRun(1, func() {
			audit, err := ReviewFabric(docs, policy)
			if err != nil || len(cfgRows(cfgMap(audit["device_items"])["192.0.2.2"])) != count {
				t.Fatal("gateway audit failed", err)
			}
		}))
	}
	t.Logf("fabric gateway allocations for 32/128 VNIs: %v", allocations)
	if allocations[1] >= allocations[0]*6 {
		t.Fatalf("fabric gateway allocations grow quadratically: %v", allocations)
	}
}
