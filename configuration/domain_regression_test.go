package configuration_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	changepkg "github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/configuration"
	recordpkg "github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/review"
	"github.com/gatework/go-vxlan/vendors"
)

func TestChangePlanOwnsInputsAndAccessorResults(t *testing.T) {
	change := vxlan.Record{"kind": "svi_acl", "vlan": 8, "vni": 10008, "acl": "protect", "direction": "out", "entries": []vxlan.Record{{"sequence": 10, "action": "deny", "expression": "ip any any"}}, "create_acl": true, "previous_binding": nil}
	plan, err := changepkg.NewChangePlan(change)
	if err != nil {
		t.Fatal(err)
	}
	change["acl"] = "different"
	recordpkg.Rows(change["entries"])[0]["expression"] = "ip any 192.0.2.0/24"
	returned := plan.Change()
	recordpkg.Rows(returned["entries"])[0]["expression"] = "changed"
	returned["acl"] = "changed"
	commands := plan.Commands()
	commands[0] = "reboot"
	rollback := plan.Rollback()
	rollback[0] = "reboot"
	if plan.Change()["acl"] != "protect" || recordpkg.Rows(plan.Change()["entries"])[0]["expression"] != "ip any any" || plan.Commands()[0] != "configure terminal" || plan.Rollback()[0] != "configure terminal" {
		t.Fatal("plan retained caller-owned mutable data")
	}
	config := vxlan.Record{"vlan_vnis": vxlan.Record{"8": 10008}, "interfaces": vxlan.Record{"Vlan8": vxlan.Record{"acl_bindings": vxlan.Record{}}}, "acls": vxlan.Record{}}
	if !plan.Eligible(config) {
		t.Fatal("valid immutable plan became ineligible")
	}
}
func TestChangePlanGatewayPreservesUnrelatedConfiguration(t *testing.T) {
	change := vxlan.Record{"kind": "svi_gateway_add", "vlan": float64(8), "vni": float64(10008), "vrf": "tenant", "address": "192.0.2.254/24"}
	plan, err := changepkg.NewChangePlan(change)
	if err != nil {
		t.Fatal(err)
	}
	before := vxlan.Record{"vlan_vnis": vxlan.Record{"8": 10008}, "interfaces": vxlan.Record{"Vlan8": vxlan.Record{"vrf": "tenant", "anycast": true, "addresses": []string{}}}, "acls": vxlan.Record{"unrelated": []vxlan.Record{{"sequence": 10, "action": "permit", "expression": "ip any any"}}}}
	after := recordpkg.Copy(before).(vxlan.Record)
	recordpkg.Map(recordpkg.At(after, "interfaces", "Vlan8"))["addresses"] = []string{"192.0.2.254/24"}
	if !plan.Satisfied(after, before) {
		t.Fatal("valid address addition rejected")
	}
	recordpkg.Rows(recordpkg.Map(after["acls"])["unrelated"])[0]["sequence"] = 100
	if !plan.Satisfied(after, before) {
		t.Fatal("semantic ACL renumbering is allowed")
	}
	recordpkg.Rows(recordpkg.Map(after["acls"])["unrelated"])[0]["action"] = "deny"
	if plan.Satisfied(after, before) {
		t.Fatal("unrelated forwarding rule drift accepted")
	}
}
func TestChangePlanRejectsInvalidParameters(t *testing.T) {
	base := vxlan.Record{"kind": "svi_gateway_add", "vlan": 8, "vni": 10008, "vrf": "tenant", "address": "192.0.2.254/24"}
	for _, edit := range []vxlan.Record{{"vlan": 8.5}, {"vni": 10008.2}, {"vlan": "8"}, {"address": "2001:db8::1/64"}, {"address": "192.0.2.1/33"}, {"address": "192.0.2.1/24\nend"}, {"vrf": ""}, {"commands": []string{"reboot"}}} {
		if _, err := changepkg.NewChangePlan(recordpkg.Merge(base, edit)); err == nil {
			t.Fatalf("accepted invalid increment %#v", edit)
		}
	}
}
func TestCompleteConfigRequiresUniqueCompleteEvidence(t *testing.T) {
	record := vxlan.Record{"review_status": "complete"}
	document := vxlan.Record{"snapshot": vxlan.Record{"dimensions": vxlan.Record{"configuration": vxlan.Record{"status": "complete", "records": []vxlan.Record{record}}}}}
	if configuration.CompleteConfig(document) == nil {
		t.Fatal("complete record rejected")
	}
	observation := recordpkg.Map(recordpkg.At(document, "snapshot", "dimensions", "configuration"))
	observation["records"] = []vxlan.Record{record, record}
	if configuration.CompleteConfig(document) != nil {
		t.Fatal("ambiguous records accepted")
	}
	observation["records"] = []vxlan.Record{record}
	record["review_status"] = "partial"
	if configuration.CompleteConfig(document) != nil {
		t.Fatal("partial record accepted")
	}
}
func TestSubnetIndexRetainsItsSnapshot(t *testing.T) {
	addresses := []string{"192.0.2.129/25"}
	svi := vxlan.Record{"vrf": "tenant", "addresses": addresses}
	config := vxlan.Record{"interfaces": vxlan.Record{"Vlan9": svi}, "vlan_vnis": vxlan.Record{"9": 10009}}
	index := configuration.NewSubnetIndex(config)
	addresses[0] = "198.51.100.1/24"
	svi["vrf"] = "other"
	recordpkg.Map(config["vlan_vnis"])["9"] = 10008
	conflicts, err := index.Conflicts("192.0.2.254/24", "tenant", 10008, "")
	if err != nil || len(conflicts) != 1 || conflicts[0]["vni"] != 10009 || recordpkg.StringSlice(conflicts[0]["value"])[0] != "192.0.2.129/25" {
		t.Fatalf("snapshot changed: %#v %v", conflicts, err)
	}
}
func TestFabricRejectsDuplicateIdentity(t *testing.T) {
	doc := vxlan.Record{"device": vxlan.Record{"host": "192.0.2.1"}}
	policy := vxlan.Record{"fabrics": vxlan.Record{"A": vxlan.Record{"leaves": []string{"192.0.2.1", "192.0.2.2"}}}}
	if _, err := review.ReviewFabric([]vxlan.Record{doc, doc}, policy, nil); err == nil || !strings.Contains(err.Error(), "重复设备身份") {
		t.Fatal("duplicate identity must fail", err)
	}
}

func TestSubnetIndexQueryAllocationGrowth(t *testing.T) {
	allocations := []float64{}
	for _, count := range []int{128, 512} {
		config := vxlan.Record{"interfaces": vxlan.Record{}, "vlan_vnis": vxlan.Record{}}
		addresses := make([]string, count)
		for i := 0; i < count; i++ {
			name := fmt.Sprintf("Vlan%d", i+1)
			addresses[i] = fmt.Sprintf("10.%d.%d.254/24", i/256, i%256)
			recordpkg.Map(config["interfaces"])[name] = vxlan.Record{"vrf": "tenant", "addresses": []string{addresses[i]}}
			recordpkg.Map(config["vlan_vnis"])[strconv.Itoa(i+1)] = 10001 + i
		}
		index := configuration.NewSubnetIndex(config)
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
	profile, err := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
	if err != nil {
		t.Fatal(err)
	}
	allocations := []float64{}
	for _, count := range []int{32, 128} {
		docs := []vxlan.Record{}
		for hostIndex, host := range []string{"192.0.2.1", "192.0.2.2"} {
			config := vxlan.Record{"review_status": "complete", "anycast_mac": "0011.0011.0011", "vlan_vnis": vxlan.Record{}, "interfaces": vxlan.Record{}, "nve": vxlan.Record{"members": vxlan.Record{}}, "evpn": vxlan.Record{}}
			for i := 0; i < count; i++ {
				vlan, vni := strconv.Itoa(i+1), strconv.Itoa(i+10001)
				addresses := []string{}
				if hostIndex == 0 {
					addresses = []string{fmt.Sprintf("10.%d.%d.254/24", i/256, i%256)}
				}
				recordpkg.Map(config["vlan_vnis"])[vlan] = 10001 + i
				recordpkg.Map(config["interfaces"])["Vlan"+vlan] = vxlan.Record{"vrf": "tenant", "anycast": true, "addresses": addresses}
				recordpkg.Map(recordpkg.Map(config["nve"])["members"])[vni] = vxlan.Record{"associate_vrf": false, "replication": "bgp"}
				recordpkg.Map(config["evpn"])[vni] = vxlan.Record{"type": "l2"}
			}
			docs = append(docs, vxlan.Record{"device": vxlan.Record{"host": host, "name": host}, "snapshot": vxlan.Record{"dimensions": vxlan.Record{"configuration": vxlan.Record{"status": "complete", "records": []vxlan.Record{config}}}}})
		}
		policy := vxlan.Record{"fabrics": vxlan.Record{"A": vxlan.Record{"leaves": []string{"192.0.2.1", "192.0.2.2"}}}}
		allocations = append(allocations, testing.AllocsPerRun(1, func() {
			audit, err := review.ReviewFabric(docs, policy, profile)
			if err != nil || len(recordpkg.Rows(recordpkg.Map(audit["device_items"])["192.0.2.2"])) != count {
				t.Fatal("gateway audit failed", err)
			}
		}))
	}
	t.Logf("fabric gateway allocations for 32/128 VNIs: %v", allocations)
	if allocations[1] >= allocations[0]*6 {
		t.Fatalf("fabric gateway allocations grow quadratically: %v", allocations)
	}
}

func TestFabricGatewayConflictsRemainScopedAndOwned(t *testing.T) {
	configs, documents, policy := benchmarkFabric(4, 1)
	for _, host := range []string{"192.0.2.3", "192.0.2.4"} {
		svi := recordpkg.Map(recordpkg.At(configs, host, "interfaces", "Vlan1"))
		svi["addresses"], svi["vrf"] = []string{}, "other"
	}
	first := recordpkg.Map(configs["192.0.2.1"])
	recordpkg.Map(first["interfaces"])["Vlan999"] = vxlan.Record{"vrf": "other", "addresses": []string{"10.0.0.1/24"}}
	recordpkg.Map(first["vlan_vnis"])["999"] = 10999
	profile, err := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
	if err != nil {
		t.Fatal(err)
	}
	audit, err := review.ReviewFabric(documents, policy, profile)
	if err != nil {
		t.Fatal(err)
	}
	var conflicts []vxlan.Record
	for _, host := range []string{"192.0.2.2", "192.0.2.3", "192.0.2.4"} {
		found := 0
		for _, item := range recordpkg.Rows(recordpkg.Map(audit["device_items"])[host]) {
			if item["code"] != "fabric_gateway" {
				continue
			}
			for _, evidence := range recordpkg.Rows(item["evidence"]) {
				if evidence["interface"] == "Vlan999" {
					found++
					conflicts = append(conflicts, evidence)
				}
			}
		}
		if host == "192.0.2.2" && found != 0 || host != "192.0.2.2" && found != 1 {
			t.Fatalf("gateway conflicts crossed VRF boundary for %s: %d", host, found)
		}
	}
	if len(conflicts) != 2 {
		t.Fatalf("missing independent conflict evidence: %d", len(conflicts))
	}
	recordpkg.StringSlice(conflicts[0]["value"])[0] = "changed"
	if recordpkg.StringSlice(conflicts[1]["value"])[0] != "10.0.0.1/24" {
		t.Fatal("cached query shared mutable evidence between recommendations")
	}
}
