package configuration_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/configuration"
	"github.com/gatework/go-vxlan/fabric"
	recordpkg "github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/rules"
	"github.com/gatework/go-vxlan/vendors"
)

func TestChangePlanOwnsInputsAndAccessorResults(t *testing.T) {
	change := vxlan.Record{"kind": "svi_acl", "vlan": 8, "vni": 10008, "acl": "protect", "direction": "out", "entries": []vxlan.Record{{"sequence": 10, "action": "deny", "expression": "ip any any"}}, "create_acl": true, "previous_binding": nil}
	plan, err := newChangePlan(change)
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
	plan, err := newChangePlan(change)
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
		if _, err := newChangePlan(recordpkg.Merge(base, edit)); err == nil {
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
func TestFabricRejectsDuplicateIdentity(t *testing.T) {
	d := fabric.NewDevice(fabric.Identity{Host: "192.0.2.1"}, nil)
	policy := &fabric.Policy{Fabrics: map[string]fabric.Membership{"A": {Leaves: []string{"192.0.2.1", "192.0.2.2"}}}}
	if _, err := fabric.Build([]*fabric.Device{d, d}, policy); err == nil {
		t.Fatal("duplicate identity must fail")
	}
}

func TestSubnetIndexQueryAllocationGrowth(t *testing.T) {
	allocations := []float64{}
	for _, count := range []int{128, 512} {
		c := &fabric.Configuration{Interfaces: map[string]fabric.Interface{}, VLANVNIs: map[string]*int{}}
		addresses := make([]string, count)
		for i := 0; i < count; i++ {
			addresses[i] = fmt.Sprintf("10.%d.%d.254/24", i/256, i%256)
			c.Interfaces[fmt.Sprintf("Vlan%d", i+1)] = fabric.Interface{VRF: "tenant", Addresses: []string{addresses[i]}}
			c.VLANVNIs[strconv.Itoa(i+1)] = new(10001 + i)
		}
		index := fabric.NewSubnetIndex(c)
		allocations = append(allocations, testing.AllocsPerRun(1, func() {
			for i, address := range addresses {
				conflicts, err := index.Conflicts(address, "tenant", new(10001+i), "")
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

func typedFabric(t *testing.T, documents []vxlan.Record, policy vxlan.Record) *fabric.Fabric {
	t.Helper()
	var devices []*fabric.Device
	for _, doc := range documents {
		d, err := fabric.EncodeDocument(doc)
		if err != nil {
			t.Fatal(err)
		}
		devices = append(devices, d)
	}
	body, _ := json.Marshal(policy)
	p, err := fabric.DecodePolicy(body)
	if err != nil {
		t.Fatal(err)
	}
	m, err := fabric.Build(devices, &p)
	if err != nil {
		t.Fatal(err)
	}
	return m.Fabrics[0]
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
		f := typedFabric(t, docs, policy)
		allocations = append(allocations, testing.AllocsPerRun(1, func() {
			if n := len(rules.Increments(f, profile)); n != count {
				t.Fatalf("gateway increments: %d, want %d", n, count)
			}
		}))
	}
	t.Logf("fabric gateway allocations for 32/128 VNIs: %v", allocations)
	if allocations[1] >= allocations[0]*6 {
		t.Fatalf("fabric gateway allocations grow quadratically: %v", allocations)
	}
}

// Gateway conflicts are scoped to the gateway's VRF: an overlapping SVI in
// another VRF neither blocks the gateway nor leaks across VRFs.
func TestFabricGatewayConflictsRemainScopedToVRF(t *testing.T) {
	configs, documents, policy := benchmarkFabric(4, 1)
	first := recordpkg.Map(configs["192.0.2.1"])
	recordpkg.Map(first["interfaces"])["Vlan999"] = vxlan.Record{"vrf": "other", "addresses": []string{"10.0.0.1/24"}}
	recordpkg.Map(first["vlan_vnis"])["999"] = 10999
	for _, host := range []string{"192.0.2.3", "192.0.2.4"} {
		recordpkg.Map(recordpkg.At(configs, host, "interfaces", "Vlan1"))["addresses"] = []string{}
	}
	profile, err := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, inc := range rules.Increments(typedFabric(t, documents, policy), profile) {
		hosts = append(hosts, inc.Host)
	}
	if !slices.Equal(hosts, []string{"192.0.2.2", "192.0.2.3", "192.0.2.4"}) {
		t.Fatalf("gateway increments: %v (another VRF must not block them)", hosts)
	}
	// The same overlap inside the gateway's VRF blocks every gateway increment.
	recordpkg.Map(recordpkg.At(configs, "192.0.2.1", "interfaces", "Vlan999"))["vrf"] = "tenant"
	if incs := rules.Increments(typedFabric(t, documents, policy), profile); len(incs) != 0 {
		t.Fatalf("overlap in the gateway VRF did not block: %d increments", len(incs))
	}
	// A spine carrying the service is a role conflict: no increment for it.
	if incs := rules.Increments(typedFabric(t, documents, vxlan.Record{"fabrics": vxlan.Record{"A": vxlan.Record{"leaves": []string{"192.0.2.1", "192.0.2.3", "192.0.2.4"}, "spines": []string{"192.0.2.2"}}}}), profile); slices.ContainsFunc(incs, func(i rules.Increment) bool { return i.Host == "192.0.2.2" }) {
		t.Fatal("increment proposed for a role-conflicted spine")
	}
}
