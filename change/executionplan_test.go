package change_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	changepkg "github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

func TestExecutionPlanOwnsApprovalBindings(t *testing.T) {
	before := nxos.ParseConfig("hostname LEAF\nvlan 8\n  vn-segment 10008\ninterface Vlan8\n  vrf member tenant\n  fabric forwarding mode anycast-gateway\n", true).Records[0]
	expected, err := vxlan.Fingerprint(before)
	if err != nil {
		t.Fatal(err)
	}
	change, err := newChangePlan(vxlan.Record{"kind": "svi_gateway_add", "vlan": 8, "vni": 10008, "vrf": "tenant", "address": "192.0.2.254/24"})
	if err != nil {
		t.Fatal(err)
	}
	item := vxlan.Record{"schema_version": 1, "platform": "cisco_nxos", "device": vxlan.Record{"host": "192.0.2.1", "name": "leaf"}, "expected_config_sha256": expected, "change": change.Change(), "commands": change.Commands(), "rollback": change.Rollback()}
	body, err := json.Marshal(vxlan.Record{"schema_version": 2, "platform": "cisco_nxos", "changes": vxlan.Record{"one": item}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := changepkg.NewExecutionPlan(body, "one")
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(body))
	plan.Device()["host"] = "192.0.2.9"
	plan.Commands()[0] = "write erase"
	plan.Presentation()["expected_config_sha256"] = "changed"
	body[0] = 'x'
	if plan.PlanSHA256() != hash || plan.Host() != "192.0.2.1" || plan.Commands()[0] != "configure terminal" || plan.ExpectedConfigSHA256() != expected {
		t.Fatal("approval binding aliased")
	}
	if err := plan.CheckBefore(before); err != nil {
		t.Fatal(err)
	}
	before["hostname"] = "changed"
	if err := plan.CheckBefore(before); err == nil {
		t.Fatal("drift accepted")
	}
	after := nxos.ParseConfig("hostname changed\nvlan 8\n  vn-segment 10008\ninterface Vlan8\n  vrf member tenant\n  fabric forwarding mode anycast-gateway\n  ip address 192.0.2.254/24\n", true).Records[0]
	if _, err := plan.CheckAfter(before, after); err == nil {
		t.Fatal("readback accepted against unbound before evidence")
	}
	item["commands"] = []string{"write erase"}
	tampered, err := json.Marshal(vxlan.Record{"schema_version": 2, "platform": "cisco_nxos", "changes": vxlan.Record{"one": item}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changepkg.NewExecutionPlan(tampered, "one"); err == nil {
		t.Fatal("commands not rerendered")
	}
}

func TestExecutionPlanRejectsUnmodeledFactsAndCollateralChanges(t *testing.T) {
	before := vxlan.Record{"review_status": "complete", "vlan_vnis": vxlan.Record{"8": 10008}, "interfaces": vxlan.Record{"Vlan8": vxlan.Record{"addresses": []string{}, "vrf": "tenant", "anycast": true, "acl_bindings": vxlan.Record{}}}}
	expected, err := vxlan.Fingerprint(before)
	if err != nil {
		t.Fatal(err)
	}
	p, err := changepkg.NewExecutionPlan(planBytes(t, expected), "item")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CheckBefore(before); err != nil {
		t.Fatalf("eligible configuration rejected: %v", err)
	}
	unknown := record.Copy(before).(vxlan.Record)
	unknown["future_feature"] = true
	if _, err := vxlan.ProjectRecord(unknown); err != nil {
		t.Fatalf("test precondition: %v", err)
	}
	digest, _ := vxlan.Fingerprint(unknown)
	q, err := changepkg.NewExecutionPlan(planBytes(t, digest), "item")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.CheckBefore(unknown); err == nil {
		t.Fatal("configuration with an unmodeled fact authorized a change")
	}
	after := record.Copy(before).(vxlan.Record)
	record.Map(record.Map(after["interfaces"])["Vlan8"])["addresses"] = []string{"192.0.2.254/24"}
	if _, err := p.CheckAfter(before, after); err != nil {
		t.Fatalf("exact readback rejected: %v", err)
	}
	collateral := record.Copy(after).(vxlan.Record)
	record.Map(collateral["interfaces"])["Ethernet1/9"] = vxlan.Record{"description": "changed during apply"}
	if _, err := p.CheckAfter(before, collateral); err == nil {
		t.Fatal("readback with a collateral change accepted")
	}
}

func planBytes(t *testing.T, expected string) []byte {
	t.Helper()
	c := vxlan.Record{"kind": "svi_gateway_add", "vlan": 8, "vni": 10008, "vrf": "tenant", "address": "192.0.2.254/24"}
	plan := vxlan.Record{"schema_version": 2, "platform": "cisco_nxos", "changes": vxlan.Record{"item": vxlan.Record{
		"schema_version": 1, "platform": "cisco_nxos", "device": vxlan.Record{"host": "192.0.2.1"}, "expected_config_sha256": expected,
		"change":   c,
		"commands": []string{"configure terminal", "interface Vlan8", "  ip address 192.0.2.254/24", "end"},
		"rollback": []string{"configure terminal", "interface Vlan8", "  no ip address 192.0.2.254/24", "end"},
	}}}
	body, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
