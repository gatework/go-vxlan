package nxos

import (
	"encoding/json"
	"strings"
	"testing"
)

const operationsConfig = `hostname LEAF-01
ntp server 192.0.2.10 use-vrf management
ntp server 192.0.2.11 prefer use-vrf management
logging server 192.0.2.20 6 use-vrf management
tacacs-server host 192.0.2.30 key 7 "secret-key"
snmp-server host 192.0.2.40 traps version 2c community-secret
system nve infra-vlans 3000
vlan 10
  name WEB
  vn-segment 10010
vpc domain 10
  peer-gateway
  auto-recovery reload-delay 360
  delay restore 150
  ip arp synchronize
interface port-channel100
  switchport mode trunk
  switchport trunk allowed vlan 10-12,20
  switchport trunk allowed vlan add 30
  vpc peer-link
interface port-channel10
  switchport trunk allowed vlan 10-20
  switchport trunk allowed vlan remove 15
interface port-channel11
  switchport trunk allowed vlan except 5
interface Vlan10
  ip dhcp relay address 198.51.100.5 use-vrf tenant
interface Ethernet1/49
  port-type fabric
`

func TestOperationsExtraction(t *testing.T) {
	o := ParseConfig(operationsConfig, true)
	if o.Status != "complete" && o.Status != "partial" {
		t.Fatalf("status %s", o.Status)
	}
	body, _ := json.Marshal(o.Records[0]["operations"])
	got := string(body)
	for _, want := range []string{
		`"ntp_servers":[{"address":"192.0.2.10","vrf":"management"},{"address":"192.0.2.11","vrf":"management"}]`,
		`"logging_servers":[{"address":"192.0.2.20","vrf":"management"}]`,
		`"tacacs_servers":[{"address":"192.0.2.30"}]`,
		`"snmp_hosts":[{"address":"192.0.2.40"}]`,
		`"nve_infra_vlans":"3000"`,
		`"vlan_names":{"10":"WEB"}`,
		`"port-channel100":"10-12,20,30"`,
		`"port-channel10":"10-14,16-20"`,
		`"port-channel11":"unknown"`,
		`"dhcp_relays":{"Vlan10":[{"address":"198.51.100.5","vrf":"tenant"}]}`,
		`"fabric_ports":["Ethernet1/49"]`,
		`"vpc":{"arp_synchronize":true,"auto_recovery":true,"delay_restore":150}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	for _, secret := range []string{"secret-key", "community-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("credential %q captured", secret)
		}
	}
	if _, ok := ParseConfig("hostname A\n", true).Records[0]["operations"]; ok {
		t.Fatal("operations emitted without operational statements")
	}
}

func TestTrunkAllowedFolding(t *testing.T) {
	for _, c := range []struct{ prev, op, list, want string }{
		{"", "", "all", "all"}, {"", "", "none", "none"}, {"", "", "1-3,2", "1-3"},
		{"1-3", "add", "5", "1-3,5"}, {"all", "add", "5", "all"}, {"1-5", "remove", "3", "1-2,4-5"},
		{"all", "remove", "3", "unknown"}, {"", "except", "3", "unknown"}, {"unknown", "add", "4", "unknown"},
		{"", "", "bogus", "unknown"},
	} {
		if got := applyTrunkAllowed(c.prev, c.op, c.list); got != c.want {
			t.Errorf("%q %s %q = %q, want %q", c.prev, c.op, c.list, got, c.want)
		}
	}
}
