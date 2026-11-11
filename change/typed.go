package change

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"

	netchange "github.com/gatework/go-netops/change"
	"github.com/gatework/go-netops/evidence"
	"github.com/gatework/go-vxlan/fabric"
)

// The three increments that may be executed automatically. Each is a typed
// netops change over *fabric.Configuration with the same JSON fields,
// commands, eligibility and readback semantics as the legacy ChangePlan.
const (
	KindSVIACL     netchange.Kind = "svi_acl"
	KindSVIGateway netchange.Kind = "svi_gateway_add"
	KindVLANVNI    netchange.Kind = "vlan_vni_add"
)

// Change is the typed form of an executable increment.
type Change interface {
	netchange.Change[*fabric.Configuration]
	netchange.Preserving[*fabric.Configuration]
}

var (
	_ Change = SVIGateway{}
	_ Change = VLANVNI{}
	_ Change = SVIACL{}

	errIneligible = errors.New("configuration does not allow the change")
	errTarget     = errors.New("configuration does not show the change")

	gatewayAddress = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$`)
	aclName        = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,63}$`)
	aclExpression  = regexp.MustCompile(`^(?:ip|tcp|udp|icmp|igmp|gre|esp|ah|ospf) [A-Za-z0-9_.:/ -]+$`)
)

func validVLANVNI(vlan, vni int) error {
	if vlan < 1 || vlan > 4094 {
		return errors.New("VLAN 无效")
	}
	if vni < 1 || vni > 16777215 {
		return errors.New("VNI 无效")
	}
	return nil
}

func sviName(vlan int) string { return fmt.Sprintf("Vlan%d", vlan) }

// mappedSVI returns the SVI when vlan maps to vni and the SVI exists.
func mappedSVI(c *fabric.Configuration, vlan, vni int) (fabric.Interface, bool) {
	if c == nil {
		return fabric.Interface{}, false
	}
	if mapped := c.VLANVNIs[fmt.Sprint(vlan)]; mapped == nil || *mapped != vni {
		return fabric.Interface{}, false
	}
	svi, ok := c.Interfaces[sviName(vlan)]
	return svi, ok
}

func network(address string) (netip.Prefix, error) {
	if !bytes.ContainsRune([]byte(address), '/') {
		a, err := netip.ParseAddr(address)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(address)
	return p.Masked(), err
}

func overlap(a, b netip.Prefix) bool {
	return a.Addr().Is4() == b.Addr().Is4() && (a.Contains(b.Addr()) || b.Contains(a.Addr()))
}

// gatewayContext requires an anycast SVI in the change's VRF and no other
// interface of that VRF overlapping the gateway network.
func gatewayContext(c *fabric.Configuration, vlan int, vrf, address string) bool {
	self := sviName(vlan)
	svi := c.Interfaces[self]
	if !fabric.True(svi.Anycast) || svi.VRF != vrf {
		return false
	}
	net, err := network(address)
	if err != nil {
		return false
	}
	for name, other := range c.Interfaces {
		if name == self || other.VRF != vrf {
			continue
		}
		for _, a := range other.Addresses {
			candidate, err := network(a)
			if err != nil || overlap(net, candidate) {
				return false
			}
		}
	}
	return true
}

func validGateway(vrf, address string) error {
	p, err := netip.ParsePrefix(address)
	if vrf == "" || !gatewayAddress.MatchString(address) || err != nil || !p.Addr().Is4() {
		return errors.New("缺少已验证的业务网关")
	}
	return nil
}

// preserved compares configurations after removing volatile parser output,
// normalizing ACLs to their ordered rules and applying drop, which removes
// exactly the field the change may modify.
func preserved(before, after *fabric.Configuration, drop func(*fabric.Configuration)) error {
	normalize := func(c *fabric.Configuration) ([]byte, error) {
		body, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		var cp fabric.Configuration
		if err := json.Unmarshal(body, &cp); err != nil {
			return nil, err
		}
		cp.ConfigDigest, cp.ReviewStatus, cp.ReviewFindings, cp.Segments, cp.UnnumberedAddresses = "", "", nil, nil, nil
		drop(&cp)
		acls := map[string][]fabric.ACLRule{}
		for name, entries := range cp.ACLs {
			acls[name] = fabric.OrderedRules(entries)
		}
		cp.ACLs = nil
		return evidence.Canonical(struct {
			Config *fabric.Configuration
			ACLs   map[string][]fabric.ACLRule
		}{&cp, acls})
	}
	if before == nil || after == nil {
		return errors.New("missing configuration")
	}
	a, err := normalize(before)
	if err != nil {
		return err
	}
	b, err := normalize(after)
	if err != nil {
		return err
	}
	if !bytes.Equal(a, b) {
		return errors.New("configuration outside the change differs")
	}
	return nil
}

// SVIGateway adds the anycast gateway address to an existing mapped SVI.
type SVIGateway struct {
	VLAN    int    `json:"vlan"`
	VNI     int    `json:"vni"`
	VRF     string `json:"vrf"`
	Address string `json:"address"`
}

// Kind identifies the configuration change kind.
func (SVIGateway) Kind() netchange.Kind { return KindSVIGateway }

// Validate checks that the proposed change has valid target values.
func (g SVIGateway) Validate() error {
	if err := validVLANVNI(g.VLAN, g.VNI); err != nil {
		return err
	}
	return validGateway(g.VRF, g.Address)
}

// Render returns the configuration and rollback commands after validation.
func (g SVIGateway) Render() (netchange.Script, error) {
	if err := g.Validate(); err != nil {
		return netchange.Script{}, err
	}
	iface := sviName(g.VLAN)
	return netchange.Script{
		Commands: []string{"configure terminal", "interface " + iface, "  ip address " + g.Address, "end"},
		Rollback: []string{"configure terminal", "interface " + iface, "  no ip address " + g.Address, "end"},
	}, nil
}

// Eligible checks whether the current configuration meets the change prerequisites.
func (g SVIGateway) Eligible(c *fabric.Configuration) error {
	svi, ok := mappedSVI(c, g.VLAN, g.VNI)
	if !ok || !gatewayContext(c, g.VLAN, g.VRF, g.Address) || len(svi.Addresses) != 0 {
		return errIneligible
	}
	return nil
}

// Satisfied checks whether the target configuration contains the proposed state.
func (g SVIGateway) Satisfied(c *fabric.Configuration) error {
	if _, ok := mappedSVI(c, g.VLAN, g.VNI); !ok || !g.target(c) {
		return errTarget
	}
	return nil
}

// Preserved checks that unrelated configuration remains unchanged.
func (g SVIGateway) Preserved(before, after *fabric.Configuration) error {
	return preserved(before, after, func(c *fabric.Configuration) {
		if svi, ok := c.Interfaces[sviName(g.VLAN)]; ok {
			svi.Addresses = nil
			c.Interfaces[sviName(g.VLAN)] = svi
		}
	})
}

// VLANVNI maps an existing VLAN, already carrying the service gateway, to
// the VNI that the rest of the fabric uses.
type VLANVNI struct {
	VLAN    int    `json:"vlan"`
	VNI     int    `json:"vni"`
	VRF     string `json:"vrf"`
	Address string `json:"address"`
}

// Kind identifies the configuration change kind.
func (VLANVNI) Kind() netchange.Kind { return KindVLANVNI }

// Validate checks that the proposed change has valid target values.
func (v VLANVNI) Validate() error {
	if err := validVLANVNI(v.VLAN, v.VNI); err != nil {
		return err
	}
	return validGateway(v.VRF, v.Address)
}

// Render returns the configuration and rollback commands after validation.
func (v VLANVNI) Render() (netchange.Script, error) {
	if err := v.Validate(); err != nil {
		return netchange.Script{}, err
	}
	return netchange.Script{
		Commands: []string{"configure terminal", fmt.Sprintf("vlan %d", v.VLAN), fmt.Sprintf("  vn-segment %d", v.VNI), "end"},
		Rollback: []string{"configure terminal", fmt.Sprintf("vlan %d", v.VLAN), "  no vn-segment", "end"},
	}, nil
}

// Eligible checks whether the current configuration meets the change prerequisites.
func (v VLANVNI) Eligible(c *fabric.Configuration) error {
	if c == nil {
		return errIneligible
	}
	value, exists := c.VLANVNIs[fmt.Sprint(v.VLAN)]
	if !exists || value != nil || !v.target(c) {
		return errIneligible
	}
	return nil
}

// Satisfied checks whether the target configuration contains the proposed state.
func (v VLANVNI) Satisfied(c *fabric.Configuration) error {
	if _, ok := mappedSVI(c, v.VLAN, v.VNI); !ok || !v.target(c) {
		return errTarget
	}
	return nil
}

// Preserved checks that unrelated configuration remains unchanged.
func (v VLANVNI) Preserved(before, after *fabric.Configuration) error {
	return preserved(before, after, func(c *fabric.Configuration) { delete(c.VLANVNIs, fmt.Sprint(v.VLAN)) })
}

// SVIACL binds an ACL to a mapped SVI, optionally creating the ACL with the
// fabric's verified rules.
type SVIACL struct {
	VLAN            int                 `json:"vlan"`
	VNI             int                 `json:"vni"`
	ACL             string              `json:"acl"`
	Direction       string              `json:"direction"`
	Entries         []fabric.ACLEntry   `json:"entries"`
	AddressGroups   map[string][]string `json:"address_groups"`
	CreateACL       bool                `json:"create_acl"`
	PreviousBinding *string             `json:"previous_binding"`
}

// Kind identifies the configuration change kind.
func (SVIACL) Kind() netchange.Kind { return KindSVIACL }

// Validate checks that the proposed change has valid target values.
func (a SVIACL) Validate() error {
	if err := validVLANVNI(a.VLAN, a.VNI); err != nil {
		return err
	}
	if !aclName.MatchString(a.ACL) || (a.Direction != "in" && a.Direction != "out") {
		return errors.New("ACL 参数无效")
	}
	if a.PreviousBinding != nil && *a.PreviousBinding != a.ACL {
		return errors.New("不能覆盖既有绑定")
	}
	p := a.policy()
	if p == nil {
		return errors.New("ACL 规则或依赖未验证")
	}
	if len(p.Rules) == 0 {
		return errors.New("无有效 ACL 规则")
	}
	for _, e := range a.Entries {
		if e.Action != "remark" && !aclExpression.MatchString(e.Expression) {
			return errors.New("ACL 规则语法未验证")
		}
	}
	return nil
}

// Render returns the configuration and rollback commands after validation.
func (a SVIACL) Render() (netchange.Script, error) {
	if err := a.Validate(); err != nil {
		return netchange.Script{}, err
	}
	entries := slices.Clone(a.Entries)
	slices.SortStableFunc(entries, func(x, y fabric.ACLEntry) int { return x.Sequence - y.Sequence })
	iface := sviName(a.VLAN)
	commands := []string{"configure terminal"}
	if a.CreateACL {
		commands = append(commands, "ip access-list "+a.ACL)
		for _, e := range entries {
			if e.Action != "remark" {
				commands = append(commands, fmt.Sprintf("  %d %s %s", e.Sequence, e.Action, e.Expression))
			}
		}
		commands = append(commands, "exit")
	}
	commands = append(commands, "interface "+iface, "  ip access-group "+a.ACL+" "+a.Direction, "end")
	rollback := []string{"configure terminal"}
	if a.PreviousBinding == nil {
		rollback = append(rollback, "interface "+iface, "  no ip access-group "+a.ACL+" "+a.Direction, "exit")
	}
	if a.CreateACL {
		rollback = append(rollback, "no ip access-list "+a.ACL)
	}
	return netchange.Script{Commands: commands, Rollback: append(rollback, "end")}, nil
}

func samePolicy(x, y *fabric.ACLPolicy) bool {
	return x != nil && y != nil && x.Key() == y.Key()
}

// Eligible checks whether the current configuration meets the change prerequisites.
func (a SVIACL) Eligible(c *fabric.Configuration) error {
	svi, ok := mappedSVI(c, a.VLAN, a.VNI)
	want := a.policy()
	// The device must resolve the planned rules to the same policy: its own
	// address groups must match those the plan was built with.
	device, _ := (&fabric.Configuration{ACLs: map[string][]fabric.ACLEntry{a.ACL: a.Entries}, AddressGroups: c.AddressGroups}).ResolveACL(a.ACL)
	if !ok || !samePolicy(device, want) || (a.CreateACL && !a.isolated(c)) {
		return errIneligible
	}
	bound, hasBinding := svi.ACLBindings[a.Direction]
	if (a.PreviousBinding == nil) != !hasBinding || (hasBinding && bound != *a.PreviousBinding) {
		return errIneligible
	}
	entries, defined := c.ACLs[a.ACL]
	switch {
	case a.CreateACL && !defined:
		return nil
	case !a.CreateACL && defined && slices.Equal(fabric.OrderedRules(entries), want.Rules):
		return nil
	}
	return errIneligible
}

// Satisfied checks whether the target configuration contains the proposed state.
func (a SVIACL) Satisfied(c *fabric.Configuration) error {
	if _, ok := mappedSVI(c, a.VLAN, a.VNI); !ok {
		return errTarget
	}
	if a.CreateACL && !a.isolated(c) {
		return errTarget
	}
	got, _ := c.ResolveACL(a.ACL)
	if c.Interfaces[sviName(a.VLAN)].ACLBindings[a.Direction] != a.ACL || !samePolicy(got, a.policy()) {
		return errTarget
	}
	return nil
}

// Preserved checks that unrelated configuration remains unchanged.
func (a SVIACL) Preserved(before, after *fabric.Configuration) error {
	return preserved(before, after, func(c *fabric.Configuration) {
		if svi, ok := c.Interfaces[sviName(a.VLAN)]; ok && svi.ACLBindings != nil {
			bindings := maps.Clone(svi.ACLBindings)
			delete(bindings, a.Direction)
			svi.ACLBindings = bindings
			c.Interfaces[sviName(a.VLAN)] = svi
		}
		if a.CreateACL && c.ACLs != nil {
			delete(c.ACLs, a.ACL)
		}
	})
}

// DecodeChange strictly decodes a change record, rejecting fields that do
// not belong to its kind and kinds that are not executable.
func DecodeChange(body []byte) (Change, error) {
	var head struct {
		Kind netchange.Kind `json:"kind"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return nil, fmt.Errorf("增量须为映射: %w", err)
	}
	strip := func() []byte {
		var m map[string]json.RawMessage
		_ = json.Unmarshal(body, &m)
		delete(m, "kind")
		b, _ := json.Marshal(m)
		return b
	}
	decode := func(v any) error {
		d := json.NewDecoder(bytes.NewReader(strip()))
		d.DisallowUnknownFields()
		if err := d.Decode(v); err != nil {
			return fmt.Errorf("增量字段无效: %w", err)
		}
		return nil
	}
	var c Change
	switch head.Kind {
	case KindSVIGateway:
		var v SVIGateway
		if err := decode(&v); err != nil {
			return nil, err
		}
		c = v
	case KindVLANVNI:
		var v VLANVNI
		if err := decode(&v); err != nil {
			return nil, err
		}
		c = v
	case KindSVIACL:
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(body, &raw)
		if _, ok := raw["create_acl"]; !ok {
			return nil, errors.New("ACL 创建状态无效")
		}
		var v SVIACL
		if err := decode(&v); err != nil {
			return nil, err
		}
		c = v
	default:
		return nil, errors.New("不支持的增量类型")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Record returns the change as its persisted JSON object with "kind".
func Record(c Change) (map[string]any, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		return nil, err
	}
	m["kind"] = string(c.Kind())
	return m, nil
}

func (g SVIGateway) target(c *fabric.Configuration) bool {
	return gatewayContext(c, g.VLAN, g.VRF, g.Address) && slices.Equal(c.Interfaces[sviName(g.VLAN)].Addresses, []string{g.Address})
}

// target: gateway in place, NVE L2 member and L2 EVPN for the VNI, and no
// other VLAN mapped to the VNI.
func (v VLANVNI) target(c *fabric.Configuration) bool {
	if c == nil || !gatewayContext(c, v.VLAN, v.VRF, v.Address) || !slices.Equal(c.Interfaces[sviName(v.VLAN)].Addresses, []string{v.Address}) {
		return false
	}
	key := fmt.Sprint(v.VNI)
	member, ok := c.NVE.Members[key]
	if !ok || member.AssociateVRF == nil || *member.AssociateVRF {
		return false
	}
	if e, ok := c.EVPN[key]; !ok || e.Type != "l2" {
		return false
	}
	for vlan, mapped := range c.VLANVNIs {
		if vlan != fmt.Sprint(v.VLAN) && mapped != nil && *mapped == v.VNI {
			return false
		}
	}
	return true
}

// policy resolves the change's own rules and address groups.
func (a SVIACL) policy() *fabric.ACLPolicy {
	groups := a.AddressGroups
	if groups == nil {
		groups = map[string][]string{}
	}
	p, _ := (&fabric.Configuration{ACLs: map[string][]fabric.ACLEntry{a.ACL: a.Entries}, AddressGroups: groups}).ResolveACL(a.ACL)
	if p == nil || !maps.EqualFunc(p.AddressGroups, groups, slices.Equal) {
		return nil
	}
	return p
}

// isolated: every existing binding of the ACL is this SVI and direction,
// so creating it cannot change other interfaces.
func (a SVIACL) isolated(c *fabric.Configuration) bool {
	for name, iface := range c.Interfaces {
		for direction, bound := range iface.ACLBindings {
			if bound == a.ACL && (name != sviName(a.VLAN) || direction != a.Direction) {
				return false
			}
		}
	}
	return true
}
