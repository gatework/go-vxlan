package rules

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/fabric"
)

// Increment is one executable change derived for one device: the only kind
// of remediation that may become an execution plan. It reproduces the legacy
// fabric review's derivation of svi_gateway_add, svi_acl and vlan_vni_add.
type Increment struct {
	Host   string
	Source assess.RuleID // the detection the increment corrects
	Change change.Change
	Script []string
	Undo   []string
	// Presentation shown to the operator before execution.
	Scope, Title, Impact, Expected string
	Prerequisites, Verify          []string
}

// Presentation text, unchanged from the legacy fabric review.
var (
	incrementPrerequisites = []string{
		"仅在本 Fabric、相同已部署业务范围内适用；核对业务访问策略与维护窗口。",
		"下发前重新读取配置，任何变化均使计划过期；逐设备逐项确认，不批量重放。",
	}
	aclPrerequisite     = "依据是本业务已挂载且有序内容一致的 ACL；即使挂载节点较少，也不以无 ACL 的多数节点为删除依据。确认此业务应统一受该 ACL 保护。"
	mappingPrerequisite = "本机未映射 VLAN 的网关、VRF、Anycast 身份及 ACL 与完整对端一致，NVE/EVPN 也已匹配；确认该业务确应在本机接入。"
)

const (
	incrementImpact   = "改变网关或 ACL 可能改变可达性及业务隔离；配置回读通过后仍需业务验收。"
	incrementExpected = "共同业务的网关和访问控制一致，允许/拒绝流量均符合设计。"
	mappingImpact     = "将已有 VLAN 接入既有 VXLAN 业务，可能立即扩展广播域；不创建 VLAN，不更改网关或 ACL。"
	mappingExpected   = "本机 VLAN/VNI 关联完整、VNI 状态符合预期，既有网关及 ACL 保持不变；接入业务验收通过。"
)

// legacyRole is the policy role name used in legacy scopes.
func legacyRole(r fabric.Role) string {
	switch r {
	case fabric.RoleLeaf:
		return "leaves"
	case fabric.RoleBorder:
		return "borders"
	}
	return "spines"
}

func present(inc *Increment, f *fabric.Fabric, role fabric.Role, vni int, verify []string) {
	inc.Scope = f.Name + " / " + legacyRole(role) + " / VNI " + strconv.Itoa(vni)
	inc.Prerequisites = slices.Clone(incrementPrerequisites)
	inc.Impact, inc.Expected, inc.Verify = incrementImpact, incrementExpected, slices.Clone(verify)
	switch inc.Source {
	case "vxlan.fabric_gateway":
		inc.Title = "网关地址需要一致"
	case "vxlan.fabric_vlan_mapping_missing":
		inc.Title = "补齐已有业务的 VLAN/VNI 关联"
		inc.Prerequisites = append(inc.Prerequisites, mappingPrerequisite)
		inc.Impact, inc.Expected = mappingImpact, mappingExpected
	default:
		inc.Title = "统一 " + inc.Change.(change.SVIACL).Direction + " 方向访问控制"
		inc.Prerequisites = append(inc.Prerequisites, aclPrerequisite)
	}
}

// Verifier supplies the review-only verification commands of the selected
// profile; without them no increment is proposed, because the outcome could
// not be verified after execution.
type Verifier interface {
	VerificationCommands(scope string) []string
}

// Increments derives executable increments for a fully configured fabric.
func Increments(f *fabric.Fabric, verify Verifier) []Increment {
	if !configured(f) || verify == nil || len(verify.VerificationCommands("fabric")) == 0 {
		return nil
	}
	conflicted := map[string]bool{}
	for _, d := range f.ByRole(fabric.RoleSpine) {
		if len(d.Configuration.Services()) > 0 {
			conflicted[d.Host] = true // role conflicts block every increment of the device
		}
	}
	var out []Increment
	groups := servicesByRole(f)
	commands := verify.VerificationCommands("fabric")
	for _, role := range []fabric.Role{fabric.RoleLeaf, fabric.RoleBorder} {
		for _, vni := range sortedKeys(groups[role]) {
			for _, inc := range vniIncrements(f, vni, groups[role][vni]) {
				present(&inc, f, role, vni, commands)
				out = append(out, inc)
			}
		}
	}
	return slices.DeleteFunc(out, func(i Increment) bool { return conflicted[i.Host] })
}

func sortedKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func newIncrement(host string, source assess.RuleID, c change.Change, cfg *fabric.Configuration) (Increment, bool) {
	if c.Validate() != nil || c.Eligible(cfg) != nil {
		return Increment{}, false
	}
	script, err := c.Render()
	if err != nil {
		return Increment{}, false
	}
	return Increment{Host: host, Source: source, Change: c, Script: script.Commands, Undo: script.Rollback}, true
}

func vniIncrements(f *fabric.Fabric, vni int, rows []roleService) []Increment {
	var out []Increment
	incomplete := slices.ContainsFunc(rows, func(r roleService) bool { return !r.service.Complete() })
	if incomplete {
		for _, r := range rows {
			if slices.Equal(r.service.Missing, []string{"VLAN"}) {
				if inc, ok := inferMapping(f, vni, r, rows); ok {
					out = append(out, inc)
				}
			}
		}
	}
	if !unambiguous(rows) || len(rows) < 2 {
		return out
	}
	blocked := incomplete || transportConflict(f, vni, rows)
	mapped := mappedRows(rows)
	if len(mapped) < 2 || !gateways(mapped) || blocked {
		return out
	}
	out = append(out, gatewayIncrements(f, vni, mapped)...)
	for _, direction := range []string{"in", "out"} {
		out = append(out, aclIncrements(vni, mapped, direction)...)
	}
	return out
}

// transportConflict reports the legacy transport blockers: replication,
// ARP suppression, route targets or tenant routing disagree.
func transportConflict(f *fabric.Fabric, vni int, rows []roleService) bool {
	in := fabricInput{Model: f}
	for _, rule := range []fabricRule{replication, arpSuppression, routeTargets, tenantRouting} {
		for _, finding := range rule.Evaluate(in) {
			if subjectHasVNI(finding.Subject, vni) && subjectHasDevice(finding.Subject, rows) {
				return true
			}
		}
	}
	return false
}

func subjectHasVNI(s assess.Subject, vni int) bool {
	for cur := &s; cur != nil; cur = cur.Parent {
		if cur.Kind == "vni" && cur.Key == strconv.Itoa(vni) {
			return true
		}
	}
	return false
}

func subjectHasDevice(s assess.Subject, rows []roleService) bool {
	for cur := &s; cur != nil; cur = cur.Parent {
		if cur.Kind == "device" {
			return slices.ContainsFunc(rows, func(r roleService) bool { return r.device.Host == cur.Key })
		}
	}
	return false
}

var vlanSVI = regexp.MustCompile(`^Vlan(\d+)$`)

// gatewayConflicts lists SVIs in the same VRF and family, mapped to another
// VNI, whose prefixes overlap the gateway network, across the fabric.
func gatewayConflicts(f *fabric.Fabric, vni int, vrf, address, exceptHost, exceptIface string) []string {
	network, err := netip.ParsePrefix(address)
	if err != nil {
		return []string{"invalid"}
	}
	network = network.Masked()
	var out []string
	for _, d := range f.Members {
		c := d.Configuration
		for name, iface := range c.Interfaces {
			m := vlanSVI.FindStringSubmatch(name)
			if m == nil || iface.VRF != vrf || (d.Host == exceptHost && name == exceptIface) {
				continue
			}
			if mapped := c.VLANVNIs[m[1]]; mapped != nil && *mapped == vni {
				continue
			}
			for _, a := range iface.Addresses {
				p, err := netip.ParsePrefix(a)
				if err != nil {
					return []string{d.Host + " " + name + " invalid"}
				}
				if p = p.Masked(); p.Addr().Is4() == network.Addr().Is4() && p.Overlaps(network) {
					out = append(out, d.Host+" "+name)
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func gatewayIncrements(f *fabric.Fabric, vni int, rows []roleService) []Increment {
	values := make([]string, len(rows)) // "" for no SVI, sorted joined addresses otherwise
	hasSVI := make([]bool, len(rows))
	nonEmpty := map[string]bool{}
	for i, r := range rows {
		if r.service.SVI != nil {
			hasSVI[i] = true
			values[i] = joinSorted(r.service.SVI.Addresses)
			if len(r.service.SVI.Addresses) > 0 {
				nonEmpty[values[i]] = true
			}
		}
	}
	allEqual := true
	for i := range rows {
		if values[i] != values[0] || hasSVI[i] != hasSVI[0] {
			allEqual = false
		}
	}
	if allEqual {
		return nil
	}
	var expected string
	single := len(nonEmpty) == 1
	for v := range nonEmpty {
		expected = v
	}
	address := ""
	if single && !strings.Contains(expected, ",") {
		address = expected
	}
	// Context: one VRF, anycast and anycast MAC across rows, all set.
	contexts := map[string]bool{}
	contextOK := true
	for _, r := range rows {
		vrf, anycast := "", ""
		if r.service.SVI != nil {
			vrf = r.service.SVI.VRF
			if r.service.SVI.Anycast != nil {
				anycast = strconv.FormatBool(*r.service.SVI.Anycast)
			}
		}
		mac := r.device.Configuration.AnycastMAC
		contexts[vrf+"|"+anycast+"|"+mac] = true
		if vrf == "" || anycast != "true" || mac == "" {
			contextOK = false
		}
	}
	contextOK = contextOK && len(contexts) == 1
	var out []Increment
	for i, r := range rows {
		if single && hasSVI[i] && values[i] == expected {
			continue
		}
		if address == "" || !contextOK || r.service.SVI == nil {
			continue
		}
		g := change.SVIGateway{VLAN: *r.service.VLAN, VNI: vni, VRF: r.service.SVI.VRF, Address: address}
		if len(gatewayConflicts(f, vni, g.VRF, address, "", "")) > 0 {
			continue
		}
		if inc, ok := newIncrement(r.device.Host, "vxlan.fabric_gateway", g, r.device.Configuration); ok {
			out = append(out, inc)
		}
	}
	return out
}

func aclIncrements(vni int, rows []roleService, direction string) []Increment {
	views := aclViews(rows, direction)
	bindings, contents := map[string]bool{}, map[string]bool{}
	unknown := false
	for _, v := range views {
		bindings[strconv.FormatBool(v.bound)+v.name] = true
		contents[v.policy.Key()] = true
		if v.bound && v.policy == nil {
			unknown = true
		}
	}
	if len(bindings) <= 1 && len(contents) <= 1 && !unknown {
		return nil
	}
	names := []string{}
	for _, v := range views {
		if v.bound && !slices.Contains(names, v.name) {
			names = append(names, v.name)
		}
	}
	if len(names) != 1 {
		return nil
	}
	name := names[0]
	var original []fabric.ACLEntry
	policies := map[string]*fabric.ACLPolicy{}
	haveOriginal := false
	for _, r := range rows {
		entries, defined := r.device.Configuration.ACLs[name]
		if !defined {
			continue
		}
		if !haveOriginal {
			original, haveOriginal = entries, true
		}
		p, _ := r.device.Configuration.ResolveACL(name)
		policies[p.Key()] = p
	}
	if len(policies) != 1 {
		return nil
	}
	var policy *fabric.ACLPolicy
	for _, p := range policies {
		policy = p
	}
	if policy == nil {
		return nil
	}
	vrfs := map[string]bool{}
	for _, r := range rows {
		vrf := ""
		if r.service.SVI != nil {
			vrf = r.service.SVI.VRF
		}
		vrfs[vrf] = true
	}
	if len(vrfs) != 1 {
		return nil
	}
	var out []Increment
	for _, v := range views {
		current, _ := v.row.device.Configuration.ResolveACL(name)
		if v.bound && v.name == name && current != nil && current.Key() == policy.Key() {
			continue
		}
		_, defined := v.row.device.Configuration.ACLs[name]
		c := change.SVIACL{VLAN: *v.row.service.VLAN, VNI: vni, ACL: name, Direction: direction, Entries: original,
			AddressGroups: policy.AddressGroups, CreateACL: !defined}
		if v.bound {
			c.PreviousBinding = new(v.name)
		}
		if inc, ok := newIncrement(v.row.device.Host, "vxlan.fabric_acl_binding", c, v.row.device.Configuration); ok {
			out = append(out, inc)
		}
	}
	return out
}

// mappingSignature is the gateway identity a VLAN must share with donors.
func mappingSignature(c *fabric.Configuration, svi fabric.Interface) (string, bool) {
	if !fabric.True(svi.Anycast) || svi.VRF == "" || len(svi.Addresses) != 1 || c.AnycastMAC == "" {
		return "", false
	}
	var policies []string
	for _, direction := range []string{"in", "out"} {
		name, bound := svi.ACLBindings[direction]
		if !bound {
			continue
		}
		p, _ := c.ResolveACL(name)
		if p == nil {
			return "", false
		}
		policies = append(policies, direction+"="+p.Key())
	}
	shutdown, mtu := "-", "-"
	if svi.Shutdown != nil {
		shutdown = strconv.FormatBool(*svi.Shutdown)
	}
	if svi.MTU != nil {
		mtu = strconv.Itoa(*svi.MTU)
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s", svi.Addresses[0], svi.VRF, shutdown, mtu, c.AnycastMAC, strings.Join(policies, ";")), true
}

func transportSignature(c *fabric.Configuration, s fabric.Service, vni int, vrf string) (string, bool) {
	if s.Member == nil || s.EVPN == nil {
		return "", false
	}
	m := *s.Member
	v := vni
	return fmt.Sprintf("%v|%s|%s|%v|%s|%s", deref(m.AssociateVRF), m.Replication, m.MulticastGroup, deref(m.SuppressARP),
		s.EVPN.Type+"|"+fabric.RouteTargetsKey(c.ExpandRouteTargets(s.EVPN.RouteTargets, &v)), c.Tenant(vrf)), true
}

func deref(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

// inferMapping reproduces InferServiceMapping: complete, unique donors with
// one gateway signature and identical transport; exactly one unmapped VLAN
// on the device carries that signature; the gateway does not overlap other
// VNIs anywhere in the fabric.
func inferMapping(f *fabric.Fabric, vni int, row roleService, rows []roleService) (Increment, bool) {
	seen := map[string]bool{}
	var donors []roleService
	for _, peer := range rows {
		if seen[peer.device.Host] {
			return Increment{}, false
		}
		seen[peer.device.Host] = true
		if peer.device.Host == row.device.Host {
			continue
		}
		if !peer.service.Complete() || peer.service.SVI == nil {
			return Increment{}, false
		}
		donors = append(donors, peer)
	}
	if len(donors) == 0 {
		return Increment{}, false
	}
	signatures := map[string]bool{}
	var expected string
	var expectedSVI fabric.Interface
	for _, d := range donors {
		sig, ok := mappingSignature(d.device.Configuration, *d.service.SVI)
		if !ok {
			return Increment{}, false
		}
		signatures[sig] = true
		expected, expectedSVI = sig, *d.service.SVI
	}
	if len(signatures) != 1 {
		return Increment{}, false
	}
	transports := map[string]bool{}
	for _, peer := range append([]roleService{row}, donors...) {
		vrf := donors[0].service.SVI.VRF
		if peer.service.SVI != nil && peer.service.SVI.VRF != "" {
			vrf = peer.service.SVI.VRF
		}
		sig, ok := transportSignature(peer.device.Configuration, peer.service, vni, vrf)
		if !ok {
			return Increment{}, false
		}
		transports[sig] = true
	}
	if len(transports) != 1 {
		return Increment{}, false
	}
	c := row.device.Configuration
	var matches []int
	for vlan, mapped := range c.VLANVNIs {
		if mapped != nil {
			continue
		}
		id, err := strconv.Atoi(vlan)
		svi, ok := c.Interfaces["Vlan"+vlan]
		if err != nil || !ok {
			continue
		}
		if sig, ok := mappingSignature(c, svi); ok && sig == expected {
			matches = append(matches, id)
		}
	}
	if len(matches) != 1 {
		return Increment{}, false
	}
	m := change.VLANVNI{VLAN: matches[0], VNI: vni, VRF: expectedSVI.VRF, Address: expectedSVI.Addresses[0]}
	if len(gatewayConflicts(f, vni, m.VRF, m.Address, row.device.Host, fmt.Sprintf("Vlan%d", m.VLAN))) > 0 {
		return Increment{}, false
	}
	return newIncrement(row.device.Host, "vxlan.fabric_vlan_mapping_missing", m, c)
}

// IncrementRuleID identifies findings that carry an executable increment.
const IncrementRuleID assess.RuleID = "vxlan.remediation_increment"

var incrementMeta = assess.RuleMeta{
	ID: IncrementRuleID, Title: "可执行的配置增量（需逐项确认后下发）", Severity: assess.SeverityMedium, Category: assess.CategoryConfiguration,
}

// incrementRule reports each executable increment as a finding whose
// remediation is a candidate change with its exact commands and rollback.
func incrementRule(verify Verifier) fabricRule {
	return assess.NewRule(incrementMeta, func(in fabricInput) []assess.Finding {
		var out []assess.Finding
		for _, inc := range Increments(in.Model, verify) {
			out = append(out, assess.Finding{
				Subject: fabricSubject(in.Model).Child("device", inc.Host).Child("change", string(inc.Change.Kind())),
				Title:   inc.Title, Detail: inc.Scope, Verify: inc.Verify,
				Remediation: &assess.Remediation{Status: assess.RemediationCandidate, Change: inc.Change,
					Commands: inc.Script, Rollback: inc.Undo, Prerequisites: inc.Prerequisites, Impact: inc.Impact, Expected: inc.Expected},
			})
		}
		return out
	})
}
