package fabric

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// ACLRule is one ordered forwarding rule (remarks removed).
type ACLRule struct {
	Action     string `json:"action"`
	Expression string `json:"expression"`
}

// ACLPolicy is an ACL's forwarding semantics with its resolved address
// groups: two ACLs are equivalent exactly when their policies are equal.
type ACLPolicy struct {
	Rules         []ACLRule           `json:"rules"`
	AddressGroups map[string][]string `json:"address_groups"`
}

// Key is a canonical identity for comparing policies across devices.
func (p *ACLPolicy) Key() string {
	if p == nil {
		return ""
	}
	var b strings.Builder
	for _, r := range p.Rules {
		fmt.Fprintf(&b, "%s %s\n", r.Action, r.Expression)
	}
	for _, name := range sortedKeys(p.AddressGroups) {
		fmt.Fprintf(&b, "group %s %s\n", name, strings.Join(p.AddressGroups[name], ","))
	}
	return b.String()
}

var (
	addressGroupRef = regexp.MustCompile(`\baddrgroup\s+(\S+)`)
	unresolvableACL = regexp.MustCompile(`\b(?:portgroup|object-group|time-range)\b`)
)

// AddressGroupRefs lists the address groups an ACL expression references.
func AddressGroupRefs(expression string) []string {
	var out []string
	for _, m := range addressGroupRef.FindAllStringSubmatch(expression, -1) {
		out = append(out, m[1])
	}
	return out
}

// MaxACLSequence is the highest NX-OS ACL sequence number.
const MaxACLSequence = 4294967295

// OrderedRules returns the ACL's rules by sequence without remarks, or nil
// when sequences are invalid or duplicated, which leaves its order unknown.
func OrderedRules(entries []ACLEntry) []ACLRule {
	if entries == nil {
		return nil // not a rule list: order unknown, unlike an empty ACL
	}
	seen := map[int]bool{}
	for _, e := range entries {
		if e.Sequence < 1 || e.Sequence > MaxACLSequence || seen[e.Sequence] || !slices.Contains([]string{"permit", "deny", "remark"}, e.Action) {
			return nil
		}
		seen[e.Sequence] = true
	}
	ordered := slices.Clone(entries)
	slices.SortStableFunc(ordered, func(a, b ACLEntry) int { return a.Sequence - b.Sequence })
	out := []ACLRule{}
	for _, e := range ordered {
		if e.Action != "remark" {
			out = append(out, ACLRule{Action: e.Action, Expression: e.Expression})
		}
	}
	return out
}

// ResolveACL returns the named ACL's policy. defined reports whether the ACL
// exists; a defined ACL with a nil policy has dependencies that cannot be
// verified (unknown object types, or missing, empty or non-IPv4 groups).
func (c *Configuration) ResolveACL(name string) (policy *ACLPolicy, defined bool) {
	entries, defined := c.ACLs[name]
	if !defined {
		return nil, false
	}
	rules := OrderedRules(entries)
	if rules == nil {
		return nil, true
	}
	var names []string
	for _, r := range rules {
		if unresolvableACL.MatchString(r.Expression) {
			return nil, true
		}
		names = append(names, AddressGroupRefs(r.Expression)...)
	}
	groups := map[string][]string{}
	for _, g := range sortedUnique(names) {
		members := c.AddressGroups[g]
		if len(members) == 0 {
			return nil, true
		}
		for _, m := range members {
			p, err := netip.ParsePrefix(m)
			if err != nil || !p.Addr().Is4() {
				return nil, true
			}
		}
		groups[g] = sortedUnique(members)
	}
	return &ACLPolicy{Rules: rules, AddressGroups: groups}, true
}

func sortedUnique(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return slices.Compact(out)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// RouteTargetKey is one expanded route target: "both" split into import and
// export, and "auto" resolved to ASN:VNI for two-byte ASNs.
type RouteTargetKey struct {
	AddressFamily string
	EVPN          bool
	Direction     string
	Target        string
}

// ExpandRouteTargets normalizes route targets for comparison, sorted and
// deduplicated.
func (c *Configuration) ExpandRouteTargets(targets []RouteTarget, vni *int) []RouteTargetKey {
	var out []RouteTargetKey
	for _, rt := range targets {
		directions := []string{rt.Direction}
		if rt.Direction == "both" {
			directions = []string{"import", "export"}
		}
		for _, d := range directions {
			target := rt.Target
			if target == "auto" {
				switch {
				case c.BGP.ASN != nil && *c.BGP.ASN >= 1 && *c.BGP.ASN <= 65535 && vni != nil:
					target = fmt.Sprintf("%d:%d", *c.BGP.ASN, *vni)
				default:
					target = fmt.Sprintf("auto(%v,%v)", deref(c.BGP.ASN), deref(vni))
				}
			}
			out = append(out, RouteTargetKey{AddressFamily: rt.AddressFamily, EVPN: rt.EVPN, Direction: d, Target: target})
		}
	}
	slices.SortFunc(out, func(a, b RouteTargetKey) int { return strings.Compare(a.String(), b.String()) })
	return slices.Compact(out)
}

func (k RouteTargetKey) String() string {
	return fmt.Sprintf("%s|%t|%s|%s", k.AddressFamily, k.EVPN, k.Direction, k.Target)
}

func deref(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

// RouteTargetsKey joins expanded route targets into one comparable identity.
func RouteTargetsKey(keys []RouteTargetKey) string {
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k.String()
	}
	return strings.Join(parts, ";")
}

// Tenant returns the comparable identity of a VRF: its L3 VNI and expanded
// route targets, or "" when the VRF is not defined.
func (c *Configuration) Tenant(vrf string) string {
	v, ok := c.VRFs[vrf]
	if !ok {
		return ""
	}
	return fmt.Sprintf("%s|%v|%s", vrf, deref(v.VNI), RouteTargetsKey(c.ExpandRouteTargets(v.RouteTargets, v.VNI)))
}
