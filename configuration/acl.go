package configuration

import (
	"regexp"
	"sort"
	"strings"

	"github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

// ACLRules projects ordered forwarding semantics, preserving unknown as nil.
func ACLRules(entries any) []vxlan.Record {
	rows, ok := record.RecordSlice(entries)
	if !ok {
		return nil
	}
	seen := map[int]bool{}
	for _, r := range rows {
		n := record.Number(r["sequence"])
		_, str := r["expression"].(string)
		if !record.Integer(r["sequence"], 1, 4294967295) || !record.Contains([]string{"permit", "deny", "remark"}, record.String(r["action"])) || !str || seen[n] {
			return nil
		}
		seen[n] = true
	}
	ordered := append([]vxlan.Record{}, rows...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return record.Number(ordered[i]["sequence"]) < record.Number(ordered[j]["sequence"])
	})
	out := []vxlan.Record{}
	for _, r := range ordered {
		if r["action"] != "remark" {
			out = append(out, record.Select(r, "action", "expression"))
		}
	}
	return out
}

var addressGroupPattern = regexp.MustCompile(`\baddrgroup\s+(\S+)`)

var unknownACLPattern = regexp.MustCompile(`\b(?:portgroup|object-group|time-range)\b`)

// ResolveACLPolicy returns ordered rules and the validated dependency snapshot.
func ResolveACLPolicy(config vxlan.Record, entries any) vxlan.Record {
	rules := ACLRules(entries)
	if rules == nil {
		return nil
	}
	names := []string{}
	for _, r := range rules {
		expr := r["expression"].(string)
		if unknownACLPattern.MatchString(expr) {
			return nil
		}
		for _, m := range addressGroupPattern.FindAllStringSubmatch(expr, -1) {
			names = append(names, m[1])
		}
	}
	groups := vxlan.Record{}
	for _, name := range record.UniqueSorted(names) {
		members, ok := record.Strings(record.Map(config["address_groups"])[name])
		if !ok || len(members) == 0 {
			return nil
		}
		for _, v := range members {
			p, e := Network(v)
			if e != nil || !strings.Contains(v, "/") || !p.Addr().Is4() {
				return nil
			}
		}
		groups[name] = record.UniqueSorted(members)
	}
	return record.Copy(vxlan.Record{"rules": rules, "address_groups": groups}).(vxlan.Record)
}

// ACLBindings enumerates all interfaces/directions affected by an ACL definition.
func ACLBindings(config vxlan.Record, name string) []vxlan.Record {
	out := []vxlan.Record{}
	interfaces := record.Map(config["interfaces"])
	for _, n := range record.Keys(interfaces) {
		b := record.Map(record.Map(interfaces[n])["acl_bindings"])
		for _, direction := range record.Keys(b) {
			if b[direction] == name {
				out = append(out, vxlan.Record{"interface": n, "direction": direction})
			}
		}
	}
	return out
}

// AddressGroupReferences lists address groups referenced by an ACL expression.
func AddressGroupReferences(expression string) []string {
	out := []string{}
	for _, match := range addressGroupPattern.FindAllStringSubmatch(expression, -1) {
		out = append(out, match[1])
	}
	return out
}
