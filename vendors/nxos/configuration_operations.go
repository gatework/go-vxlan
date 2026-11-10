package nxos

import (
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	vxlan "github.com/gatework/go-vxlan"
)

// Operational statements the relational parser leaves ignored but that
// operations reviews need: management servers, trunk and relay settings,
// vPC domain options and VLAN names. The pass is read-only over the block
// tree: it never changes line states or existing record keys, and it never
// captures credentials (TACACS keys, SNMP communities, passwords).
var (
	opServer        = regexp.MustCompile(`^(ntp server|logging server|tacacs-server host|snmp-server host)\s+(\S+)(.*)$`)
	opUseVRF        = regexp.MustCompile(`\buse-vrf\s+(\S+)`)
	opInfraVLANs    = regexp.MustCompile(`^system nve infra-vlans\s+([\d,\- ]+)$`)
	opVLANBlock     = regexp.MustCompile(`^vlan (\d+)$`)
	opVLANName      = regexp.MustCompile(`^name\s+(\S+)$`)
	opInterface     = regexp.MustCompile(`^interface (\S+)$`)
	opTrunkAllowed  = regexp.MustCompile(`^switchport trunk allowed vlan(?: (add|remove|except))? (\S+)$`)
	opDHCPRelay     = regexp.MustCompile(`^ip dhcp relay address (\S+)(.*)$`)
	opVPCDomain     = regexp.MustCompile(`^vpc domain \d+$`)
	opDelayRestore  = regexp.MustCompile(`^delay restore (\d+)$`)
	opAutoRecovery  = regexp.MustCompile(`^auto-recovery(?: reload-delay \d+)?$`)
	opVLANListToken = regexp.MustCompile(`^(?:\d+(?:-\d+)?)(?:,\d+(?:-\d+)?)*$`)
)

var serverKeys = map[string]string{
	"ntp server": "ntp_servers", "logging server": "logging_servers",
	"tacacs-server host": "tacacs_servers", "snmp-server host": "snmp_hosts",
}

func opServerRecord(address, rest string) (vxlan.Record, bool) {
	a, err := netip.ParseAddr(address)
	if err != nil {
		return nil, false
	}
	r := vxlan.Record{"address": a.String()}
	if m := opUseVRF.FindStringSubmatch(rest); m != nil {
		r["vrf"] = m[1]
	}
	return r, true
}

func extractOperations(blocks []*cfgBlock) vxlan.Record {
	ops := vxlan.Record{}
	appendTo := func(key string, v any) { ops[key] = append(ops[key].([]any), v) }
	ensureList := func(key string) {
		if _, ok := ops[key]; !ok {
			ops[key] = []any{}
		}
	}
	ensureMap := func(key string) vxlan.Record {
		if m, ok := ops[key].(vxlan.Record); ok {
			return m
		}
		m := vxlan.Record{}
		ops[key] = m
		return m
	}
	for _, b := range blocks {
		t := strings.TrimSpace(b.text)
		switch {
		case opServer.MatchString(t):
			m := opServer.FindStringSubmatch(t)
			if r, ok := opServerRecord(m[2], m[3]); ok {
				ensureList(serverKeys[m[1]])
				appendTo(serverKeys[m[1]], r)
			}
		case opInfraVLANs.MatchString(t):
			ops["nve_infra_vlans"] = strings.ReplaceAll(opInfraVLANs.FindStringSubmatch(t)[1], " ", "")
		case opVLANBlock.MatchString(t):
			id := opVLANBlock.FindStringSubmatch(t)[1]
			for _, c := range b.children {
				if m := opVLANName.FindStringSubmatch(strings.TrimSpace(c.text)); m != nil {
					ensureMap("vlan_names")[id] = m[1]
				}
			}
		case opInterface.MatchString(t):
			name := opInterface.FindStringSubmatch(t)[1]
			if strings.HasPrefix(strings.ToLower(name), "vlan") {
				name = "Vlan" + name[4:]
			}
			for _, c := range b.children {
				ct := strings.TrimSpace(c.text)
				if m := opTrunkAllowed.FindStringSubmatch(ct); m != nil {
					trunks := ensureMap("trunk_allowed")
					prev, _ := trunks[name].(string)
					trunks[name] = applyTrunkAllowed(prev, m[1], m[2])
				} else if m := opDHCPRelay.FindStringSubmatch(ct); m != nil {
					if r, ok := opServerRecord(m[1], m[2]); ok {
						relays := ensureMap("dhcp_relays")
						relays[name] = append(listOf(relays[name]), r)
					}
				} else if ct == "port-type fabric" {
					ensureList("fabric_ports")
					appendTo("fabric_ports", name)
				}
			}
		case opVPCDomain.MatchString(t):
			vpc := vxlan.Record{}
			for _, c := range b.children {
				ct := strings.TrimSpace(c.text)
				switch {
				case opAutoRecovery.MatchString(ct):
					vpc["auto_recovery"] = true
				case opDelayRestore.MatchString(ct):
					if n, err := strconv.Atoi(opDelayRestore.FindStringSubmatch(ct)[1]); err == nil {
						vpc["delay_restore"] = n
					}
				case ct == "ip arp synchronize":
					vpc["arp_synchronize"] = true
				case ct == "ipv6 nd synchronize":
					vpc["nd_synchronize"] = true
				case ct == "fast-convergence":
					vpc["fast_convergence"] = true
				}
			}
			if len(vpc) > 0 {
				ops["vpc"] = vpc
			}
		}
	}
	if len(ops) == 0 {
		return nil
	}
	return ops
}

func listOf(v any) []any {
	l, _ := v.([]any)
	return l
}

// applyTrunkAllowed folds one "switchport trunk allowed vlan" statement into
// the allowed list: a canonical range list, "all" or "none". An
// unrecognized statement yields "unknown", which never proves a VLAN allowed.
func applyTrunkAllowed(prev, op, list string) string {
	switch {
	case op == "" && (list == "all" || list == "none"):
		return list
	case !opVLANListToken.MatchString(list) || prev == "unknown":
		return "unknown"
	}
	current := expandVLANs(list)
	switch op {
	case "":
		return compressVLANs(current)
	case "add":
		if prev == "all" {
			return "all"
		}
		return compressVLANs(append(expandVLANs(prev), current...))
	case "remove", "except":
		// The remaining set from "all" is not enumerable without the platform range.
		if prev == "all" || prev == "" || op == "except" {
			return "unknown"
		}
		return compressVLANs(slices.DeleteFunc(expandVLANs(prev), func(v int) bool { return slices.Contains(current, v) }))
	}
	return "unknown"
}

func expandVLANs(list string) []int {
	var out []int
	if list == "" || list == "none" {
		return out
	}
	for part := range strings.SplitSeq(list, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a || b-a > 4094 {
				continue
			}
		}
		for v := a; v <= b; v++ {
			out = append(out, v)
		}
	}
	return out
}

func compressVLANs(vlans []int) string {
	slices.Sort(vlans)
	vlans = slices.Compact(vlans)
	if len(vlans) == 0 {
		return "none"
	}
	var parts []string
	for i := 0; i < len(vlans); {
		j := i
		for j+1 < len(vlans) && vlans[j+1] == vlans[j]+1 {
			j++
		}
		if i == j {
			parts = append(parts, strconv.Itoa(vlans[i]))
		} else {
			parts = append(parts, strconv.Itoa(vlans[i])+"-"+strconv.Itoa(vlans[j]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}
