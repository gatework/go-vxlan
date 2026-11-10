package rules

import (
	"regexp"
	"slices"
	"strconv"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-vxlan/fabric"
)

var (
	nveName               = regexp.MustCompile(`(?i)^nve[1-9]\d*$`)
	relationPrerequisites = []string{
		"确认该 VNI 应在本机承载业务，而非预配置或退网残留。",
		"核对当前软件版本、设备角色、同 Fabric 对端的 VLAN/VNI、RD/RT 与复制方式。",
		"重新采集配置并确认与本报告一致；审批维护窗口后逐台操作，出现异常先回读，勿盲目重放。",
	}
)

const (
	relationImpact   = "补齐可能开始发布路由或扩展二层广播域；须核对隔离边界、对端配置和回退条件。"
	relationExpected = "VLAN、NVE 与 EVPN 关联一致；预期承载业务的 VNI 状态 Up，BGP/对端正常，业务验收通过。"
)

// relationRemediation ports the legacy NVE/EVPN script suggestions. These
// kinds are not in the automatic execution whitelist, so a derivable fix is
// a manual script for operator review, never an executable change.
func relationRemediation(c *fabric.Configuration, rf fabric.RelationFinding) *assess.Remediation {
	r := &assess.Remediation{Status: assess.RemediationBlocked, Prerequisites: slices.Clone(relationPrerequisites), Impact: relationImpact, Expected: relationExpected}
	if rf.VNI == nil || *rf.VNI < 1 || *rf.VNI > 16777215 {
		r.Blockers = []string{"VNI 非有效整数，无法生成命令。"}
		return r
	}
	vni := *rf.VNI
	key := strconv.Itoa(vni)
	vlans := c.VLANsForVNI(vni)
	member, hasMember := c.NVE.Members[key]
	evpn, hasEVPN := c.EVPN[key]
	switch rf.Code {
	case "nve_l2_without_evpn":
		if l2Context(c, vni, vlans) && hasMember && !member.AssociateVRF && member.Replication == "bgp" && !hasEVPN && autoPolicy(c) {
			manual(r, evpnAdd(key), evpnRemove(key), "本机现有 L2 EVPN 均采用 RD auto、RT import/export auto；候选沿用此模式，仍需确认本 VNI 的业务意图。")
		} else {
			r.Blockers = []string{"需要唯一 VLAN 映射、L2 BGP 复制以及一致的 RD/RT 策略；缺失或冲突时不能套用 auto。"}
		}
	case "vlan_vni_without_nve", "evpn_vni_without_nve":
		auto := autoPolicy(c)
		if hasEVPN {
			auto = autoEVPN(evpn)
		}
		if l2Context(c, vni, vlans) && !hasMember && bgpReplication(c) && auto {
			commands := []string{"interface " + c.NVE.Interface, "  member vni " + key, "    ingress-replication protocol bgp", "exit", "exit"}
			rollback := []string{"interface " + c.NVE.Interface, "  no member vni " + key, "exit"}
			if !hasEVPN {
				commands = append(commands, evpnAdd(key)...)
				rollback = append(rollback, evpnRemove(key)...)
			}
			manual(r, commands, rollback, "本机既有 L2 成员统一使用 BGP 复制、EVPN auto 策略；仅补齐缺失的 NVE/EVPN，不启用额外 ARP 抑制。")
		} else {
			r.Blockers = []string{"需确认 VNI 的 L2/L3 角色、VLAN、NVE 接口、复制模式和 RD/RT，当前不能唯一确定增量配置。"}
		}
	case "nve_l2_without_vlan":
		r.Blockers = []string{"请提供本 VNI 对应 VLAN ID，并核对 access/trunk/SVI；不能由 VNI 尾数或其他设备名称猜测。"}
		r.Commands = []string{"vlan <VLAN_ID>", "  vn-segment " + key}
	default:
		r.Blockers = []string{"需要明确 VRF/VNI 业务映射和 L2/L3 角色；先核对设计，再补齐或清理残留配置。"}
	}
	return r
}

func manual(r *assess.Remediation, commands, rollback []string, assumption string) {
	r.Status = assess.RemediationManual
	r.Prerequisites = append(r.Prerequisites, assumption)
	r.Commands = slices.Concat([]string{"configure terminal"}, commands, []string{"end"})
	r.Rollback = slices.Concat([]string{"configure terminal"}, rollback, []string{"end"})
}

func l2Context(c *fabric.Configuration, vni int, vlans []int) bool {
	if !c.NVOverlayEVPN || c.NVE.Shutdown == nil || *c.NVE.Shutdown || c.NVE.HostReachability != "bgp" ||
		!nveName.MatchString(c.NVE.Interface) || len(vlans) != 1 || vlans[0] < 1 || vlans[0] > 4094 {
		return false
	}
	for _, v := range c.VRFs {
		if v.VNI != nil && *v.VNI == vni {
			return false
		}
	}
	return true
}

func autoPolicy(c *fabric.Configuration) bool {
	count := 0
	for _, e := range c.EVPN {
		if e.Type == "l2" {
			count++
			if !autoEVPN(e) {
				return false
			}
		}
	}
	return count > 0
}

func autoEVPN(e fabric.EVPNInstance) bool {
	if e.Type != "l2" || e.RD != "auto" || len(e.RouteTargets) != 2 {
		return false
	}
	var directions []string
	for _, rt := range e.RouteTargets {
		if rt.Target != "auto" || rt.EVPN {
			return false
		}
		directions = append(directions, rt.Direction)
	}
	slices.Sort(directions)
	return slices.Equal(directions, []string{"export", "import"})
}

func bgpReplication(c *fabric.Configuration) bool {
	count := 0
	for _, m := range c.NVE.Members {
		if m.AssociateVRF {
			continue
		}
		count++
		if m.Replication != "bgp" || m.MulticastGroup != "" {
			return false
		}
	}
	return count > 0
}

func evpnAdd(vni string) []string {
	return []string{"evpn", "  vni " + vni + " l2", "    rd auto", "    route-target import auto", "    route-target export auto", "exit", "exit"}
}

func evpnRemove(vni string) []string {
	return []string{"evpn", "  no vni " + vni + " l2", "exit"}
}
