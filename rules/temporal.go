package rules

import (
	"slices"
	"strconv"
	"strings"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-netops/drift"
	"github.com/gatework/go-netops/evidence"
	"github.com/gatework/go-vxlan/fabric"
)

// Change is one device observed in two batches.
type Change struct {
	Previous, Current *fabric.Device
}

// Coverage is complete for a dimension only when both snapshots have it, so
// a change is never inferred from evidence missing on one side.
func (c *Change) Coverage() evidence.Coverage {
	out := evidence.Coverage{}
	for _, dim := range fabric.Dimensions() {
		p, q := c.Previous.Coverage.Status(dim), c.Current.Coverage.Status(dim)
		switch {
		case p.Complete() && q.Complete():
			out[dim] = evidence.StatusComplete
		case p == evidence.StatusNotRequested && q == evidence.StatusNotRequested:
			out[dim] = evidence.StatusNotRequested
		default:
			out[dim] = evidence.StatusPartial
		}
	}
	return out
}

type temporalRule = assess.Rule[*Change]
type temporalInput = assess.Input[*Change]

// TemporalRules report what changed since the previous batch.
func TemporalRules() []assess.Rule[*Change] {
	return []temporalRule{configChanged, servicesChanged, nvePeersLost, bgpSessionsLost, ospfLost, vpcPeerChanged}
}

func changeMeta(id assess.RuleID, title string, sev assess.Severity, dims ...evidence.Dimension) assess.RuleMeta {
	return assess.RuleMeta{ID: id, Title: title, Severity: sev, Category: assess.CategoryDrift, Requires: dims, Verify: dims}
}

func changeSubject(c *Change) assess.Subject { return device(c.Current) }

var configChanged = assess.NewRule(changeMeta("vxlan.change_configuration", "运行配置自上次采集后已变化", assess.SeverityInfo, fabric.DimConfiguration), func(in temporalInput) []assess.Finding {
	p, q := in.Model.Previous.Configuration, in.Model.Current.Configuration
	if p == nil || q == nil || p.ConfigDigest == q.ConfigDigest {
		return nil
	}
	return []assess.Finding{{Subject: changeSubject(in.Model), Expected: p.ConfigDigest, Actual: q.ConfigDigest,
		Detail: "核对变更单；配置差异以两次采集的原文为准"}}
})

func serviceMap(c *fabric.Configuration) map[int]int {
	out := map[int]int{}
	if c == nil {
		return out
	}
	for _, s := range c.Services() {
		vlan := 0
		if s.VLAN != nil {
			vlan = *s.VLAN
		}
		out[s.VNI] = vlan
	}
	return out
}

var servicesChanged = assess.NewRule(changeMeta("vxlan.change_services", "L2 业务（VNI/VLAN）新增、删除或重映射", assess.SeverityMedium, fabric.DimConfiguration), func(in temporalInput) []assess.Finding {
	subject := func(vni int) assess.Subject { return changeSubject(in.Model).Child("vni", strconv.Itoa(vni)) }
	var out []assess.Finding
	for _, d := range drift.Changes(subject, "services.vlan", serviceMap(in.Model.Previous.Configuration), serviceMap(in.Model.Current.Configuration)) {
		f := driftFinding(d)
		if d.Kind == drift.KindMissing {
			f.Severity = assess.SeverityHigh // a removed service is the riskiest change
		}
		out = append(out, f)
	}
	return out
})

// lost reports keys that were healthy before and are not healthy now.
func lost(subject assess.Subject, kind string, before, after []string) []assess.Finding {
	var out []assess.Finding
	for _, k := range before {
		if !slices.Contains(after, k) {
			out = append(out, assess.Finding{Subject: subject.Child(kind, k), Expected: "up", Actual: "not up"})
		}
	}
	return out
}

func upPeers(d *fabric.Device) []string {
	var out []string
	for _, p := range d.NVEPeers {
		if strings.EqualFold(p.State, "up") {
			out = append(out, p.PeerIP)
		}
	}
	return out
}

var nvePeersLost = assess.NewRule(changeMeta("vxlan.change_nve_peers_lost", "上次为 Up 的 NVE peer 已消失或不再 Up", assess.SeverityHigh, fabric.DimNVEPeers), func(in temporalInput) []assess.Finding {
	return lost(changeSubject(in.Model), "nve_peer", upPeers(in.Model.Previous), upPeers(in.Model.Current))
})

func establishedPeers(d *fabric.Device) []string {
	var out []string
	for _, n := range d.BGPNeighbors {
		if strings.EqualFold(n.State, "established") {
			out = append(out, n.VRF+"/"+n.PeerIP)
		}
	}
	return out
}

var bgpSessionsLost = assess.NewRule(changeMeta("vxlan.change_bgp_sessions_lost", "上次已建立的 BGP EVPN 会话已断开", assess.SeverityHigh, fabric.DimBGP), func(in temporalInput) []assess.Finding {
	return lost(changeSubject(in.Model), "bgp_peer", establishedPeers(in.Model.Previous), establishedPeers(in.Model.Current))
})

func fullNeighbors(d *fabric.Device) []string {
	var out []string
	for _, n := range d.OSPFNeighbors {
		if strings.HasPrefix(strings.ToLower(n.State), "full") {
			out = append(out, n.Process+"/"+n.NeighborID)
		}
	}
	return out
}

var ospfLost = assess.NewRule(changeMeta("vxlan.change_ospf_lost", "上次为 FULL 的 OSPF 邻居已丢失", assess.SeverityHigh, fabric.DimOSPF), func(in temporalInput) []assess.Finding {
	return lost(changeSubject(in.Model), "ospf_neighbor", fullNeighbors(in.Model.Previous), fullNeighbors(in.Model.Current))
})

var vpcPeerChanged = assess.NewRule(changeMeta("vxlan.change_vpc_peer", "vPC 对等/keepalive 状态较上次变化", assess.SeverityHigh, fabric.DimVPC), func(in temporalInput) []assess.Finding {
	p, q := in.Model.Previous.VPC, in.Model.Current.VPC
	if p == nil || q == nil {
		return nil
	}
	var out []assess.Finding
	for _, c := range []struct{ path, before, after string }{
		{"vpc.peer_status", p.PeerStatus, q.PeerStatus}, {"vpc.keepalive_status", p.KeepaliveStatus, q.KeepaliveStatus},
		{"vpc.role", p.Role, q.Role},
	} {
		if !strings.EqualFold(c.before, c.after) {
			out = append(out, assess.Finding{Subject: changeSubject(in.Model).Child("status", c.path), Expected: c.before, Actual: c.after})
		}
	}
	return out
})
