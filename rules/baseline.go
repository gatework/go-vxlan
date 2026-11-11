package rules

import (
	"maps"
	"slices"
	"strconv"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-netops/drift"
	"github.com/gatework/go-vxlan/fabric"
)

// BaselineScope is one fabric with its effective declared intent.
type BaselineScope struct {
	Fabric *fabric.Fabric
	Expect fabric.Expectation
}

type baselineRule = assess.Rule[*BaselineScope]
type baselineInput = assess.Input[*BaselineScope]

// BaselineRules compare each fabric with its declared intent. Every finding
// is a drift from the baseline, never from peers, so a fabric whose members
// all agree on a wrong value is still reported.
func BaselineRules() []assess.Rule[*BaselineScope] {
	return []baselineRule{baselineAnycastMAC, baselineSVIMTU, baselineFeatures, baselineNVE, baselineEVPNAuto,
		baselineServices, baselineManagement, baselineVPC}
}

func baselineMeta(id assess.RuleID, title string, sev assess.Severity) assess.RuleMeta {
	return assess.RuleMeta{ID: id, Title: title, Severity: sev, Category: assess.CategoryDrift}
}

// vteps returns fully configured VTEPs; baseline rules, like fabric rules,
// draw no conclusion from incomplete fabrics.
func vteps(s *BaselineScope) []*fabric.Device {
	if !configured(s.Fabric) {
		return nil
	}
	return s.Fabric.VTEPs()
}

func deviceIn(s *BaselineScope, d *fabric.Device) assess.Subject {
	return fabricSubject(s.Fabric).Child("device", d.Host)
}

func driftFinding(d drift.Deviation) assess.Finding {
	return d.Finding(d.Path + " " + string(d.Kind))
}

var baselineAnycastMAC = assess.NewRule(baselineMeta("vxlan.baseline_anycast_mac", "Anycast 网关 MAC 偏离基线", assess.SeverityHigh), func(in baselineInput) []assess.Finding {
	want := in.Model.Expect.AnycastGatewayMAC
	if want == nil {
		return nil
	}
	var out []assess.Finding
	for _, d := range vteps(in.Model) {
		if !slices.ContainsFunc(d.Configuration.Services(), func(s fabric.Service) bool { return s.Gateway() }) {
			continue
		}
		mac := d.Configuration.AnycastMAC
		if dev, ok := drift.Expect(deviceIn(in.Model, d), "anycast_gateway_mac", *want, mac, mac != ""); ok {
			out = append(out, driftFinding(dev))
		}
	}
	return out
})

var baselineSVIMTU = assess.NewRule(baselineMeta("vxlan.baseline_svi_mtu", "业务 SVI MTU 偏离基线", assess.SeverityMedium), func(in baselineInput) []assess.Finding {
	want := in.Model.Expect.SVIMTU
	if want == nil {
		return nil
	}
	var out []assess.Finding
	for _, d := range vteps(in.Model) {
		for _, s := range d.Configuration.Services() {
			if !s.Gateway() {
				continue
			}
			mtu := 0
			if s.SVI.MTU != nil {
				mtu = *s.SVI.MTU
			}
			subject := deviceIn(in.Model, d).Child("vni", strconv.Itoa(s.VNI))
			if dev, ok := drift.Expect(subject, "svi.mtu", *want, mtu, s.SVI.MTU != nil); ok {
				out = append(out, driftFinding(dev))
			}
		}
	}
	return out
})

var baselineFeatures = assess.NewRule(baselineMeta("vxlan.baseline_features", "VTEP 缺少基线要求的 feature", assess.SeverityHigh), func(in baselineInput) []assess.Finding {
	want := in.Model.Expect.RequiredFeatures
	if len(want) == 0 {
		return nil
	}
	var out []assess.Finding
	for _, d := range vteps(in.Model) {
		for _, dev := range drift.Sets(deviceIn(in.Model, d), "features", want, d.Configuration.Features) {
			if dev.Kind == drift.KindMissing { // extra features are not drift
				out = append(out, driftFinding(dev))
			}
		}
	}
	return out
})

var baselineNVE = assess.NewRule(baselineMeta("vxlan.baseline_nve", "NVE 配置偏离基线", assess.SeverityHigh), func(in baselineInput) []assess.Finding {
	e := in.Model.Expect.NVE
	if e == nil {
		return nil
	}
	var out []assess.Finding
	for _, d := range vteps(in.Model) {
		c := d.Configuration
		subject := deviceIn(in.Model, d)
		check := func(path string, want *string, got string) {
			if want != nil {
				if dev, ok := drift.Expect(subject, path, *want, got, got != ""); ok {
					out = append(out, driftFinding(dev))
				}
			}
		}
		check("nve.host_reachability", e.HostReachability, c.NVE.HostReachability)
		check("nve.source_interface", e.SourceInterface, canonicalLoopback(c.NVE.SourceInterface))
		for _, s := range c.Services() {
			if s.Member == nil {
				continue
			}
			vni := subject.Child("vni", strconv.Itoa(s.VNI))
			if e.Replication != nil {
				if dev, ok := drift.Expect(vni, "nve.replication", *e.Replication, s.Member.Replication, s.Member.Replication != ""); ok {
					out = append(out, driftFinding(dev))
				}
			}
			if e.SuppressARP != nil {
				got := s.Member.SuppressARP != nil && *s.Member.SuppressARP
				if dev, ok := drift.Expect(vni, "nve.suppress_arp", *e.SuppressARP, got, true); ok {
					out = append(out, driftFinding(dev))
				}
			}
		}
	}
	return out
})

var baselineEVPNAuto = assess.NewRule(baselineMeta("vxlan.baseline_evpn_auto", "EVPN 实例的 RD/RT 偏离基线（auto）", assess.SeverityMedium), func(in baselineInput) []assess.Finding {
	want := in.Model.Expect.EVPNAutoRDRT
	if want == nil {
		return nil
	}
	var out []assess.Finding
	for _, d := range vteps(in.Model) {
		for _, key := range slices.Sorted(maps.Keys(d.Configuration.EVPN)) {
			e := d.Configuration.EVPN[key]
			if e.Type != "l2" {
				continue
			}
			if dev, ok := drift.Expect(deviceIn(in.Model, d).Child("vni", key), "evpn.auto_rd_rt", *want, autoEVPN(e), true); ok {
				out = append(out, driftFinding(dev))
			}
		}
	}
	return out
})

var baselineServices = assess.NewRule(baselineMeta("vxlan.baseline_services", "VNI/VLAN 业务映射偏离基线", assess.SeverityHigh), func(in baselineInput) []assess.Finding {
	want := in.Model.Expect.Services
	if len(want) == 0 {
		return nil
	}
	var out []assess.Finding
	for _, d := range vteps(in.Model) {
		for _, s := range d.Configuration.Services() {
			subject := deviceIn(in.Model, d).Child("vni", strconv.Itoa(s.VNI))
			vlan, declared := want[s.VNI]
			switch {
			case !declared:
				out = append(out, assess.Finding{Category: assess.CategoryDrift, Subject: subject, Severity: assess.SeverityLow,
					Detail: "services unexpected", Actual: s.VLAN})
			case s.VLAN == nil:
				// Reported by fabric_vlan_mapping_missing / service_incomplete.
			default:
				if dev, ok := drift.Expect(subject, "services.vlan", vlan, *s.VLAN, true); ok {
					out = append(out, driftFinding(dev))
				}
			}
		}
	}
	return out
})

var baselineManagement = assess.NewRule(baselineMeta("vxlan.baseline_management", "管理平面服务器偏离基线", assess.SeverityMedium), func(in baselineInput) []assess.Finding {
	m := in.Model.Expect.Management
	if m == nil || !configured(in.Model.Fabric) {
		return nil
	}
	expected := map[string][]string{"ntp": m.NTP, "logging": m.Logging, "tacacs": m.TACACS, "snmp": m.SNMP}
	var out []assess.Finding
	for _, d := range in.Model.Fabric.Members {
		for _, k := range serverKinds {
			want := expected[k.name]
			if want == nil {
				continue
			}
			for _, dev := range drift.Sets(deviceIn(in.Model, d).Child("management", k.name), "management."+k.name, want, fabric.Addresses(k.get(ops(d.Configuration)))) {
				out = append(out, driftFinding(dev))
			}
		}
	}
	return out
})

var baselineVPC = assess.NewRule(baselineMeta("vxlan.baseline_vpc", "vPC 域选项偏离基线", assess.SeverityMedium), func(in baselineInput) []assess.Finding {
	e := in.Model.Expect.VPC
	if e == nil || !configured(in.Model.Fabric) {
		return nil
	}
	var out []assess.Finding
	for _, d := range in.Model.Fabric.Members {
		c := d.Configuration
		if c.VPCDomain == nil {
			continue
		}
		o := ops(c).VPC
		if o == nil {
			o = &fabric.VPCOptions{}
		}
		subject := deviceIn(in.Model, d).Child("vpc_domain", strconv.Itoa(c.VPCDomain.ID))
		flag := func(path string, want *bool, got bool) {
			if want != nil {
				if dev, ok := drift.Expect(subject, path, *want, got, true); ok {
					out = append(out, driftFinding(dev))
				}
			}
		}
		flag("vpc.peer_gateway", e.PeerGateway, c.VPCDomain.PeerGateway)
		flag("vpc.auto_recovery", e.AutoRecovery, o.AutoRecovery)
		flag("vpc.arp_synchronize", e.ARPSynchronize, o.ARPSynchronize)
		if e.DelayRestore != nil {
			got := 0
			if o.DelayRestore != nil {
				got = *o.DelayRestore
			}
			if dev, ok := drift.Expect(subject, "vpc.delay_restore", *e.DelayRestore, got, o.DelayRestore != nil); ok {
				out = append(out, driftFinding(dev))
			}
		}
	}
	return out
})

// DeriveBaseline proposes a baseline from each fabric's current majority
// values. It is a starting point for operators to review and freeze, not an
// assertion that the current state is correct; attributes without a clear
// majority are left undeclared.
func DeriveBaseline(m *fabric.Model) fabric.Baseline {
	b := fabric.Baseline{SchemaVersion: fabric.BaselineSchemaVersion, Fabrics: map[string]fabric.Expectation{}}
	for _, f := range m.Fabrics {
		if !configured(f) {
			continue
		}
		e := deriveFabricBaseline(f)
		b.Fabrics[f.Name] = e
	}
	return b
}

func deriveFabricBaseline(f *fabric.Fabric) fabric.Expectation {
	var e fabric.Expectation
	vt := f.VTEPs()
	majority := func(values []string) (string, bool) {
		var ms []drift.Member[string]
		for _, v := range values {
			ms = append(ms, drift.Member[string]{Value: v, Present: v != ""})
		}
		v, ok, _ := drift.Consensus("", ms)
		return v, ok
	}
	var macs, mtus, reach, source []string
	services := map[int][]string{}
	for _, d := range vt {
		c := d.Configuration
		macs = append(macs, c.AnycastMAC)
		reach = append(reach, c.NVE.HostReachability)
		source = append(source, canonicalLoopback(c.NVE.SourceInterface))
		for _, s := range c.Services() {
			if s.Gateway() && s.SVI.MTU != nil {
				mtus = append(mtus, strconv.Itoa(*s.SVI.MTU))
			}
			if s.VLAN != nil {
				services[s.VNI] = append(services[s.VNI], strconv.Itoa(*s.VLAN))
			}
		}
	}
	if v, ok := majority(macs); ok && v != "" {
		e.AnycastGatewayMAC = &v
	}
	if v, ok := majority(mtus); ok && v != "" {
		n, _ := strconv.Atoi(v)
		e.SVIMTU = &n
	}
	nve := &fabric.NVEExpectation{}
	if v, ok := majority(reach); ok && v != "" {
		nve.HostReachability = &v
	}
	if v, ok := majority(source); ok && v != "" {
		nve.SourceInterface = &v
	}
	if nve.HostReachability != nil || nve.SourceInterface != nil {
		e.NVE = nve
	}
	e.Services = map[int]int{}
	for vni, vlans := range services {
		if v, ok := majority(vlans); ok && v != "" {
			n, _ := strconv.Atoi(v)
			e.Services[vni] = n
		}
	}
	mgmt := deriveManagementBaseline(f, majority)
	if mgmt.NTP != nil || mgmt.Logging != nil || mgmt.TACACS != nil || mgmt.SNMP != nil {
		e.Management = mgmt
	}
	return e
}

func deriveManagementBaseline(f *fabric.Fabric, majority func([]string) (string, bool)) *fabric.ManagementExpectation {
	mgmt := &fabric.ManagementExpectation{}
	for _, k := range serverKinds {
		var sets []string
		byKey := map[string][]string{}
		for _, d := range f.Members {
			addrs := fabric.Addresses(k.get(ops(d.Configuration)))
			key := joinSorted(addrs)
			byKey[key] = addrs
			sets = append(sets, key)
		}
		if v, ok := majority(sets); ok && v != "" {
			switch k.name {
			case "ntp":
				mgmt.NTP = byKey[v]
			case "logging":
				mgmt.Logging = byKey[v]
			case "tacacs":
				mgmt.TACACS = byKey[v]
			case "snmp":
				mgmt.SNMP = byKey[v]
			}
		}
	}
	return mgmt
}
