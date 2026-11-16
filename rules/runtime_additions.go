package rules

import (
	"math/big"
	"strings"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-netops/evidence"
	"github.com/gatework/go-vxlan/fabric"
)

var bgpCapabilityGap = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.bgp_evpn_capability_gap", Title: "BGP EVPN 配置数与 capable 数量不同",
	Severity: assess.SeverityMedium, Category: assess.CategoryRuntime,
	Requires: []evidence.Dimension{fabric.DimBGP}, Verify: []evidence.Dimension{fabric.DimBGP, fabric.DimConfiguration},
}, func(in deviceInput) []assess.Finding {
	var out []assess.Finding
	for _, summary := range in.Model.BGPSummaries {
		if summary.ConfiguredPeers == nil || summary.CapablePeers == nil {
			continue
		}
		configured, validConfig := new(big.Int).SetString(summary.ConfiguredPeers.String(), 10)
		capable, validCapable := new(big.Int).SetString(summary.CapablePeers.String(), 10)
		if !validConfig || !validCapable {
			continue
		}
		if capable.Sign() < 0 || configured.Cmp(capable) <= 0 {
			continue
		}
		out = append(out, assess.Finding{
			Subject: device(in.Model).Child("vrf", summary.VRF), Actual: summary,
			Detail: "核对 address-family、维护意图与对端能力；两种计数不同，不据此补造邻居或判定业务中断。",
		})
	}
	return out
})

func configuredInterfaces(d *fabric.Device) map[string]*fabric.Interface {
	index := map[string]*fabric.Interface{}
	if !d.Has(fabric.DimConfiguration) || !d.Configuration.Complete() {
		return index
	}
	for name, iface := range d.Configuration.Interfaces {
		key := canonicalInterface(name)
		if _, exists := index[key]; exists {
			index[key] = nil
		} else {
			index[key] = &iface
		}
	}
	return index
}

func canonicalInterface(name string) string {
	name = strings.ToLower(name)
	for _, pair := range [][2]string{{"ethernet", "eth"}, {"port-channel", "po"}, {"loopback", "lo"}} {
		if suffix, ok := strings.CutPrefix(name, pair[0]); ok {
			return pair[1] + suffix
		}
	}
	return name
}

var configuredInterfaceDown = assess.NewRule(assess.RuleMeta{
	ID: "vxlan.configured_interface_down", Title: "明确启用且具有网络角色的接口未建立",
	Severity: assess.SeverityMedium, Category: assess.CategoryRuntime,
	Requires: []evidence.Dimension{fabric.DimConfiguration, fabric.DimInterfaces},
	Verify:   []evidence.Dimension{fabric.DimInterfaces, fabric.DimConfiguration},
}, func(in deviceInput) []assess.Finding {
	var out []assess.Finding
	interfaces := configuredInterfaces(in.Model)
	for _, row := range in.Model.Interfaces {
		switch strings.ToLower(row.State) {
		case "down", "notconnect", "disabled", "admin-down":
		default:
			continue
		}
		iface := interfaces[canonicalInterface(row.Interface)]
		if iface == nil || iface.Shutdown == nil || *iface.Shutdown {
			continue
		}
		if iface.OSPF == "" && !iface.PeerLink && iface.VPCID == nil {
			continue
		}
		out = append(out, assess.Finding{
			Subject: device(in.Model).Child("interface", row.Interface), Actual: row, Expected: "up",
			Detail: "核对 OSPF、vPC 或 peer-link 接口的维护意图与对端；不自动启用接口。",
		})
	}
	return out
})

func pointToPointOSPF(interfaces map[string]*fabric.Interface, neighbor fabric.OSPFNeighbor) bool {
	iface := interfaces[canonicalInterface(neighbor.Interface)]
	if iface == nil || iface.Shutdown != nil && *iface.Shutdown {
		return false
	}
	vrf := iface.VRF
	if vrf == "" {
		vrf = "default"
	}
	return iface.OSPFNetworkType == "point-to-point" && neighbor.VRF == vrf && strings.HasPrefix(iface.OSPF, neighbor.Process+" area ")
}

func configuredDownMember(interfaces map[string]*fabric.Interface, channel fabric.PortChannel, member fabric.PortChannelMember) bool {
	iface := interfaces[canonicalInterface(channel.Interface)]
	if iface == nil || iface.Shutdown != nil && *iface.Shutdown {
		return false
	}
	config := interfaces[canonicalInterface(member.Interface)]
	if config == nil || config.Shutdown != nil && *config.Shutdown {
		return false
	}
	return config.ChannelGroup != nil && *config.ChannelGroup == channel.Group && strings.ContainsAny(member.Flags, "Ds")
}
