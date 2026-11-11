package nxos

import (
	"slices"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/internal/textparse"
)

func absentReason(name string, configuration vxlan.Observation, beforeQuery bool) string {
	if beforeQuery && name != "vpc" || !unconfigured(name, configuration) {
		return ""
	}
	switch name {
	case "vpc":
		return "vpc_not_configured"
	case "port_channels":
		return "port_channels_not_configured"
	default:
		return "nve_not_configured"
	}
}
func unconfigured(name string, o vxlan.Observation) bool {
	if !o.Complete() || len(o.Records) != 1 {
		return false
	}
	d := o.Records[0]
	switch name {
	case "vpc":
		if d["vpc_domain"] != nil {
			return false
		}
		return !slices.Contains(record.StringSlice(d["features"]), "vpc")
	case "nve_peers", "nve_vnis":
		return record.Map(d["nve"])["interface"] == nil
	case "port_channels":
		for n, v := range record.Map(d["interfaces"]) {
			if textparse.Match(`(?i)port-channel\d+`, n) != nil || record.Map(v)["channel_group"] != nil {
				return false
			}
		}
		return true
	}
	return false
}
