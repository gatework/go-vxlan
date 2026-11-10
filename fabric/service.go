package fabric

import (
	"maps"
	"slices"
	"strconv"
)

// Service is one L2 VNI as deployed on one device: its VLAN mapping, SVI,
// NVE member and EVPN instance. Missing parts are nil.
type Service struct {
	VNI    int
	VLAN   *int // nil when the VNI has no VLAN mapping
	SVI    *Interface
	Member *NVEMember
	EVPN   *EVPNInstance
	// Missing names absent associations: VLAN, NVE, NVE L2, EVPN, EVPN L2.
	Missing []string
}

// Complete reports whether VLAN, NVE and EVPN associations are all present.
func (s Service) Complete() bool { return len(s.Missing) == 0 }

// Gateway reports whether the service has a routed SVI.
func (s Service) Gateway() bool {
	return s.SVI != nil && (True(s.SVI.Anycast) || len(s.SVI.Addresses) > 0)
}

// L3VNIs returns VNIs bound to VRFs or used as L3 by NVE or EVPN.
func (c *Configuration) L3VNIs() map[int]bool {
	l3 := map[int]bool{}
	for _, v := range c.VRFs {
		if v.VNI != nil {
			l3[*v.VNI] = true
		}
	}
	for k, e := range c.EVPN {
		if n, err := strconv.Atoi(k); err == nil && e.Type == "l3" {
			l3[n] = true
		}
	}
	for k, m := range c.NVE.Members {
		if n, err := strconv.Atoi(k); err == nil && True(m.AssociateVRF) {
			l3[n] = true
		}
	}
	return l3
}

// EffectiveMember returns the NVE member with the global multicast group
// inherited when the member declares no replication of its own.
func (c *Configuration) EffectiveMember(vni int) *NVEMember {
	m, ok := c.NVE.Members[strconv.Itoa(vni)]
	if !ok {
		return nil
	}
	if c.NVE.MulticastGroup != "" && m.Replication == "" && m.MulticastGroup == "" && !True(m.AssociateVRF) {
		m.MulticastGroup = c.NVE.MulticastGroup
	}
	return &m
}

// Services lists the device's L2 services by VNI, then VLAN. It follows the
// legacy service catalog: a VNI is an L2 service when it is mapped from a
// VLAN and not L3, or declared L2 by NVE or EVPN.
func (c *Configuration) Services() []Service {
	l3 := c.L3VNIs()
	l2 := map[int]bool{}
	for k, e := range c.EVPN {
		if n, err := strconv.Atoi(k); err == nil && e.Type == "l2" {
			l2[n] = true
		}
	}
	for k, m := range c.NVE.Members {
		if n, err := strconv.Atoi(k); err == nil && !True(m.AssociateVRF) {
			l2[n] = true
		}
	}
	vlansByVNI := map[int][]int{}
	for vlan, vni := range c.VLANVNIs {
		id, err := strconv.Atoi(vlan)
		if err != nil || vni == nil {
			continue
		}
		if !l3[*vni] {
			l2[*vni] = true
		}
		vlansByVNI[*vni] = append(vlansByVNI[*vni], id)
	}
	var out []Service
	for _, vni := range slices.Sorted(maps.Keys(l2)) {
		vlans := slices.Sorted(slices.Values(vlansByVNI[vni]))
		if len(vlans) == 0 {
			vlans = []int{-1}
		}
		for _, vlan := range vlans {
			s := Service{VNI: vni, Member: c.EffectiveMember(vni)}
			if vlan >= 0 {
				s.VLAN = new(vlan)
				if svi, ok := c.Interfaces["Vlan"+strconv.Itoa(vlan)]; ok {
					s.SVI = &svi
				}
			} else {
				s.Missing = append(s.Missing, "VLAN")
			}
			switch {
			case s.Member == nil:
				s.Missing = append(s.Missing, "NVE")
			case True(s.Member.AssociateVRF):
				s.Missing = append(s.Missing, "NVE L2")
			}
			if e, ok := c.EVPN[strconv.Itoa(vni)]; ok {
				s.EVPN = &e
				if e.Type != "l2" {
					s.Missing = append(s.Missing, "EVPN L2")
				}
			} else if c.NVOverlayEVPN {
				s.Missing = append(s.Missing, "EVPN")
			}
			out = append(out, s)
		}
	}
	return out
}

// Complete reports whether the configuration is fully parsed and reviewed.
// Partial configurations cannot support conclusions.
func (c *Configuration) Complete() bool { return c != nil && c.ReviewStatus == "complete" }

// VLANsForVNI returns the VLAN IDs mapped to vni, in numeric order.
func (c *Configuration) VLANsForVNI(vni int) []int {
	var out []int
	for vlan, v := range c.VLANVNIs {
		if id, err := strconv.Atoi(vlan); err == nil && v != nil && *v == vni {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}
