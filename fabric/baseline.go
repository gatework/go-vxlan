package fabric

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"go.yaml.in/yaml/v3"
)

// BaselineSchemaVersion is the version of the baseline document.
const BaselineSchemaVersion = 1

// ErrBaseline reports an invalid baseline document.
var ErrBaseline = errors.New("fabric: invalid baseline")

// NVEExpectation is the intended NVE configuration of every VTEP.
type NVEExpectation struct {
	HostReachability *string `yaml:"host_reachability,omitempty" json:"host_reachability,omitempty"`
	SourceInterface  *string `yaml:"source_interface,omitempty" json:"source_interface,omitempty"`
	Replication      *string `yaml:"replication,omitempty" json:"replication,omitempty"`
	SuppressARP      *bool   `yaml:"suppress_arp,omitempty" json:"suppress_arp,omitempty"`
}

// ManagementExpectation lists the intended server addresses of every device.
// A nil list states no expectation; an empty list expects none.
type ManagementExpectation struct {
	NTP     []string `yaml:"ntp,omitempty" json:"ntp,omitempty"`
	Logging []string `yaml:"logging,omitempty" json:"logging,omitempty"`
	TACACS  []string `yaml:"tacacs,omitempty" json:"tacacs,omitempty"`
	SNMP    []string `yaml:"snmp,omitempty" json:"snmp,omitempty"`
}

// VPCExpectation is the intended vPC domain configuration of vPC members.
type VPCExpectation struct {
	PeerGateway    *bool `yaml:"peer_gateway,omitempty" json:"peer_gateway,omitempty"`
	AutoRecovery   *bool `yaml:"auto_recovery,omitempty" json:"auto_recovery,omitempty"`
	ARPSynchronize *bool `yaml:"arp_synchronize,omitempty" json:"arp_synchronize,omitempty"`
	DelayRestore   *int  `yaml:"delay_restore,omitempty" json:"delay_restore,omitempty"`
}

// Expectation is the declared intent for one fabric. Nil fields declare no
// expectation, so a partial baseline checks only what it states.
type Expectation struct {
	AnycastGatewayMAC *string                `yaml:"anycast_gateway_mac,omitempty" json:"anycast_gateway_mac,omitempty"`
	SVIMTU            *int                   `yaml:"svi_mtu,omitempty" json:"svi_mtu,omitempty"`
	RequiredFeatures  []string               `yaml:"required_features,omitempty" json:"required_features,omitempty"`
	EVPNAutoRDRT      *bool                  `yaml:"evpn_auto_rd_rt,omitempty" json:"evpn_auto_rd_rt,omitempty"`
	NVE               *NVEExpectation        `yaml:"nve,omitempty" json:"nve,omitempty"`
	Services          map[int]int            `yaml:"services,omitempty" json:"services,omitempty"` // VNI -> VLAN
	Management        *ManagementExpectation `yaml:"management,omitempty" json:"management,omitempty"`
	VPC               *VPCExpectation        `yaml:"vpc,omitempty" json:"vpc,omitempty"`
}

// Baseline is the frozen operational intent of one or more fabrics.
type Baseline struct {
	SchemaVersion int                    `yaml:"schema_version" json:"schema_version"`
	Defaults      Expectation            `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	Fabrics       map[string]Expectation `yaml:"fabrics,omitempty" json:"fabrics,omitempty"`
}

// DecodeBaseline strictly decodes and validates a YAML baseline.
func DecodeBaseline(body []byte) (Baseline, error) {
	var b Baseline
	d := yaml.NewDecoder(bytes.NewReader(body))
	d.KnownFields(true)
	if err := d.Decode(&b); err != nil {
		return Baseline{}, fmt.Errorf("%w: %w", ErrBaseline, err)
	}
	return b, b.Validate()
}

// Encode renders the baseline as YAML.
func (b Baseline) Encode() ([]byte, error) {
	var out bytes.Buffer
	e := yaml.NewEncoder(&out)
	e.SetIndent(2)
	if err := e.Encode(b); err != nil {
		return nil, err
	}
	return out.Bytes(), e.Close()
}

// Validate checks the schema version and value ranges.
func (b Baseline) Validate() error {
	if b.SchemaVersion != BaselineSchemaVersion {
		return fmt.Errorf("%w: schema_version %d", ErrBaseline, b.SchemaVersion)
	}
	check := func(scope string, e Expectation) error {
		if e.SVIMTU != nil && (*e.SVIMTU < 576 || *e.SVIMTU > 9216) {
			return fmt.Errorf("%w: %s svi_mtu", ErrBaseline, scope)
		}
		for vni, vlan := range e.Services {
			if vni < 1 || vni > 16777215 || vlan < 1 || vlan > 4094 {
				return fmt.Errorf("%w: %s service %d", ErrBaseline, scope, vni)
			}
		}
		if m := e.Management; m != nil {
			for _, list := range [][]string{m.NTP, m.Logging, m.TACACS, m.SNMP} {
				for _, a := range list {
					if p, err := netip.ParseAddr(a); err != nil || p.String() != a {
						return fmt.Errorf("%w: %s management address %q", ErrBaseline, scope, a)
					}
				}
			}
		}
		return nil
	}
	if err := check("defaults", b.Defaults); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(b.Fabrics)) {
		if err := check("fabric "+name, b.Fabrics[name]); err != nil {
			return err
		}
	}
	return nil
}

// For returns the effective expectation of a fabric: its own fields over
// the defaults, field by field.
func (b Baseline) For(name string) Expectation {
	e := b.Defaults
	o, ok := b.Fabrics[name]
	if !ok {
		return e
	}
	if o.AnycastGatewayMAC != nil {
		e.AnycastGatewayMAC = o.AnycastGatewayMAC
	}
	if o.SVIMTU != nil {
		e.SVIMTU = o.SVIMTU
	}
	if o.RequiredFeatures != nil {
		e.RequiredFeatures = o.RequiredFeatures
	}
	if o.EVPNAutoRDRT != nil {
		e.EVPNAutoRDRT = o.EVPNAutoRDRT
	}
	if o.NVE != nil {
		e.NVE = o.NVE
	}
	if o.Services != nil {
		e.Services = o.Services
	}
	if o.Management != nil {
		e.Management = o.Management
	}
	if o.VPC != nil {
		e.VPC = o.VPC
	}
	return e
}

// ServiceKeys returns the declared VNIs in order.
func (e Expectation) ServiceKeys() []int { return slices.Sorted(maps.Keys(e.Services)) }

// Addresses returns server addresses, for comparison with a baseline.
func Addresses(servers []Server) []string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		out = append(out, s.Address)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
