package fabric

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"go.yaml.in/yaml/v3"

	"github.com/gatework/go-netops/evidence"
)

// ErrPolicy reports an invalid fabric membership policy.
var ErrPolicy = errors.New("fabric: invalid policy")

// Membership lists a fabric's devices by role. Hosts are canonical IP
// addresses and must be unique across roles and fabrics.
type Membership struct {
	Leaves  []string `yaml:"leaves,omitempty" json:"leaves,omitempty"`
	Borders []string `yaml:"borders,omitempty" json:"borders,omitempty"`
	Spines  []string `yaml:"spines,omitempty" json:"spines,omitempty"`
}

func (m Membership) roles() []struct {
	role  Role
	hosts []string
} {
	return []struct {
		role  Role
		hosts []string
	}{{RoleLeaf, m.Leaves}, {RoleBorder, m.Borders}, {RoleSpine, m.Spines}}
}

// Policy declares the fabrics. It is the same document the legacy review
// accepts: {"fabrics": {name: {leaves: [...], borders: [...], spines: [...]}}}.
type Policy struct {
	Fabrics map[string]Membership `yaml:"fabrics" json:"fabrics"`
}

// DecodePolicy strictly decodes and validates a YAML or JSON policy.
func DecodePolicy(body []byte) (Policy, error) {
	var p Policy
	d := yaml.NewDecoder(bytes.NewReader(body))
	d.KnownFields(true)
	if err := d.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("%w: %w", ErrPolicy, err)
	}
	return p, p.Validate()
}

// ValidatePolicyDocument validates a policy already decoded from YAML or
// JSON, such as a configuration value, with the same strict rules as
// DecodePolicy.
func ValidatePolicyDocument(v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPolicy, err)
	}
	_, err = DecodePolicy(body)
	return err
}

// Validate enforces explicit, unique, canonical membership with at least
// two members per fabric.
func (p Policy) Validate() error {
	if len(p.Fabrics) == 0 {
		return fmt.Errorf("%w: no fabrics", ErrPolicy)
	}
	seen := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(p.Fabrics)) {
		if name == "" {
			return fmt.Errorf("%w: empty fabric name", ErrPolicy)
		}
		count := 0
		for _, r := range p.Fabrics[name].roles() {
			for _, host := range r.hosts {
				a, err := netip.ParseAddr(host)
				if err != nil || a.String() != host || a.Zone() != "" {
					return fmt.Errorf("%w: fabric %s member %q is not a canonical address", ErrPolicy, name, host)
				}
				if seen[host] {
					return fmt.Errorf("%w: member %s appears twice", ErrPolicy, host)
				}
				seen[host] = true
				count++
			}
		}
		if count < 2 {
			return fmt.Errorf("%w: fabric %s needs at least two members", ErrPolicy, name)
		}
	}
	return nil
}

// Fabric is one declared fabric with its observed member devices.
type Fabric struct {
	Name    string
	Members []*Device // declaration order: leaves, borders, spines
	// Missing lists declared hosts with no collected report.
	Missing []string
}

// ByRole returns the observed members with a role.
func (f *Fabric) ByRole(role Role) []*Device {
	var out []*Device
	for _, d := range f.Members {
		if d.Role == role {
			out = append(out, d)
		}
	}
	return out
}

// VTEPs returns leaves and borders, the members that terminate VXLAN.
func (f *Fabric) VTEPs() []*Device {
	return slices.Concat(f.ByRole(RoleLeaf), f.ByRole(RoleBorder))
}

// Coverage is complete for a dimension only if every member has it.
func (f *Fabric) Coverage() evidence.Coverage {
	c := evidence.Coverage{}
	for _, dim := range Dimensions() {
		status := evidence.StatusComplete
		for _, d := range f.Members {
			if s := d.Coverage.Status(dim); !s.Complete() {
				status = s
				break
			}
		}
		if len(f.Members) > 0 && len(f.Missing) == 0 {
			c[dim] = status
		} else {
			c[dim] = evidence.StatusPartial
		}
	}
	return c
}

// Model is everything a review assesses.
type Model struct {
	Devices    []*Device // in input order
	Fabrics    []*Fabric // sorted by name
	Unassigned []*Device // collected but in no fabric
}

// Build assigns roles from the policy. Duplicate device hosts are rejected.
func Build(devices []*Device, policy *Policy) (*Model, error) {
	byHost := map[string]*Device{}
	for _, d := range devices {
		if _, dup := byHost[d.Host]; dup {
			return nil, fmt.Errorf("%w: duplicate device %s", ErrDocument, d.Host)
		}
		byHost[d.Host] = d
	}
	m := &Model{Devices: devices}
	assigned := map[string]bool{}
	if policy != nil {
		if err := policy.Validate(); err != nil {
			return nil, err
		}
		for _, name := range slices.Sorted(maps.Keys(policy.Fabrics)) {
			f := &Fabric{Name: name}
			for _, r := range policy.Fabrics[name].roles() {
				for _, host := range r.hosts {
					d, ok := byHost[host]
					if !ok {
						f.Missing = append(f.Missing, host)
						continue
					}
					d.Role = r.role
					assigned[host] = true
					f.Members = append(f.Members, d)
				}
			}
			m.Fabrics = append(m.Fabrics, f)
		}
	}
	for _, d := range devices {
		if !assigned[d.Host] {
			m.Unassigned = append(m.Unassigned, d)
		}
	}
	return m, nil
}
