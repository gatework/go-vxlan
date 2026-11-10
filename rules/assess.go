package rules

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-netops/evidence"
	"github.com/gatework/go-vxlan/fabric"
)

// Commands resolves collection commands for verification hints; the
// selected parser.Profile satisfies it.
type Commands interface{ Command(string) string }

type verify struct{ c Commands }

func (v verify) Command(d evidence.Dimension) (string, error) {
	if v.c == nil {
		return "", errors.New("no profile")
	}
	if cmd := v.c.Command(string(d)); cmd != "" {
		return cmd, nil
	}
	return "", errors.New("unknown dimension")
}

// DeviceAssessment is one device's result.
type DeviceAssessment struct {
	Device     fabric.Identity   `json:"device"`
	Role       fabric.Role       `json:"role,omitempty"`
	Coverage   evidence.Coverage `json:"coverage"`
	Assessment assess.Assessment `json:"assessment"`
}

// FabricAssessment is one fabric's cross-device result.
type FabricAssessment struct {
	Name       string            `json:"name"`
	Members    []string          `json:"members"`
	Missing    []string          `json:"missing,omitempty"`
	Assessment assess.Assessment `json:"assessment"`
}

// Report is the schema 3 assessment of a review.
type Report struct {
	SchemaVersion int                     `json:"schema_version"`
	Platform      string                  `json:"platform"`
	Devices       []DeviceAssessment      `json:"devices"`
	Fabrics       []FabricAssessment      `json:"fabrics"`
	Unassigned    []string                `json:"unassigned,omitempty"`
	Counts        map[assess.Severity]int `json:"counts"`
	Highest       assess.Severity         `json:"highest,omitempty"`
	// Incomplete is true when any enabled rule could not run for lack of
	// evidence; the report then cannot vouch for what it did not check.
	Incomplete bool `json:"incomplete"`
}

// Assessor holds the two engines built from one policy.
type Assessor struct {
	devices *assess.Engine[*fabric.Device]
	fabrics *assess.Engine[*fabric.Fabric]
}

// NewAssessor validates the policy against both catalogs. A rule named in
// the policy must exist in one of them.
func NewAssessor(policy assess.Policy, commands Commands) (*Assessor, error) {
	deviceCatalog, err := assess.NewCatalog(DeviceRules()...)
	if err != nil {
		return nil, err
	}
	fabricCatalog, err := assess.NewCatalog(FabricRules()...)
	if err != nil {
		return nil, err
	}
	for id := range policy.Rules {
		_, inDevice := deviceCatalog.Lookup(id)
		_, inFabric := fabricCatalog.Lookup(id)
		if !inDevice && !inFabric {
			return nil, fmt.Errorf("%w: policy names unknown rule %s", assess.ErrInvalid, id)
		}
	}
	v := verify{commands}
	de, err := assess.NewEngine(deviceCatalog, subset(policy, deviceCatalog), v)
	if err != nil {
		return nil, err
	}
	fe, err := assess.NewEngine(fabricCatalog, subset(policy, fabricCatalog), v)
	if err != nil {
		return nil, err
	}
	return &Assessor{devices: de, fabrics: fe}, nil
}

func subset[M any](p assess.Policy, c *assess.Catalog[M]) assess.Policy {
	out := assess.Policy{OnlyEnabled: p.OnlyEnabled, Rules: map[assess.RuleID]assess.RulePolicy{}}
	for id, rp := range p.Rules {
		if _, ok := c.Lookup(id); ok {
			out.Rules[id] = rp
		}
	}
	return out
}

// Assess evaluates every device and every fabric of the model.
func (a *Assessor) Assess(ctx context.Context, m *fabric.Model) (Report, error) {
	r := Report{SchemaVersion: assess.SchemaVersion, Platform: "cisco_nxos", Devices: []DeviceAssessment{}, Fabrics: []FabricAssessment{}, Counts: map[assess.Severity]int{}}
	add := func(as assess.Assessment) {
		for sev, n := range as.Counts {
			r.Counts[sev] += n
		}
		r.Highest = max(r.Highest, as.Highest())
		r.Incomplete = r.Incomplete || as.Incomplete()
	}
	for _, d := range m.Devices {
		as, err := a.devices.Run(ctx, d, d.Coverage)
		if err != nil {
			return Report{}, err
		}
		r.Devices = append(r.Devices, DeviceAssessment{Device: d.Identity, Role: d.Role, Coverage: d.Coverage, Assessment: as})
		add(as)
	}
	for _, f := range m.Fabrics {
		as, err := a.fabrics.Run(ctx, f, f.Coverage())
		if err != nil {
			return Report{}, err
		}
		members := []string{}
		for _, d := range f.Members {
			members = append(members, d.Host)
		}
		r.Fabrics = append(r.Fabrics, FabricAssessment{Name: f.Name, Members: members, Missing: f.Missing, Assessment: as})
		add(as)
	}
	if len(m.Fabrics) > 0 {
		for _, d := range m.Unassigned {
			r.Unassigned = append(r.Unassigned, d.Host)
		}
		slices.Sort(r.Unassigned)
		r.Incomplete = r.Incomplete || len(r.Unassigned) > 0
	}
	return r, nil
}

// RuleIDs lists every rule identifier, for policy authoring and docs.
func RuleIDs() []assess.RuleID {
	var ids []assess.RuleID
	for _, r := range DeviceRules() {
		ids = append(ids, r.Meta().ID)
	}
	for _, r := range FabricRules() {
		ids = append(ids, r.Meta().ID)
	}
	return slices.Sorted(slices.Values(ids))
}
