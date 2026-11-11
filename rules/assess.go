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
type Commands interface{ Command(name string) string }

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
	SchemaVersion int                `json:"schema_version"`
	Platform      string             `json:"platform"`
	Devices       []DeviceAssessment `json:"devices"`
	Fabrics       []FabricAssessment `json:"fabrics"`
	Unassigned    []string           `json:"unassigned,omitempty"`
	// Baseline holds drift from the declared intent, when a baseline is given.
	Baseline []FabricAssessment `json:"baseline,omitempty"`
	// Changes holds per-device changes since a previous batch, when given.
	Changes []DeviceAssessment `json:"changes,omitempty"`
	// Appeared and Disappeared list devices present in only one batch.
	Appeared    []string                `json:"appeared,omitempty"`
	Disappeared []string                `json:"disappeared,omitempty"`
	Counts      map[assess.Severity]int `json:"counts"`
	Highest     assess.Severity         `json:"highest,omitempty"`
	// Incomplete is true when any enabled rule could not run for lack of
	// evidence; the report then cannot vouch for what it did not check.
	Incomplete bool `json:"incomplete"`
}

// Assessor holds the two engines built from one policy.
type Assessor struct {
	devices  *assess.Engine[*fabric.Device]
	fabrics  *assess.Engine[*fabric.Fabric]
	baseline *assess.Engine[*BaselineScope]
	temporal *assess.Engine[*Change]
}

// Inputs are optional comparison points for an assessment.
type Inputs struct {
	// Baseline is the frozen intent; nil skips baseline drift.
	Baseline *fabric.Baseline
	// Previous is the model of an earlier batch; nil skips change detection.
	Previous *fabric.Model
}

// NewAssessor validates the policy against both catalogs. A rule named in
// the policy must exist in one of them.
func NewAssessor(policy assess.Policy, commands Commands) (*Assessor, error) {
	deviceCatalog, err := assess.NewCatalog(DeviceRules()...)
	if err != nil {
		return nil, err
	}
	var verifier Verifier
	if v, ok := commands.(Verifier); ok {
		verifier = v
	}
	fabricCatalog, err := assess.NewCatalog(append(FabricRules(), incrementRule(verifier))...)
	if err != nil {
		return nil, err
	}
	baselineCatalog, err := assess.NewCatalog(BaselineRules()...)
	if err != nil {
		return nil, err
	}
	temporalCatalog, err := assess.NewCatalog(TemporalRules()...)
	if err != nil {
		return nil, err
	}
	for id := range policy.Rules {
		_, inDevice := deviceCatalog.Lookup(id)
		_, inFabric := fabricCatalog.Lookup(id)
		_, inBaseline := baselineCatalog.Lookup(id)
		_, inTemporal := temporalCatalog.Lookup(id)
		if !inDevice && !inFabric && !inBaseline && !inTemporal {
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
	be, err := assess.NewEngine(baselineCatalog, subset(policy, baselineCatalog), v)
	if err != nil {
		return nil, err
	}
	te, err := assess.NewEngine(temporalCatalog, subset(policy, temporalCatalog), v)
	if err != nil {
		return nil, err
	}
	return &Assessor{devices: de, fabrics: fe, baseline: be, temporal: te}, nil
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
	return a.AssessWith(ctx, m, Inputs{})
}

// AssessWith also compares the model with a baseline and a previous batch.
func (a *Assessor) AssessWith(ctx context.Context, m *fabric.Model, inputs Inputs) (Report, error) {
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
		r.Fabrics = append(r.Fabrics, FabricAssessment{Name: f.Name, Members: hosts(f.Members), Missing: f.Missing, Assessment: as})
		add(as)
	}
	if b := inputs.Baseline; b != nil {
		if err := b.Validate(); err != nil {
			return Report{}, err
		}
		for _, f := range m.Fabrics {
			as, err := a.baseline.Run(ctx, &BaselineScope{Fabric: f, Expect: b.For(f.Name)}, f.Coverage())
			if err != nil {
				return Report{}, err
			}
			r.Baseline = append(r.Baseline, FabricAssessment{Name: f.Name, Members: hosts(f.Members), Missing: f.Missing, Assessment: as})
			add(as)
		}
	}
	if prev := inputs.Previous; prev != nil {
		if err := a.assessChanges(ctx, m, prev, &r, add); err != nil {
			return Report{}, err
		}
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

func hosts(devices []*fabric.Device) []string {
	out := []string{}
	for _, d := range devices {
		out = append(out, d.Host)
	}
	return out
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
	ids = append(ids, IncrementRuleID)
	for _, r := range BaselineRules() {
		ids = append(ids, r.Meta().ID)
	}
	for _, r := range TemporalRules() {
		ids = append(ids, r.Meta().ID)
	}
	return slices.Sorted(slices.Values(ids))
}

func (a *Assessor) assessChanges(ctx context.Context, m, prev *fabric.Model, r *Report, add func(assess.Assessment)) error {
	before := map[string]*fabric.Device{}
	for _, d := range prev.Devices {
		before[d.Host] = d
	}
	now := map[string]bool{}
	for _, d := range m.Devices {
		now[d.Host] = true
		p, ok := before[d.Host]
		if !ok {
			r.Appeared = append(r.Appeared, d.Host)
			continue
		}
		c := &Change{Previous: p, Current: d}
		as, err := a.temporal.Run(ctx, c, c.Coverage())
		if err != nil {
			return err
		}
		r.Changes = append(r.Changes, DeviceAssessment{Device: d.Identity, Role: d.Role, Coverage: c.Coverage(), Assessment: as})
		add(as)
	}
	for _, d := range prev.Devices {
		if !now[d.Host] {
			r.Disappeared = append(r.Disappeared, d.Host)
		}
	}
	slices.Sort(r.Appeared)
	slices.Sort(r.Disappeared)
	// A device that stopped reporting cannot be vouched for.
	r.Incomplete = r.Incomplete || len(r.Disappeared) > 0
	return nil
}
