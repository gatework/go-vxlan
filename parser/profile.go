// Package parser binds ordered query declarations to immutable parser profiles.
package parser

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	vxlan "github.com/gatework/go-vxlan"
)

// ParseFunc converts one command response into an owned observation.
// Complete describes transport completion, not whether all syntax was recognized.
type ParseFunc func(string, bool) (vxlan.Observation, error)

// QuerySpec declares one evidence dimension, its read command, and its parser.
// Slice order is the default collection and presentation order.
type QuerySpec struct {
	Dimension string
	Command   string
	Parse     ParseFunc
}

// ProfileSpec describes a platform. ModelParsers replaces parsers by dimension;
// it cannot add undeclared commands or dimensions.
type ProfileSpec struct {
	Queries      []QuerySpec
	Preparation  []string
	AbsentReason func(string, vxlan.Observation, bool) string
	ModelParsers map[string]map[string]ParseFunc
}

// Query is an immutable profile's public command declaration.
type Query struct {
	Dimension string
	Command   string
}

type profileDefinition struct {
	profile      Profile
	modelParsers map[string]map[string]ParseFunc
}

// Registry owns validated definitions and produces independent selected profiles.
type Registry struct{ profiles map[string]profileDefinition }

// Profile binds the platform's command order and the selected model's parsers.
type Profile struct {
	queries      []Query
	preparation  []string
	absentReason func(string, vxlan.Observation, bool) string
	commands     map[string]string
	parsers      map[string]ParseFunc
}

func normalized(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
func validCommand(s string) bool {
	return strings.TrimSpace(s) != "" && strings.IndexFunc(s, func(r rune) bool { return r < 32 || r == 127 }) < 0
}

// NewRegistry copies definitions and validates each query and model override.
func NewRegistry(specs map[string]ProfileSpec) (*Registry, error) {
	r := &Registry{profiles: make(map[string]profileDefinition, len(specs))}
	for platform, s := range specs {
		key := normalized(platform)
		if key == "" {
			return nil, fmt.Errorf("empty platform")
		}
		if _, ok := r.profiles[key]; ok {
			return nil, fmt.Errorf("duplicate platform")
		}
		p := Profile{preparation: slices.Clone(s.Preparation), absentReason: s.AbsentReason, commands: make(map[string]string, len(s.Queries)), parsers: make(map[string]ParseFunc, len(s.Queries))}
		if len(s.Queries) == 0 {
			return nil, fmt.Errorf("empty query declarations")
		}
		commands := map[string]bool{}
		for _, q := range s.Queries {
			if strings.TrimSpace(q.Dimension) == "" || !validCommand(q.Command) || q.Parse == nil {
				return nil, fmt.Errorf("invalid query declaration")
			}
			if p.commands[q.Dimension] != "" || commands[q.Command] {
				return nil, fmt.Errorf("duplicate query declaration")
			}
			commands[q.Command] = true
			p.queries = append(p.queries, Query{Dimension: q.Dimension, Command: q.Command})
			p.commands[q.Dimension] = q.Command
			p.parsers[q.Dimension] = q.Parse
		}
		for _, command := range p.preparation {
			if !validCommand(command) {
				return nil, fmt.Errorf("invalid preparation command")
			}
		}
		d := profileDefinition{profile: p, modelParsers: map[string]map[string]ParseFunc{}}
		for model, overrides := range s.ModelParsers {
			mk := normalized(model)
			if mk == "" {
				return nil, fmt.Errorf("empty model")
			}
			if _, ok := d.modelParsers[mk]; ok {
				return nil, fmt.Errorf("duplicate model")
			}
			selected := make(map[string]ParseFunc, len(overrides))
			for dimension, parse := range overrides {
				if p.parsers[dimension] == nil || parse == nil {
					return nil, fmt.Errorf("invalid model parser")
				}
				selected[dimension] = parse
			}
			d.modelParsers[mk] = selected
		}
		r.profiles[key] = d
	}
	return r, nil
}

// Fetch selects a platform and optional model without retaining caller-owned data.
func (r *Registry) Fetch(platform, model string) (*Profile, error) {
	if r == nil {
		return nil, fmt.Errorf("nil parser registry")
	}
	d, ok := r.profiles[normalized(platform)]
	if !ok {
		return nil, fmt.Errorf("unsupported platform")
	}
	p := d.profile
	p.queries = slices.Clone(p.queries)
	p.preparation = slices.Clone(p.preparation)
	p.commands = maps.Clone(p.commands)
	p.parsers = maps.Clone(p.parsers)
	maps.Copy(p.parsers, d.modelParsers[normalized(model)])
	return &p, nil
}

func (p *Profile) Queries() []Query { return slices.Clone(p.queries) }
func (p *Profile) Dimensions() []string {
	names := make([]string, len(p.queries))
	for i, q := range p.queries {
		names[i] = q.Dimension
	}
	return names
}
func (p *Profile) Commands() map[string]string   { return maps.Clone(p.commands) }
func (p *Profile) Command(name string) string    { return p.commands[name] }
func (p *Profile) PreparationCommands() []string { return slices.Clone(p.preparation) }
func (p *Profile) AbsentReason(name string, configuration vxlan.Observation, beforeQuery bool) string {
	if p.absentReason == nil {
		return ""
	}
	return p.absentReason(name, configuration, beforeQuery)
}

// Parse verifies the dimension identity and takes ownership of parser output.
func (p *Profile) Parse(name, text string, complete bool) (vxlan.Observation, error) {
	parse := p.parsers[name]
	if parse == nil {
		return vxlan.Observation{}, fmt.Errorf("unknown dimension %s", name)
	}
	o, err := parse(text, complete)
	if err != nil {
		return vxlan.Observation{}, err
	}
	if o.Name != name {
		return vxlan.Observation{}, fmt.Errorf("parser observation name mismatch")
	}
	owned, err := vxlan.NewObservation(o.Name, o.Status, o.Records, o.Issues, o.Evidence)
	if o.StartedAt != nil {
		owned.StartedAt = new(*o.StartedAt)
	}
	if o.CompletedAt != nil {
		owned.CompletedAt = new(*o.CompletedAt)
	}
	return owned, err
}
