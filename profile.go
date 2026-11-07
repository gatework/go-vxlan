package vxlan

import (
	"fmt"
	"maps"
	"strings"
)

// ParseFunc converts one command's output into an owned observation.
type ParseFunc func(string, bool) (Observation, error)
type ProfileSpec struct {
	Commands     map[string]string
	Parsers      map[string]ParseFunc
	ModelParsers map[string]map[string]ParseFunc
}
type ParserRegistry struct{ profiles map[string]ProfileSpec }
type Profile struct {
	commands map[string]string
	parsers  map[string]ParseFunc
}

func normalized(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// NewParserRegistry copies definitions and validates every command override.
func NewParserRegistry(specs map[string]ProfileSpec) (*ParserRegistry, error) {
	r := &ParserRegistry{profiles: map[string]ProfileSpec{}}
	for platform, s := range specs {
		key := normalized(platform)
		if key == "" {
			return nil, fmt.Errorf("empty platform")
		}
		if _, ok := r.profiles[key]; ok {
			return nil, fmt.Errorf("duplicate platform")
		}
		p := ProfileSpec{Commands: map[string]string{}, Parsers: map[string]ParseFunc{}, ModelParsers: map[string]map[string]ParseFunc{}}
		for name, command := range s.Commands {
			if strings.TrimSpace(name) == "" || strings.TrimSpace(command) == "" || strings.IndexFunc(command, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
				return nil, fmt.Errorf("invalid command")
			}
			if s.Parsers[command] == nil {
				return nil, fmt.Errorf("missing parser for %s", name)
			}
			p.Commands[name] = command
			p.Parsers[command] = s.Parsers[command]
		}
		if len(p.Commands) == 0 || len(p.Parsers) != len(s.Parsers) {
			return nil, fmt.Errorf("parser command mismatch")
		}
		for model, overrides := range s.ModelParsers {
			mk := normalized(model)
			if mk == "" {
				return nil, fmt.Errorf("empty model")
			}
			if _, ok := p.ModelParsers[mk]; ok {
				return nil, fmt.Errorf("duplicate model")
			}
			p.ModelParsers[mk] = map[string]ParseFunc{}
			for command, parser := range overrides {
				if p.Parsers[command] == nil || parser == nil {
					return nil, fmt.Errorf("invalid model parser")
				}
				p.ModelParsers[mk][command] = parser
			}
		}
		r.profiles[key] = p
	}
	return r, nil
}
func (r *ParserRegistry) Fetch(platform, model string) (*Profile, error) {
	if r == nil {
		return nil, fmt.Errorf("nil parser registry")
	}
	s, ok := r.profiles[normalized(platform)]
	if !ok {
		return nil, fmt.Errorf("unsupported platform")
	}
	p := &Profile{commands: maps.Clone(s.Commands), parsers: maps.Clone(s.Parsers)}
	maps.Copy(p.parsers, s.ModelParsers[normalized(model)])
	return p, nil
}
func (p *Profile) Commands() map[string]string {
	if p.commands == nil {
		return map[string]string{}
	}
	return maps.Clone(p.commands)
}
func (p *Profile) Command(name string) string { return p.commands[name] }
func (p *Profile) Parse(name, text string, complete bool) (Observation, error) {
	parser := p.parsers[p.Command(name)]
	if parser == nil {
		return Observation{}, fmt.Errorf("unknown dimension %s", name)
	}
	o, e := parser(text, complete)
	if e != nil {
		return Observation{}, e
	}
	if o.Name != name {
		return Observation{}, fmt.Errorf("parser observation name mismatch")
	}
	owned, e := NewObservation(o.Name, o.Status, o.Records, o.Issues, o.Evidence)
	if o.StartedAt != nil {
		owned.StartedAt = new(*o.StartedAt)
	}
	if o.CompletedAt != nil {
		owned.CompletedAt = new(*o.CompletedAt)
	}
	return owned, e
}
func NXOSProfileSpec() ProfileSpec {
	s := ProfileSpec{Commands: Commands(), Parsers: map[string]ParseFunc{}}
	for name, command := range s.Commands {
		s.Parsers[command] = func(text string, complete bool) (Observation, error) {
			if name == "configuration" {
				return ParseConfigChecked(text, complete)
			}
			return ParseRuntime(name, text, complete)
		}
	}
	return s
}
func DefaultParserRegistry() *ParserRegistry {
	r, e := NewParserRegistry(map[string]ProfileSpec{"cisco_nxos": NXOSProfileSpec()})
	if e != nil {
		panic(e)
	}
	return r
}
