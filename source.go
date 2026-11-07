package vxlan

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"
)

// LineState distinguishes successful interpretation from unrelated, rejected,
// and unvisited source. Merely reading a line does not mean it was parsed.
type LineState string

const (
	LinePending     LineState = "pending"
	LineParsed      LineState = "parsed"
	LineIgnored     LineState = "ignored"
	LineUnsupported LineState = "unsupported"
	LineInvalid     LineState = "invalid"
)

// ConfigurationParser retains the last successful input's source document.
// Each Parse creates an independent snapshot; invalid input clears Document.
// A parser instance must not be used concurrently.
type ConfigurationParser struct{ document *ConfigurationDocument }

func (p *ConfigurationParser) Parse(text string, complete bool) (Observation, error) {
	p.document = nil
	if err := validateConfigInput(text); err != nil {
		return Observation{}, err
	}
	d := newConfigurationDocument(text)
	o := parseConfig(text, complete, d)
	p.document = d
	return o, nil
}
func (p *ConfigurationParser) Document() *ConfigurationDocument { return p.document }
func (p ConfigurationParser) String() string {
	return fmt.Sprintf("ConfigurationParser{document=%t}", p.document != nil)
}
func (p ConfigurationParser) GoString() string { return p.String() }
func (p ConfigurationParser) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Document *ConfigurationDocument `json:"document"`
	}{p.document})
}

// ParseConfigChecked rejects malformed UTF-8 and NUL bytes before parsing.
// Unsupported NX-OS syntax remains a partial Observation, not a Go error.
func ParseConfigChecked(text string, complete bool) (Observation, error) {
	if err := validateConfigInput(text); err != nil {
		return Observation{}, err
	}
	return parseConfig(text, complete, nil), nil
}
func validateConfigInput(text string) error {
	if !utf8.ValidString(text) {
		return errors.New("configuration input contains invalid UTF-8")
	}
	if strings.ContainsRune(text, '\x00') {
		return errors.New("configuration input contains NUL")
	}
	return nil
}

// ConfigurationDocument is an immutable source snapshot. Content and the
// explicit source accessors reveal configuration text; formatting and JSON
// only expose metadata. Returned slices and captured data are independent copies.
type ConfigurationDocument struct {
	content  string
	checksum string
	lines    []SourceLine
	states   []LineState
	roots    []SourceBlock
	captures []SourceCapture
}

func newConfigurationDocument(text string) *ConfigurationDocument {
	d := &ConfigurationDocument{content: text, checksum: fmt.Sprintf("%x", sha256.Sum256([]byte(text)))}
	for start := 0; start < len(text); {
		end := start
		for end < len(text) && text[end] != '\r' && text[end] != '\n' {
			end++
		}
		if end < len(text) {
			if text[end] == '\r' && end+1 < len(text) && text[end+1] == '\n' {
				end += 2
			} else {
				end++
			}
		}
		raw := text[start:end]
		d.lines = append(d.lines, SourceLine{index: len(d.lines), raw: raw, indent: len(raw) - len(strings.TrimLeft(raw, " \t"))})
		d.states = append(d.states, LinePending)
		start = end
	}
	return d
}
func (d *ConfigurationDocument) Content() string     { return d.content }
func (d *ConfigurationDocument) Checksum() string    { return d.checksum }
func (d *ConfigurationDocument) Size() int           { return len(d.lines) }
func (d *ConfigurationDocument) Position() int       { return d.Size() }
func (d *ConfigurationDocument) EOF() bool           { return true }
func (d *ConfigurationDocument) Lines() []SourceLine { return append([]SourceLine{}, d.lines...) }
func (d *ConfigurationDocument) States() []LineState { return append([]LineState{}, d.states...) }

// State uses a zero-based line index and returns an error outside the document.
func (d *ConfigurationDocument) State(index int) (LineState, error) {
	if index < 0 || index >= d.Size() {
		return "", fmt.Errorf("source line index out of range: %d", index)
	}
	return d.states[index], nil
}
func (d *ConfigurationDocument) Visited(index int) bool { return index >= 0 && index < d.Size() }
func (d *ConfigurationDocument) Parsed(index int) bool {
	return index >= 0 && index < d.Size() && d.states[index] == LineParsed
}
func (d *ConfigurationDocument) Roots() []SourceBlock { return append([]SourceBlock{}, d.roots...) }
func (d *ConfigurationDocument) Captures() []SourceCapture {
	return append([]SourceCapture{}, d.captures...)
}

// CapturesFor uses record keys (strings) and array indexes (ints), relative to
// the first observation record. Numeric map keys such as VNIs are strings.
func (d *ConfigurationDocument) CapturesFor(path ...any) []SourceCapture {
	out := []SourceCapture{}
	for _, c := range d.captures {
		if reflect.DeepEqual(c.path, path) {
			out = append(out, c)
		}
	}
	return out
}
func (d *ConfigurationDocument) UnparsedLines() []SourceLine {
	out := []SourceLine{}
	for i, l := range d.lines {
		if !resolvedLine(d.states[i]) {
			out = append(out, l)
		}
	}
	return out
}
func (d *ConfigurationDocument) UnparsedContent() string {
	var b strings.Builder
	for _, l := range d.UnparsedLines() {
		b.WriteString(l.raw)
	}
	return b.String()
}
func (d *ConfigurationDocument) Complete() bool {
	for _, s := range d.states {
		if !resolvedLine(s) {
			return false
		}
	}
	return true
}
func (d ConfigurationDocument) String() string {
	return fmt.Sprintf("ConfigurationDocument{lines=%d captures=%d}", d.Size(), len(d.captures))
}
func (d ConfigurationDocument) GoString() string { return d.String() }
func (d ConfigurationDocument) MarshalJSON() ([]byte, error) {
	counts := map[LineState]int{}
	for _, s := range d.states {
		counts[s]++
	}
	return json.Marshal(Record{"position": d.Position(), "lines": d.Size(), "states": counts, "captures": len(d.captures)})
}
func resolvedLine(s LineState) bool { return s == LineParsed || s == LineIgnored }

// SourceLine retains an original physical line, including its line terminator.
type SourceLine struct {
	index, indent int
	raw           string
}

func (l SourceLine) Index() int                   { return l.index }
func (l SourceLine) Number() int                  { return l.index + 1 }
func (l SourceLine) Indent() int                  { return l.indent }
func (l SourceLine) Content() string              { return l.raw }
func (l SourceLine) Text() string                 { return strings.Trim(l.raw, " \t\r\n\v\f") }
func (l SourceLine) String() string               { return fmt.Sprintf("SourceLine{number=%d}", l.Number()) }
func (l SourceLine) GoString() string             { return l.String() }
func (l SourceLine) MarshalJSON() ([]byte, error) { return json.Marshal(Record{"number": l.Number()}) }

// SourceBlock covers a header and its original subtree, including interleaved
// comments and blank lines. Ranges use inclusive, one-based line numbers.
type SourceBlock struct {
	document    *ConfigurationDocument
	index, last int
	children    []SourceBlock
}

func (b SourceBlock) Index() int              { return b.index }
func (b SourceBlock) Line() int               { return b.index + 1 }
func (b SourceBlock) LineRange() (int, int)   { return b.Line(), b.last + 1 }
func (b SourceBlock) Header() SourceLine      { return b.document.lines[b.index] }
func (b SourceBlock) Text() string            { return b.Header().Text() }
func (b SourceBlock) Children() []SourceBlock { return append([]SourceBlock{}, b.children...) }
func (b SourceBlock) Lines() []SourceLine {
	return append([]SourceLine{}, b.document.lines[b.index:b.last+1]...)
}
func (b SourceBlock) States() []LineState {
	return append([]LineState{}, b.document.states[b.index:b.last+1]...)
}
func (b SourceBlock) Content() string {
	var out strings.Builder
	for _, l := range b.document.lines[b.index : b.last+1] {
		out.WriteString(l.raw)
	}
	return out.String()
}
func (b SourceBlock) Complete() bool {
	for _, s := range b.document.states[b.index : b.last+1] {
		if !resolvedLine(s) {
			return false
		}
	}
	return true
}
func (b SourceBlock) String() string {
	return fmt.Sprintf("SourceBlock{lines=%d..%d children=%d}", b.Line(), b.last+1, len(b.children))
}
func (b SourceBlock) GoString() string { return b.String() }
func (b SourceBlock) MarshalJSON() ([]byte, error) {
	return json.Marshal(Record{"first_line": b.Line(), "last_line": b.last + 1, "children": len(b.children)})
}

// SourceCapture associates a copied fact with its source block and fact path.
// Data returns a deep copy so callers cannot mutate the retained snapshot.
type SourceCapture struct {
	block SourceBlock
	path  []any
	data  any
}

func (c SourceCapture) Block() SourceBlock    { return c.block }
func (c SourceCapture) Path() []any           { return append([]any{}, c.path...) }
func (c SourceCapture) Data() any             { return clone(c.data) }
func (c SourceCapture) Content() string       { return c.block.Content() }
func (c SourceCapture) Complete() bool        { return c.block.Complete() }
func (c SourceCapture) LineRange() (int, int) { return c.block.LineRange() }
func (c SourceCapture) String() string {
	return fmt.Sprintf("SourceCapture{lines=%d..%d}", c.block.Line(), c.block.last+1)
}
func (c SourceCapture) GoString() string { return c.String() }
func (c SourceCapture) MarshalJSON() ([]byte, error) {
	return json.Marshal(Record{"first_line": c.block.Line(), "last_line": c.block.last + 1, "complete": c.Complete()})
}

func (s *cfgState) enter(b *cfgBlock) {
	s.current = b
	if s.document != nil && s.document.states[b.line-1] == LinePending {
		s.document.states[b.line-1] = LineParsed
	}
}
func (s *cfgState) mark(b *cfgBlock, state LineState) {
	if s.document != nil && b != nil {
		s.document.states[b.line-1] = state
	}
}
func (s *cfgState) capture(b *cfgBlock, value any, path []any) {
	if s.document != nil {
		s.document.captures = append(s.document.captures, SourceCapture{block: sourceBlock(s.document, b), path: append([]any{}, path...), data: clone(value)})
	}
}
func (s *cfgState) scope(b *cfgBlock, path []any, fn func() any) any {
	previous := s.path
	s.path = path
	defer func() { s.path = previous }()
	value := fn()
	s.capture(b, value, path)
	return value
}
func sourcePath(parent []any, keys ...any) []any { return append(append([]any{}, parent...), keys...) }
func sourceBlock(d *ConfigurationDocument, b *cfgBlock) SourceBlock {
	out := SourceBlock{document: d, index: b.line - 1, last: b.last - 1}
	for _, c := range b.children {
		out.children = append(out.children, sourceBlock(d, c))
	}
	return out
}
func (s *cfgState) finishSources(d Record, blocks []*cfgBlock) {
	if s.document == nil {
		return
	}
	for _, b := range blocks {
		s.document.roots = append(s.document.roots, sourceBlock(s.document, b))
	}
	for _, f := range s.features {
		for i, name := range cfgStrings(d[f.collection]) {
			if name == f.name {
				s.capture(f.block, name, []any{f.collection, i})
				break
			}
		}
	}
	for _, collection := range []string{"prefix_lists", "ipv6_prefix_lists", "route_maps"} {
		for _, name := range cfgKeys(cfgMap(d[collection])) {
			for i, row := range cfgRows(cfgMap(d[collection])[name]) {
				if b := s.policies[fmt.Sprintf("%p", row)]; b != nil {
					s.capture(b, row, []any{collection, name, i})
				}
			}
		}
	}
	sort.SliceStable(s.document.captures, func(i, j int) bool { return s.document.captures[i].block.index < s.document.captures[j].block.index })
}

type cfgFeatureSource struct {
	collection, name string
	block            *cfgBlock
}
