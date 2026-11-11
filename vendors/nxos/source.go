package nxos

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

// LineState distinguishes successful interpretation from unrelated, rejected,
// and unvisited source. Merely reading a line does not mean it was parsed.
type LineState string

// Source line classification states.
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
//
//nolint:recvcheck // Value-formatting methods intentionally redact values and pointers consistently.
type ConfigurationParser struct{ document *ConfigurationDocument }

// Parse validates input and retains the parsed source document.
func (p *ConfigurationParser) Parse(text string, complete bool) (vxlan.Observation, error) {
	p.document = nil
	if err := validateConfigInput(text); err != nil {
		return vxlan.Observation{}, err
	}
	d := newConfigurationDocument(text)
	o := parseConfig(text, complete, d)
	p.document = d
	return o, nil
}

// Document returns the most recently parsed source document.
func (p *ConfigurationParser) Document() *ConfigurationDocument { return p.document }
func (p ConfigurationParser) String() string {
	return fmt.Sprintf("ConfigurationParser{document=%t}", p.document != nil)
}

// GoString returns diagnostic metadata without configuration payloads.
func (p ConfigurationParser) GoString() string { return p.String() }

// MarshalJSON encodes metadata without exposing configuration text.
func (p ConfigurationParser) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Document *ConfigurationDocument `json:"document"`
	}{p.document})
}

// ParseConfigChecked rejects malformed UTF-8 and NUL bytes before parsing.
// Unsupported NX-OS syntax remains a partial Observation, not a Go error.
func ParseConfigChecked(text string, complete bool) (vxlan.Observation, error) {
	if err := validateConfigInput(text); err != nil {
		return vxlan.Observation{}, err
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
//
//nolint:recvcheck // Value-formatting methods intentionally redact values and pointers consistently.
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

// Content returns the explicit original configuration text.
func (d *ConfigurationDocument) Content() string { return d.content }

// Checksum returns the SHA256 digest of the original source bytes.
func (d *ConfigurationDocument) Checksum() string { return d.checksum }

// Size returns the number of source lines.
func (d *ConfigurationDocument) Size() int { return len(d.lines) }

// Position returns the completed parser position.
func (d *ConfigurationDocument) Position() int { return d.Size() }

// EOF reports whether the source traversal reached its end.
func (d *ConfigurationDocument) EOF() bool { return true }

// Lines returns a detached list of source lines.
func (d *ConfigurationDocument) Lines() []SourceLine { return append([]SourceLine{}, d.lines...) }

// States returns a detached list of line classification states.
func (d *ConfigurationDocument) States() []LineState { return append([]LineState{}, d.states...) }

// State uses a zero-based line index and returns an error outside the document.
func (d *ConfigurationDocument) State(index int) (LineState, error) {
	if index < 0 || index >= d.Size() {
		return "", fmt.Errorf("source line index out of range: %d", index)
	}
	return d.states[index], nil
}

// Visited reports whether the line index lies within the parsed document.
func (d *ConfigurationDocument) Visited(index int) bool { return index >= 0 && index < d.Size() }

// Parsed reports whether the line was classified as parsed.
func (d *ConfigurationDocument) Parsed(index int) bool {
	return index >= 0 && index < d.Size() && d.states[index] == LineParsed
}

// Roots returns detached top-level source block metadata.
func (d *ConfigurationDocument) Roots() []SourceBlock { return append([]SourceBlock{}, d.roots...) }

// Captures returns detached captured values and source associations.
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

// UnparsedLines returns source lines with no accepted classification.
func (d *ConfigurationDocument) UnparsedLines() []SourceLine {
	out := []SourceLine{}
	for i, l := range d.lines {
		if !resolvedLine(d.states[i]) {
			out = append(out, l)
		}
	}
	return out
}

// UnparsedContent joins the source text of unparsed lines.
func (d *ConfigurationDocument) UnparsedContent() string {
	var b strings.Builder
	for _, l := range d.UnparsedLines() {
		b.WriteString(l.raw)
	}
	return b.String()
}

// Complete reports whether every relevant source line was accepted.
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

// GoString returns diagnostic metadata without configuration payloads.
func (d ConfigurationDocument) GoString() string { return d.String() }

// MarshalJSON encodes metadata without exposing configuration text.
func (d ConfigurationDocument) MarshalJSON() ([]byte, error) {
	counts := map[LineState]int{}
	for _, s := range d.states {
		counts[s]++
	}
	return json.Marshal(vxlan.Record{"position": d.Position(), "lines": d.Size(), "states": counts, "captures": len(d.captures)})
}
func resolvedLine(s LineState) bool { return s == LineParsed || s == LineIgnored }

// SourceLine retains an original physical line, including its line terminator.
type SourceLine struct {
	index, indent int
	raw           string
}

// Index returns the zero-based source line index.
func (l SourceLine) Index() int { return l.index }

// Number returns the one-based source line number.
func (l SourceLine) Number() int { return l.index + 1 }

// Indent returns the source indentation width.
func (l SourceLine) Indent() int { return l.indent }

// Content returns the explicit original configuration text.
func (l SourceLine) Content() string { return l.raw }

// Text returns the trimmed source text.
func (l SourceLine) Text() string   { return strings.Trim(l.raw, " \t\r\n\v\f") }
func (l SourceLine) String() string { return fmt.Sprintf("SourceLine{number=%d}", l.Number()) }

// GoString returns diagnostic metadata without configuration payloads.
func (l SourceLine) GoString() string { return l.String() }

// MarshalJSON encodes metadata without exposing configuration text.
func (l SourceLine) MarshalJSON() ([]byte, error) {
	return json.Marshal(vxlan.Record{"number": l.Number()})
}

// SourceBlock covers a header and its original subtree, including interleaved
// comments and blank lines. Ranges use inclusive, one-based line numbers.
type SourceBlock struct {
	document    *ConfigurationDocument
	index, last int
	children    []SourceBlock
}

// Index returns the zero-based source line index.
func (b SourceBlock) Index() int { return b.index }

// Line returns the one-based starting line number.
func (b SourceBlock) Line() int { return b.index + 1 }

// LineRange returns inclusive one-based source line boundaries.
func (b SourceBlock) LineRange() (int, int) { return b.Line(), b.last + 1 }

// Header returns the block header source line.
func (b SourceBlock) Header() SourceLine { return b.document.lines[b.index] }

// Text returns the trimmed source text.
func (b SourceBlock) Text() string { return b.Header().Text() }

// Children returns a detached list of nested blocks.
func (b SourceBlock) Children() []SourceBlock { return append([]SourceBlock{}, b.children...) }

// Lines returns a detached list of source lines.
func (b SourceBlock) Lines() []SourceLine {
	return append([]SourceLine{}, b.document.lines[b.index:b.last+1]...)
}

// States returns a detached list of line classification states.
func (b SourceBlock) States() []LineState {
	return append([]LineState{}, b.document.states[b.index:b.last+1]...)
}

// Content returns the explicit original configuration text.
func (b SourceBlock) Content() string {
	var out strings.Builder
	for _, l := range b.document.lines[b.index : b.last+1] {
		out.WriteString(l.raw)
	}
	return out.String()
}

// Complete reports whether every relevant source line was accepted.
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

// GoString returns diagnostic metadata without configuration payloads.
func (b SourceBlock) GoString() string { return b.String() }

// MarshalJSON encodes metadata without exposing configuration text.
func (b SourceBlock) MarshalJSON() ([]byte, error) {
	return json.Marshal(vxlan.Record{"first_line": b.Line(), "last_line": b.last + 1, "children": len(b.children)})
}

// SourceCapture associates a copied fact with its source block and fact path.
// Data returns a deep copy so callers cannot mutate the retained snapshot.
type SourceCapture struct {
	block SourceBlock
	path  []any
	data  any
}

// Block returns the source block owning the captured value.
func (c SourceCapture) Block() SourceBlock { return c.block }

// Path returns a detached path into the projected configuration.
func (c SourceCapture) Path() []any { return append([]any{}, c.path...) }

// Data returns a detached captured value.
func (c SourceCapture) Data() any { return record.Copy(c.data) }

// Content returns the explicit original configuration text.
func (c SourceCapture) Content() string { return c.block.Content() }

// Complete reports whether every relevant source line was accepted.
func (c SourceCapture) Complete() bool { return c.block.Complete() }

// LineRange returns inclusive one-based source line boundaries.
func (c SourceCapture) LineRange() (int, int) { return c.block.LineRange() }
func (c SourceCapture) String() string {
	return fmt.Sprintf("SourceCapture{lines=%d..%d}", c.block.Line(), c.block.last+1)
}

// GoString returns diagnostic metadata without configuration payloads.
func (c SourceCapture) GoString() string { return c.String() }

// MarshalJSON encodes metadata without exposing configuration text.
func (c SourceCapture) MarshalJSON() ([]byte, error) {
	return json.Marshal(vxlan.Record{"first_line": c.block.Line(), "last_line": c.block.last + 1, "complete": c.Complete()})
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
		s.document.captures = append(s.document.captures, SourceCapture{block: sourceBlock(s.document, b), path: append([]any{}, path...), data: record.Copy(value)})
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
func (s *cfgState) finishSources(d vxlan.Record, blocks []*cfgBlock) {
	if s.document == nil {
		return
	}
	for _, b := range blocks {
		s.document.roots = append(s.document.roots, sourceBlock(s.document, b))
	}
	for _, f := range s.features {
		for i, name := range record.StringSlice(d[f.collection]) {
			if name == f.name {
				s.capture(f.block, name, []any{f.collection, i})
				break
			}
		}
	}
	for _, collection := range []string{"prefix_lists", "ipv6_prefix_lists", "route_maps"} {
		for _, name := range record.Keys(record.Map(d[collection])) {
			for i, row := range record.Rows(record.Map(d[collection])[name]) {
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
