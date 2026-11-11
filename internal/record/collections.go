package record

import (
	"slices"
	"sort"
)

// List views supported record and string slices as a list, or returns nil.
func List(v any) []any {
	if a, ok := v.([]Record); ok {
		r := []any{}
		for _, x := range a {
			r = append(r, x)
		}
		return r
	}
	if a, ok := v.([]any); ok {
		return a
	}
	if a, ok := v.([]string); ok {
		r := []any{}
		for _, s := range a {
			r = append(r, s)
		}
		return r
	}
	return nil
}

// Texts selects the string elements of a supported list.
func Texts(v any) []string {
	r := []string{}
	for _, x := range List(v) {
		if s, ok := x.(string); ok {
			r = append(r, s)
		}
	}
	return r
}

// StringSlice reads a string array and panics on a violated internal type invariant.
func StringSlice(v any) []string {
	if v == nil {
		return []string{}
	}
	if s, ok := v.([]string); ok {
		return s
	}
	out := []string{}
	values, ok := v.([]any)
	if !ok {
		panic("record: string array has an invalid type")
	}
	for _, a := range values {
		value, ok := a.(string)
		if !ok {
			panic("record: string array contains a non-string")
		}
		out = append(out, value)
	}
	return out
}

// Rows reads record rows and panics if the container is not an array.
func Rows(v any) []Record {
	if v == nil {
		return []Record{}
	}
	if r, ok := v.([]Record); ok {
		return r
	}
	out := []Record{}
	values, ok := v.([]any)
	if !ok {
		panic("record: row array has an invalid type")
	}
	for _, x := range values {
		out = append(out, Map(x))
	}
	return out
}

// Keys returns lexically sorted map keys.
func Keys(m Record) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// NaturalKeys orders keys with numeric suffixes numerically within a shared prefix.
func NaturalKeys(m Record) []string {
	keys := Keys(m)
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		prefixA, prefixB := a, b
		for len(prefixA) > 0 && prefixA[len(prefixA)-1] >= '0' && prefixA[len(prefixA)-1] <= '9' {
			prefixA = prefixA[:len(prefixA)-1]
		}
		for len(prefixB) > 0 && prefixB[len(prefixB)-1] >= '0' && prefixB[len(prefixB)-1] <= '9' {
			prefixB = prefixB[:len(prefixB)-1]
		}
		if prefixA == prefixB && prefixA != a && prefixB != b {
			return Number(a[len(prefixA):]) < Number(b[len(prefixB):])
		}
		return a < b
	})
	return keys
}

// UniqueSorted returns sorted distinct strings.
func UniqueSorted(x []string) []string {
	m := map[string]bool{}
	for _, v := range x {
		m[v] = true
	}
	out := []string{}
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Unique is confined to fabric review, whose error boundary preserves errors.
func Unique(rows []any) []any {
	out, err := UniqueChecked(rows)
	if err != nil {
		panic(err)
	}
	return out
}

// UniqueChecked deduplicates rows by canonical JSON and rejects unsupported evidence.
func UniqueChecked(rows []any) ([]any, error) {
	out := []any{}
	seen := map[string]bool{}
	for _, row := range rows {
		encoded, err := CanonicalJSON(row)
		if err != nil {
			return nil, err
		}
		key := string(encoded)
		if !seen[key] {
			seen[key] = true
			out = append(out, row)
		}
	}
	return out, nil
}

// Contains reports whether the list contains the value.
func Contains(xs []string, v string) bool {
	return slices.Contains(xs, v)
}

// Slice accepts only arrays containing records.
func Slice(v any) ([]Record, bool) {
	switch rows := v.(type) {
	case []Record:
		return rows, true
	case []any:
		r := []Record{}
		for _, x := range rows {
			m, ok := x.(map[string]any)
			if !ok {
				return nil, false
			}
			r = append(r, m)
		}
		return r, true
	default:
		return nil, false
	}
}

// Strings accepts only arrays containing strings.
func Strings(v any) ([]string, bool) {
	switch s := v.(type) {
	case []string:
		return s, true
	case []any:
		r := []string{}
		for _, x := range s {
			v, ok := x.(string)
			if !ok {
				return nil, false
			}
			r = append(r, v)
		}
		return r, true
	default:
		return nil, false
	}
}
