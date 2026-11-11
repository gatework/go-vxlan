package record

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"strconv"
)

// Record holds a projected evidence object.
type Record = map[string]any

// Map returns a record view, or an empty record for other types.
func Map(v any) Record {
	m, _ := v.(map[string]any)
	if m == nil {
		return Record{}
	}
	return m
}

// Number converts supported numeric values to an integer.
func Number(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case int64:
		return int(n)
	default:
		i, _ := strconv.Atoi(fmt.Sprint(v))
		return i
	}
}

// NumberFloat converts supported numeric values to float64.
func NumberFloat(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case float64:
		return n
	case int64:
		return float64(n)
	}
	return math.NaN()
}

// Int64 recognizes integral values representable by int64.
func Int64(value any) (int64, bool) {
	switch n := value.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		if n >= math.MinInt64 && n < -float64(math.MinInt64) && math.Trunc(n) == n {
			return int64(n), true
		}
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
	}
	return 0, false
}

// Integer recognizes an exact integer within inclusive bounds.
func Integer(v any, minimum, maximum int) bool {
	switch n := v.(type) {
	case int:
		return n >= minimum && n <= maximum
	case int64:
		return n >= int64(minimum) && n <= int64(maximum)
	case float64:
		return n >= float64(minimum) && n <= float64(maximum) && math.Trunc(n) == n
	default:
		return false
	}
}

// String returns the string value, or an empty string for other types.
func String(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// Truthy reports whether a value is neither nil nor false.
func Truthy(v any) bool { return v != nil && v != false }

// Equal compares normalized evidence values.
func Equal(a, b any) bool {
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case nil:
		return b == nil
	}

	if x, ok := Int64(a); ok {
		y, ok := Int64(b)
		return ok && x == y
	}
	if x, ok := a.(float64); ok {
		if y, ok := b.(float64); ok {
			return x == y
		}
	}
	left, leftErr := CanonicalJSON(a)
	right, rightErr := CanonicalJSON(b)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

// At traverses nested record keys.
func At(v Record, keys ...string) any {
	var a any = v
	for _, k := range keys {
		a = Map(a)[k]
	}
	return a
}

// Merge returns a shallow merged record with the second record taking precedence.
func Merge(a, b Record) Record {
	m := Record{}
	maps.Copy(m, a)
	maps.Copy(m, b)
	return m
}

// MergeLayers recursively merges configuration layers in increasing precedence.
func MergeLayers(ms ...Record) Record {
	out := Record{}
	for _, m := range ms {
		for k, v := range m {
			if child, ok := v.(map[string]any); ok {
				out[k] = MergeLayers(Map(out[k]), child)
			} else {
				out[k] = v
			}
		}
	}
	return out
}

// Select copies the requested fields into a new record.
func Select(a Record, keys ...string) Record {
	m := Record{}
	for _, k := range keys {
		if v, ok := a[k]; ok {
			m[k] = v
		}
	}
	return m
}

// Compact copies non-nil fields into a new record.
func Compact(a Record) Record {
	m := Record{}
	for k, v := range a {
		if v != nil {
			m[k] = v
		}
	}
	return m
}
