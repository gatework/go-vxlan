package record

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
)

type Record = map[string]any

func Map(v any) Record {
	m, _ := v.(map[string]any)
	if m == nil {
		return Record{}
	}
	return m
}

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

func Integer(v any, min, max int) bool {
	switch n := v.(type) {
	case int:
		return n >= min && n <= max
	case int64:
		return n >= int64(min) && n <= int64(max)
	case float64:
		return n >= float64(min) && n <= float64(max) && math.Trunc(n) == n
	default:
		return false
	}
}

func String(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func Truthy(v any) bool { return v != nil && v != false }

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

func At(v Record, keys ...string) any {
	var a any = v
	for _, k := range keys {
		a = Map(a)[k]
	}
	return a
}

func Merge(a, b Record) Record {
	m := Record{}
	for k, v := range a {
		m[k] = v
	}
	for k, v := range b {
		m[k] = v
	}
	return m
}

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

func Select(a Record, keys ...string) Record {
	m := Record{}
	for _, k := range keys {
		if v, ok := a[k]; ok {
			m[k] = v
		}
	}
	return m
}

func Compact(a Record) Record {
	m := Record{}
	for k, v := range a {
		if v != nil {
			m[k] = v
		}
	}
	return m
}
