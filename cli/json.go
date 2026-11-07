package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"
)

// decodeDocument preserves exact evidence numbers and rejects ambiguous objects.
// The same boundary applies to persisted evidence and executable plans.
func decodeDocument(body []byte) (M, error) {
	if !utf8.Valid(body) {
		return nil, fmt.Errorf("JSON 编码无效")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 128 {
			return nil, fmt.Errorf("JSON 嵌套过深")
		}
		token, e := decoder.Token()
		if e != nil {
			return nil, e
		}
		switch t := token.(type) {
		case json.Delim:
			switch t {
			case '{':
				m := M{}
				for decoder.More() {
					key, e := decoder.Token()
					if e != nil {
						return nil, e
					}
					k, ok := key.(string)
					if !ok {
						return nil, fmt.Errorf("JSON 键无效")
					}
					if _, exists := m[k]; exists {
						return nil, fmt.Errorf("JSON 包含重复键")
					}
					value, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					m[k] = value
				}
				if _, e = decoder.Token(); e != nil {
					return nil, e
				}
				return m, nil
			case '[':
				a := []any{}
				for decoder.More() {
					value, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, value)
				}
				if _, e = decoder.Token(); e != nil {
					return nil, e
				}
				return a, nil
			default:
				return nil, fmt.Errorf("JSON 分隔符无效")
			}
		case json.Number:
			return documentNumber(t), nil
		default:
			return token, nil
		}
	}
	value, e := read(0)
	if e != nil {
		return nil, e
	}
	if _, e = decoder.Token(); e != io.EOF {
		return nil, fmt.Errorf("JSON 存在多余内容")
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("JSON 须为对象")
	}
	return m, nil
}

// Domain identities use int64; larger counters and fractions retain their JSON
// representation. Normalize integral decimal/exponent forms without rounding.
func documentNumber(n json.Number) any {
	if i, e := n.Int64(); e == nil {
		return i
	}
	s := n.String()
	if len(s) > 1024 {
		return n
	}
	if index := strings.LastIndexAny(s, "eE"); index >= 0 {
		exponent, e := strconv.Atoi(s[index+1:])
		if e != nil || exponent < -1024 || exponent > 1024 {
			return n
		}
	}
	rational, ok := new(big.Rat).SetString(s)
	if ok && rational.IsInt() && rational.Num().IsInt64() {
		return rational.Num().Int64()
	}
	return n
}

func integerInRange(value any, min, max int64) bool {
	switch v := value.(type) {
	case int:
		return int64(v) >= min && int64(v) <= max
	case int64:
		return v >= min && v <= max
	case float64:
		return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= float64(min) && v <= float64(max) && math.Trunc(v) == v
	default:
		return false
	}
}
