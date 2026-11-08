package vxlan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	recordpkg "github.com/gatework/go-vxlan/internal/record"
)

type evidenceVisit struct {
	kind    reflect.Kind
	pointer uintptr
	length  int
}

// ProjectRecord produces owned JSON evidence without an encoding round trip.
// Snapshot and Observation have explicit projections; arbitrary structs and
// pointers are rejected. Nil containers remain null, and empty ones remain empty.
func ProjectRecord(value any) (Record, error) {
	projected, err := projectValue(reflect.ValueOf(value), make(map[evidenceVisit]bool), 0)
	if err != nil {
		return nil, err
	}
	record, ok := projected.(Record)
	if !ok || record == nil {
		return nil, recordpkg.ErrEvidence
	}
	return record, nil
}

func projectValue(v reflect.Value, active map[evidenceVisit]bool, depth int) (any, error) {
	if depth > 128 {
		return nil, recordpkg.ErrEvidence
	}
	if !v.IsValid() {
		return nil, nil
	}
	if v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil, nil
		}
		return projectValue(v.Elem(), active, depth)
	}
	if v.CanInterface() {
		var projected any
		switch x := v.Interface().(type) {
		case Snapshot:
			projected = Record{"target": x.Target, "fabric_key": x.FabricKey, "dimensions": x.Dimensions, "observed_at": x.ObservedAt}
		case *Snapshot:
			if x == nil {
				return nil, nil
			}
			return projectValue(reflect.ValueOf(*x), active, depth)
		case Observation:
			projected = Record{"name": x.Name, "status": x.Status, "records": x.Records, "issues": x.Issues, "evidence": x.Evidence, "started_at": x.StartedAt, "completed_at": x.CompletedAt}
		case time.Time:
			if _, err := x.MarshalJSON(); err != nil {
				return nil, recordpkg.ErrEvidence
			}
			return x.Format(time.RFC3339Nano), nil
		case *time.Time:
			if x == nil {
				return nil, nil
			}
			return projectValue(reflect.ValueOf(*x), active, depth)
		case json.Number:
			if strings.TrimSpace(string(x)) != string(x) || !json.Valid([]byte(x)) || len(x) == 0 || x[0] != '-' && (x[0] < '0' || x[0] > '9') {
				return nil, recordpkg.ErrEvidence
			}
			return documentNumber(x), nil
		}
		if projected != nil {
			return projectValue(reflect.ValueOf(projected), active, depth)
		}
	}
	switch v.Kind() {
	case reflect.Map, reflect.Slice:
		if v.IsNil() {
			return nil, nil
		}
		key := evidenceVisit{kind: v.Kind(), pointer: v.Pointer(), length: v.Len()}
		if active[key] {
			return nil, recordpkg.ErrEvidence
		}
		active[key] = true
		defer delete(active, key)
		if v.Kind() == reflect.Map {
			if v.Type().Key().Kind() != reflect.String {
				return nil, recordpkg.ErrEvidence
			}
			out := make(Record, v.Len())
			iter := v.MapRange()
			for iter.Next() {
				name := iter.Key().String()
				if !utf8.ValidString(name) {
					return nil, recordpkg.ErrEvidence
				}
				value, err := projectValue(iter.Value(), active, depth+1)
				if err != nil {
					return nil, err
				}
				out[name] = value
			}
			return out, nil
		}
		fallthrough
	case reflect.Array:
		out := make([]any, v.Len())
		for i := range v.Len() {
			value, err := projectValue(v.Index(i), active, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = value
		}
		return out, nil
	case reflect.String:
		if !utf8.ValidString(v.String()) {
			return nil, recordpkg.ErrEvidence
		}
		return v.String(), nil
	case reflect.Bool:
		return v.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return documentNumber(json.Number(strconv.FormatUint(v.Uint(), 10))), nil
	case reflect.Float32, reflect.Float64:
		n := v.Float()
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, recordpkg.ErrEvidence
		}
		encoded, err := json.Marshal(v.Interface())
		if err != nil {
			return nil, recordpkg.ErrEvidence
		}
		return documentNumber(json.Number(encoded)), nil
	default:
		return nil, recordpkg.ErrEvidence
	}
}

// NewEvidenceDocument checks the same structural contract for live projections
// and persisted JSON documents. The returned record is detached from the caller.
func NewEvidenceDocument(value any) (Record, error) {
	document, err := ProjectRecord(value)
	if err != nil {
		return nil, err
	}
	if err := validateEvidenceDocument(document); err != nil {
		return nil, err
	}
	return document, nil
}

func evidenceObject(value any) Record { r, _ := value.(Record); return r }
func evidenceList(value any) []any    { r, _ := value.([]any); return r }
func evidenceString(value any) string { r, _ := value.(string); return r }

// DecodeDocument preserves exact evidence numbers and rejects ambiguous objects.
// The same boundary applies to persisted evidence and executable plans.
func DecodeDocument(body []byte) (Record, error) {
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
				m := Record{}
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

func validateEvidenceDocument(doc Record) error {
	d, ok := doc["device"].(map[string]any)
	if !ok {
		return fmt.Errorf("无设备身份")
	}
	host := evidenceString(d["host"])
	ip, e := netip.ParseAddr(host)
	if e != nil || ip.String() != host || evidenceString(d["name"]) == "" {
		return fmt.Errorf("设备身份无效")
	}
	v, ok := doc["snapshot"]
	if !ok {
		return fmt.Errorf("无快照字段")
	}
	if v == nil {
		return nil
	}
	snap, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("快照结构错误")
	}
	dims, ok := snap["dimensions"].(map[string]any)
	if !ok {
		return fmt.Errorf("观测结构错误")
	}
	if target, ok := snap["target"]; ok && evidenceString(evidenceObject(target)["host"]) != host {
		return fmt.Errorf("设备与快照身份不一致")
	}
	for name, value := range dims {
		o, ok := value.(map[string]any)
		if !ok || !slices.Contains([]string{"complete", "partial", "failed", "unsupported", "not_requested"}, evidenceString(o["status"])) {
			return fmt.Errorf("观测状态无效")
		}
		rows, ok := o["records"].([]any)
		if !ok {
			return fmt.Errorf("观测记录须为数组")
		}
		if issues, ok := o["issues"]; ok {
			if _, ok = issues.([]any); !ok {
				return fmt.Errorf("诊断须为数组")
			}
			for _, x := range evidenceList(issues) {
				if _, ok = x.(map[string]any); !ok {
					return fmt.Errorf("诊断须为记录")
				}
			}
		}
		for _, row := range rows {
			r, ok := row.(map[string]any)
			if !ok {
				return fmt.Errorf("观测记录无效")
			}
			if name == "configuration" {
				if e := validateConfigurationRecord(r); e != nil {
					return e
				}
			}
		}
	}
	return nil
}

// ValidateConfigurationRecord checks the structural configuration contract.
func ValidateConfigurationRecord(record Record) error {
	r, err := ProjectRecord(record)
	if err != nil {
		return err
	}
	return validateConfigurationRecord(r)
}

func validateConfigurationRecord(r Record) error {
	records := func(v any) error {
		a, ok := v.([]any)
		if !ok {
			return fmt.Errorf("配置列表无效")
		}
		for _, x := range a {
			if _, ok := x.(map[string]any); !ok {
				return fmt.Errorf("配置条目无效")
			}
		}
		return nil
	}
	if v, ok := r["review_findings"]; ok {
		if e := records(v); e != nil {
			return e
		}
	}
	for _, x := range evidenceObject(r["evpn"]) {
		if v, ok := evidenceObject(x)["route_targets"]; ok {
			if e := records(v); e != nil {
				return e
			}
		}
	}
	hashes := func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("配置映射无效")
		}
		for _, x := range m {
			if _, ok = x.(map[string]any); !ok {
				return fmt.Errorf("配置记录无效")
			}
		}
		return nil
	}
	for _, k := range []string{"interfaces", "vrfs", "evpn"} {
		if v, ok := r[k]; ok {
			if e := hashes(v); e != nil {
				return e
			}
		}
	}
	for _, k := range []string{"nve", "vlan_vnis", "acls", "address_groups"} {
		if v, ok := r[k]; ok {
			if _, ok = v.(map[string]any); !ok {
				return fmt.Errorf("配置容器无效")
			}
		}
	}
	if v, ok := evidenceObject(r["nve"])["members"]; ok {
		if e := hashes(v); e != nil {
			return e
		}
	}
	for _, x := range evidenceObject(r["interfaces"]) {
		v := evidenceObject(x)
		if a, ok := v["addresses"]; ok {
			if evidenceList(a) == nil {
				return fmt.Errorf("接口地址无效")
			}
			for _, addr := range evidenceList(a) {
				if _, e := netip.ParsePrefix(evidenceString(addr)); e != nil {
					return fmt.Errorf("接口地址无效")
				}
			}
		}
		if b, ok := v["acl_bindings"]; ok {
			m, ok := b.(map[string]any)
			if !ok {
				return fmt.Errorf("ACL 绑定无效")
			}
			for direction, name := range m {
				if !slices.Contains([]string{"in", "out"}, direction) || evidenceString(name) == "" {
					return fmt.Errorf("ACL 绑定无效")
				}
			}
		}
	}
	for _, v := range evidenceObject(r["acls"]) {
		if evidenceList(v) == nil {
			return fmt.Errorf("ACL 规则无效")
		}
		for _, x := range evidenceList(v) {
			entry, ok := x.(map[string]any)
			if !ok || !slices.Contains([]string{"permit", "deny", "remark"}, evidenceString(entry["action"])) || !recordpkg.Integer(entry["sequence"], 1, 4294967295) {
				return fmt.Errorf("ACL 规则无效")
			}
			if _, ok := entry["expression"].(string); !ok {
				return fmt.Errorf("ACL 表达式无效")
			}
		}
	}
	for _, v := range evidenceObject(r["address_groups"]) {
		if evidenceList(v) == nil {
			return fmt.Errorf("地址组无效")
		}
		for _, x := range evidenceList(v) {
			p, e := netip.ParsePrefix(evidenceString(x))
			if e != nil || !p.Addr().Is4() {
				return fmt.Errorf("地址组成员无效")
			}
		}
	}
	return nil
}
