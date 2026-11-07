// Package vxlan models Cisco NX-OS VXLAN evidence independently of its transport.
package vxlan

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

type Record = map[string]any

type Observation struct {
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	Records     []Record   `json:"records"`
	Issues      []Record   `json:"issues"`
	Evidence    []Record   `json:"evidence"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
}

func NewObservation(name, status string, records, issues, evidence []Record) (Observation, error) {
	if name == "" {
		return Observation{}, fmt.Errorf("empty observation name")
	}
	switch status {
	case "complete", "partial", "failed", "unsupported", "not_requested":
	default:
		return Observation{}, fmt.Errorf("invalid observation status")
	}
	return Observation{Name: name, Status: status, Records: copyRecords(records), Issues: copyRecords(issues), Evidence: copyRecords(evidence)}, nil
}
func (o Observation) Complete() bool { return o.Status == "complete" }
func (o Observation) String() string {
	return fmt.Sprintf("Observation{name=%s status=%s records=%d}", o.Name, o.Status, len(o.Records))
}
func (o Observation) GoString() string { return o.String() }

type Snapshot struct {
	Target     Record                 `json:"target"`
	FabricKey  any                    `json:"fabric_key"`
	Dimensions map[string]Observation `json:"dimensions"`
	ObservedAt *time.Time             `json:"observed_at"`
}

func (s Snapshot) Complete() bool {
	n := 0
	for _, o := range s.Dimensions {
		if o.Status == "not_requested" {
			continue
		}
		n++
		if !o.Complete() {
			return false
		}
	}
	return n > 0
}
func (s Snapshot) String() string {
	return fmt.Sprintf("Snapshot{complete=%t dimensions=%d}", s.Complete(), len(s.Dimensions))
}
func (s Snapshot) GoString() string { return s.String() }
func copyRecords(in []Record) []Record {
	out := make([]Record, len(in))
	for i, r := range in {
		out[i] = clone(r).(Record)
	}
	return out
}
func clone(v any) any {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case map[string]any:
		y := Record{}
		for k, v := range x {
			y[k] = clone(v)
		}
		return y
	case []Record:
		return copyRecords(x)
	case []any:
		y := make([]any, len(x))
		for i, v := range x {
			y[i] = clone(v)
		}
		return y
	case []string:
		return append([]string{}, x...)
	case json.Number:
		return x
	default:
		return cloneReflect(reflect.ValueOf(v)).Interface()
	}
}
func observation(name, status string, rows, issues []Record) Observation {
	o, _ := NewObservation(name, status, rows, issues, nil)
	return o
}

func cloneReflect(v reflect.Value) reflect.Value {
	if !v.IsValid() {
		return reflect.ValueOf((*any)(nil)).Elem()
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		r := reflect.New(v.Type()).Elem()
		r.Set(cloneReflect(v.Elem()))
		return r
	case reflect.Map:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		r := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			r.SetMapIndex(iter.Key(), cloneReflect(iter.Value()))
		}
		return r
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		r := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			r.Index(i).Set(cloneReflect(v.Index(i)))
		}
		return r
	case reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		r := reflect.New(v.Type().Elem())
		r.Elem().Set(cloneReflect(v.Elem()))
		return r
	case reflect.Array:
		r := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			r.Index(i).Set(cloneReflect(v.Index(i)))
		}
		return r
	default:
		return v
	}
}
