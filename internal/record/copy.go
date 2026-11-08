package record

import (
	"encoding/json"
	"reflect"
	"slices"
)

func Copy(v any) any {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case map[string]any:
		if x == nil {
			return x
		}
		y := Record{}
		for k, v := range x {
			y[k] = Copy(v)
		}
		return y
	case []Record:
		if x == nil {
			return x
		}
		return CopyRecords(x)
	case []any:
		if x == nil {
			return x
		}
		y := make([]any, len(x))
		for i, v := range x {
			y[i] = Copy(v)
		}
		return y
	case []string:
		return slices.Clone(x)
	case json.Number:
		return x
	default:
		return copyReflect(reflect.ValueOf(v)).Interface()
	}
}

func CopyRecords(in []Record) []Record {
	out := make([]Record, len(in))
	for i, r := range in {
		out[i] = Copy(r).(Record)
	}
	return out
}

func copyReflect(v reflect.Value) reflect.Value {
	if !v.IsValid() {
		return reflect.ValueOf((*any)(nil)).Elem()
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		r := reflect.New(v.Type()).Elem()
		r.Set(copyReflect(v.Elem()))
		return r
	case reflect.Map:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		r := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			r.SetMapIndex(iter.Key(), copyReflect(iter.Value()))
		}
		return r
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		r := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			r.Index(i).Set(copyReflect(v.Index(i)))
		}
		return r
	case reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		r := reflect.New(v.Type().Elem())
		r.Elem().Set(copyReflect(v.Elem()))
		return r
	case reflect.Array:
		r := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			r.Index(i).Set(copyReflect(v.Index(i)))
		}
		return r
	default:
		return v
	}
}
