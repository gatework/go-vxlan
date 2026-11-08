package vxlan_test

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/configuration"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/review"
)

func TestEvidenceRejectsAmbiguousValues(t *testing.T) {
	cycle := vxlan.Record{}
	cycle["self"] = cycle
	for _, value := range []any{cycle, math.NaN(), math.Inf(1), func() {}, make(chan int), json.Number("1 "), json.Number("null"), string([]byte{0xff}), &struct{ Value string }{"unprojected"}} {
		if _, err := vxlan.ProjectRecord(vxlan.Record{"value": value}); !errors.Is(err, record.ErrEvidence) {
			t.Fatalf("accepted %T: %v", value, err)
		}
		if hash, err := vxlan.Fingerprint(value); hash != "" || !errors.Is(err, record.ErrEvidence) {
			t.Fatalf("hashed %T: %q %v", value, hash, err)
		}
		if _, err := vxlan.NewObservation("configuration", "complete", []vxlan.Record{{"value": value}}, nil, nil); !errors.Is(err, record.ErrEvidence) {
			t.Fatalf("copied %T: %v", value, err)
		}
	}
}

func TestEvidenceAllowsSharedSliceViews(t *testing.T) {
	shared := []any{int64(1), nil}
	shared[1] = shared[:1]
	projected, err := vxlan.ProjectRecord(vxlan.Record{"value": shared})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(projected)
	if err != nil || string(body) != `{"value":[1,[1]]}` {
		t.Fatalf("shared view rejected: %s %v", body, err)
	}
}

func TestDomainEncodingFailuresDoNotPanicOrBecomeNoConflict(t *testing.T) {
	cycle := vxlan.Record{}
	cycle["self"] = cycle
	if _, err := configuration.NewSubnetIndex(cycle).Conflicts("192.0.2.0/24", "tenant", 10001, ""); !errors.Is(err, record.ErrEvidence) {
		t.Fatal("invalid index became no conflict", err)
	}
	if values := configuration.ServiceRouteTargets([]vxlan.Record{{"direction": "both", "target": func() {}}}, 65000, 10001); values != nil {
		t.Fatal("unencodable route target accepted")
	}
	policy := vxlan.Record{"fabrics": vxlan.Record{"A": vxlan.Record{"leaves": []string{"192.0.2.1", "192.0.2.2"}}}}
	if _, err := review.ReviewFabric([]vxlan.Record{cycle}, policy); !errors.Is(err, record.ErrEvidence) {
		t.Fatal("invalid fabric document accepted", err)
	}
}

func TestLiveAndPersistedEvidenceShareProjection(t *testing.T) {
	row := vxlan.Record{"counter": json.Number("9007199254740993"), "fraction": json.Number("0.123456789012345678901"), "nil_rows": []vxlan.Record(nil), "empty_rows": []vxlan.Record{}, "nil_map": vxlan.Record(nil), "empty_map": vxlan.Record{}}
	observation, err := vxlan.NewObservation("bgp_neighbors", "complete", []vxlan.Record{row}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	device := vxlan.Record{"host": "192.0.2.1", "name": "leaf"}
	live := vxlan.Record{"device": device, "snapshot": vxlan.Snapshot{Target: device, Dimensions: map[string]vxlan.Observation{"bgp_neighbors": observation}}}
	projected, err := vxlan.NewEvidenceDocument(live)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(live)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := vxlan.DecodeDocument(body)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err = vxlan.NewEvidenceDocument(persisted)
	if err != nil || !reflect.DeepEqual(projected, persisted) {
		t.Fatalf("projection mismatch: %v", err)
	}
	rows := evidenceList(evidenceObject(evidenceObject(evidenceObject(projected["snapshot"])["dimensions"])["bgp_neighbors"])["records"])
	got := evidenceObject(rows[0])
	if got["nil_rows"] != nil || got["nil_map"] != nil || got["empty_rows"] == nil || got["empty_map"] == nil {
		t.Fatalf("nil/empty changed: %#v", got)
	}
	row["counter"] = 0
	if got["counter"] != int64(9007199254740993) {
		t.Fatal("evidence aliased or rounded")
	}
	a, err := vxlan.Fingerprint(projected)
	if err != nil {
		t.Fatal(err)
	}
	b, err := vxlan.Fingerprint(persisted)
	if err != nil || a != b {
		t.Fatalf("fingerprint mismatch: %v", err)
	}
	if record.Equal(int64(9007199254740993), float64(9007199254740992)) {
		t.Fatal("adjacent exact numbers compared equal")
	}
}

func evidenceObject(v any) vxlan.Record { r, _ := v.(vxlan.Record); return r }
func evidenceList(v any) []any          { r, _ := v.([]any); return r }
