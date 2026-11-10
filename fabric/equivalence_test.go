package fabric_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gatework/go-netops/evidence"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

// observed converts a parser observation into the representation-neutral
// input of fabric.NewDevice.
func observed(t *testing.T, o vxlan.Observation) fabric.Observed {
	t.Helper()
	out := fabric.Observed{Status: evidence.Status(o.Status)}
	for _, r := range o.Records {
		body, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		out.Records = append(out.Records, body)
	}
	for _, i := range o.Issues {
		body, err := json.Marshal(i)
		if err != nil {
			t.Fatal(err)
		}
		out.Issues = append(out.Issues, body)
	}
	return out
}

func generic(t *testing.T, v any) any {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var out any
	if err := d.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func zero(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case string:
		return x == ""
	case json.Number:
		return x == "0"
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

// lossless reports the first fact present in original but absent or
// different in roundTrip. Only zero values may be dropped by omitempty.
func lossless(original, roundTrip any, path string) error {
	switch o := original.(type) {
	case map[string]any:
		r, ok := roundTrip.(map[string]any)
		if !ok {
			if zero(o) && roundTrip == nil {
				return nil
			}
			return fmt.Errorf("%s: object became %T", path, roundTrip)
		}
		for k, v := range o {
			rv, present := r[k]
			if !present {
				if zero(v) {
					continue
				}
				return fmt.Errorf("%s.%s: lost %v", path, k, v)
			}
			if err := lossless(v, rv, path+"."+k); err != nil {
				return err
			}
		}
		for k, v := range r {
			if _, present := o[k]; !present && !zero(v) {
				return fmt.Errorf("%s.%s: invented %v", path, k, v)
			}
		}
		return nil
	case []any:
		r, ok := roundTrip.([]any)
		if !ok {
			if len(o) == 0 && roundTrip == nil {
				return nil
			}
			return fmt.Errorf("%s: list became %T", path, roundTrip)
		}
		if len(r) != len(o) {
			return fmt.Errorf("%s: %d items became %d", path, len(o), len(r))
		}
		for i := range o {
			if err := lossless(o[i], r[i], fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	}
	if fmt.Sprint(original) != fmt.Sprint(roundTrip) {
		return fmt.Errorf("%s: %v became %v", path, original, roundTrip)
	}
	return nil
}

func requireModeled(t *testing.T, name string, o vxlan.Observation, d *fabric.Device, dim evidence.Dimension) {
	t.Helper()
	for _, i := range d.Issues[dim] {
		if i.Code == fabric.IssueUnmodeled {
			t.Fatalf("%s: unmodeled fact: %s", name, i.Detail)
		}
	}
	if got := d.Coverage.Status(dim); string(got) != o.Status {
		t.Fatalf("%s: status %s became %s", name, o.Status, got)
	}
}

func TestConfigurationFixturesDecodeLosslessly(t *testing.T) {
	files, _ := filepath.Glob("../testdata/configuration/*.json")
	if len(files) < 400 {
		t.Fatalf("expected the configuration corpus, found %d files", len(files))
	}
	decoded := 0
	for _, f := range files {
		var fixture struct {
			Text     string `json:"text"`
			Complete bool   `json:"complete"`
		}
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &fixture); err != nil {
			t.Fatal(err)
		}
		o, err := nxos.ParseConfigChecked(fixture.Text, fixture.Complete)
		if err != nil {
			continue // input rejected before parsing; nothing to model
		}
		d := fabric.NewDevice(fabric.Identity{Host: "192.0.2.1"}, map[evidence.Dimension]fabric.Observed{fabric.DimConfiguration: observed(t, o)})
		requireModeled(t, filepath.Base(f), o, d, fabric.DimConfiguration)
		if len(o.Records) == 0 {
			continue
		}
		if err := lossless(generic(t, o.Records[0]), generic(t, d.Configuration), "configuration"); err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
		decoded++
	}
	t.Logf("decoded %d configurations losslessly", decoded)
}

func TestRuntimeGoldensDecodeLosslessly(t *testing.T) {
	body, err := os.ReadFile("../testdata/runtime/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID, Name, Text string
		Complete       bool
	}
	if err := json.Unmarshal(body, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		o, err := nxos.ParseRuntime(c.Name, c.Text, c.Complete)
		if err != nil {
			continue
		}
		dim := evidence.Dimension(c.Name)
		d := fabric.NewDevice(fabric.Identity{Host: "192.0.2.1"}, map[evidence.Dimension]fabric.Observed{dim: observed(t, o)})
		requireModeled(t, c.ID, o, d, dim)
		var typed any
		switch dim {
		case fabric.DimVPC:
			if d.VPC != nil {
				typed = []any{d.VPC}
			}
		case fabric.DimCDP:
			typed = d.CDPNeighbors
		case fabric.DimNVEPeers:
			typed = d.NVEPeers
		case fabric.DimNVEVNIs:
			typed = d.NVEVNIs
		case fabric.DimBGP:
			typed = d.BGPNeighbors
		case fabric.DimOSPF:
			typed = d.OSPFNeighbors
		case fabric.DimInterfaces:
			typed = d.Interfaces
		case fabric.DimPortChannels:
			typed = d.PortChannels
		case fabric.DimMACs:
			typed = d.MACs
		case fabric.DimL2RouteMACs:
			typed = d.L2RouteMACs
		case fabric.DimL2RouteMACIPs:
			typed = d.L2RouteMACIPs
		default:
			t.Fatalf("%s: unknown dimension", c.ID)
		}
		if err := lossless(generic(t, o.Records), generic(t, typed), c.Name); err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		for i, raw := range o.Issues {
			issue, err := fabric.DecodeIssue(mustJSON(t, raw))
			if err != nil || issue.Code != raw["code"] {
				t.Fatalf("%s: issue %d not modeled: %v", c.ID, i, err)
			}
		}
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnmodeledFieldDowngradesDimension(t *testing.T) {
	d := fabric.NewDevice(fabric.Identity{Host: "192.0.2.1"}, map[evidence.Dimension]fabric.Observed{
		fabric.DimNVEPeers: {Status: evidence.StatusComplete, Records: []json.RawMessage{json.RawMessage(`{"peer_ip":"10.0.0.2","state":"Up","new_field":1}`)}},
	})
	if d.Has(fabric.DimNVEPeers) || d.Issues[fabric.DimNVEPeers][0].Code != fabric.IssueUnmodeled {
		t.Fatalf("unmodeled field accepted: %+v", d)
	}
}
