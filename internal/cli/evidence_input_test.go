package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/report"
)

func evidenceBatch(t *testing.T, body string) string {
	t.Helper()
	d := t.TempDir()
	if e := os.Mkdir(filepath.Join(d, "evidence"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(d, "evidence", "leaf.json"), []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
	return d
}
func TestEvidenceNumbers(t *testing.T) {
	body := `{"device":{"host":"192.0.2.1","name":"leaf"},"snapshot":{"dimensions":{"bgp_neighbors":{"status":"complete","records":[{"state":"Idle","messages_received":9007199254740993}],"issues":[]}}}}`
	sources, e := report.ReadSources(context.Background(), evidenceBatch(t, body))
	if e != nil {
		t.Fatal(e)
	}
	device, e := fabric.EncodeDocument(sources[0].Document)
	if e != nil {
		t.Fatal(e)
	}
	if len(device.BGPNeighbors) != 1 || device.BGPNeighbors[0].MessagesReceived.String() != "9007199254740993" {
		t.Fatalf("evidence number changed: %+v", device.BGPNeighbors)
	}
}
func TestDuplicateEvidenceKeys(t *testing.T) {
	body := `{"device":{"host":"192.0.2.1","name":"leaf"},"snapshot":{"dimensions":{"configuration":{"status":"partial","status":"complete","records":[{"review_status":"complete"}],"issues":[]}}}}`
	if _, e := report.ReadSources(context.Background(), evidenceBatch(t, body)); e == nil {
		t.Fatal("ambiguous duplicate status accepted")
	}
}
func TestACLSequenceType(t *testing.T) {
	for _, seq := range []any{nil, "ten", 1.5, 0, -1, int64(4294967296)} {
		r := vxlan.Record{"acls": vxlan.Record{"WEB": []any{vxlan.Record{"action": "permit", "sequence": seq, "expression": "ip any any"}}}}
		if e := vxlan.ValidateConfigurationRecord(r); e == nil {
			t.Errorf("invalid ACL sequence accepted: %#v", seq)
		}
	}
}

func TestNormalizationNumbers(t *testing.T) {
	n := json.Number("9007199254740993")
	out := normalize(vxlan.Record{"counter": n})
	encoded, e := json.Marshal(out)
	if e != nil {
		t.Fatal(e)
	}
	if string(encoded) != `{"counter":9007199254740993}` {
		t.Fatalf("normalization changed evidence: %s", encoded)
	}
}

func TestDuplicatePlanKeys(t *testing.T) {
	change := vxlan.Record{"kind": "svi_gateway_add", "vlan": 8, "vni": 10008, "vrf": "tenant", "address": "192.0.2.254/24"}
	cp, e := newChangePlan(change)
	if e != nil {
		t.Fatal(e)
	}
	doc := vxlan.Record{"schema_version": 2, "platform": "cisco_nxos", "changes": vxlan.Record{"test": vxlan.Record{"schema_version": 1, "platform": "cisco_nxos", "device": vxlan.Record{"host": "192.0.2.1", "name": "leaf"}, "expected_config_sha256": strings.Repeat("0", 64), "change": change, "commands": cp.Commands(), "rollback": cp.Rollback()}}}
	body := []byte(strings.Replace(string(jsonBytes(doc)), `"schema_version": 2`, `"schema_version": 3, "schema_version": 2`, 1))
	if !strings.Contains(string(body), `"schema_version": 3,`) {
		t.Fatal("probe did not create duplicate")
	}
	d := t.TempDir()
	path := filepath.Join(d, "plan.json")
	os.WriteFile(path, body, 0600)
	os.WriteFile(path+".sha256", []byte(fmt.Sprintf("%x", sha256.Sum256(body))), 0600)
	reader := &forbiddenReader{}
	a := App{Input: reader, Output: io.Discard, Error: io.Discard, Terminal: func() bool { return true }, CWD: d, Home: d, Directories: []string{}, Environment: map[string]string{}}
	if code := a.Run(context.Background(), []string{"apply", "--plan", path, "--item", "test"}); code != 2 || reader.read {
		t.Fatalf("ambiguous plan reached confirmation: code=%d read=%t", code, reader.read)
	}
}

func TestFractionalPlanIdentities(t *testing.T) {
	change := vxlan.Record{"kind": "svi_gateway_add", "vlan": 8, "vni": 10008, "vrf": "tenant", "address": "192.0.2.254/24"}
	cp, e := newChangePlan(change)
	if e != nil {
		t.Fatal(e)
	}
	doc := vxlan.Record{"schema_version": 2, "platform": "cisco_nxos", "changes": vxlan.Record{"test": vxlan.Record{"schema_version": 1, "platform": "cisco_nxos", "device": vxlan.Record{"host": "192.0.2.1", "name": "leaf"}, "expected_config_sha256": strings.Repeat("0", 64), "change": change, "commands": cp.Commands(), "rollback": cp.Rollback()}}}
	original := string(jsonBytes(doc))
	for _, pair := range [][2]string{{`"schema_version": 2`, `"schema_version": 2.00000000000000000001`}, {`"schema_version": 1`, `"schema_version": 0.99999999999999999999`}, {`"vlan": 8`, `"vlan": 8.00000000000000000001`}, {`"vni": 10008`, `"vni": 10007.99999999999999999999`}} {
		body := []byte(strings.Replace(original, pair[0], pair[1], 1))
		if string(body) == original {
			t.Fatal("probe not changed")
		}
		d := t.TempDir()
		path := filepath.Join(d, "plan.json")
		if e := os.WriteFile(path, body, 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path+".sha256", []byte(fmt.Sprintf("%x", sha256.Sum256(body))), 0600); e != nil {
			t.Fatal(e)
		}
		reader := &forbiddenReader{}
		a := App{Input: reader, Output: io.Discard, Error: io.Discard, Terminal: func() bool { return true }, CWD: d, Home: d, Directories: []string{}, Environment: map[string]string{}}
		if code := a.Run(context.Background(), []string{"apply", "--plan", path, "--item", "test"}); code != 2 || reader.read {
			t.Fatalf("fractional plan reached confirmation: %s code=%d read=%t", pair[1], code, reader.read)
		}
	}
}
