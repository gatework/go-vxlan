package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gatework/go-net-connector/connector"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/collect"
	"github.com/gatework/go-vxlan/internal/record"
)

func TestCLIParseAndHelp(t *testing.T) {
	var out, err bytes.Buffer
	a := App{Input: bytes.NewBufferString("hostname LEAF\n"), Output: &out, Error: &err, Environment: map[string]string{"VXLAN_CONFIG": "/not/exist"}}
	if a.Run(context.Background(), []string{"--help"}) != 0 {
		t.Fatal(err.String())
	}
	out.Reset()
	if a.Run(context.Background(), []string{"parse", "--complete", "--json"}) != 0 {
		t.Fatal(err.String())
	}
	var o vxlan.Observation
	if json.Unmarshal(out.Bytes(), &o) != nil || !o.Complete() {
		t.Fatal(out.String())
	}
	if a.Run(context.Background(), []string{"apply", "--plan", "missing", "--item", "x"}) != 2 {
		t.Fatal("nonterminal apply allowed")
	}
}

type fakeSession struct{}

func (fakeSession) Read(_ context.Context, command string) (collect.Capture, error) {
	body := ""
	if command == "show running-config" {
		body = "hostname LEAF\n"
	}
	return collect.Capture{Body: body, Complete: true}, nil
}
func TestCLICollectOffline(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "vxlan.yml"), []byte("devices:\n - host: 192.0.2.1\ndimensions: [configuration]\n"), 0600)
	var out, err bytes.Buffer
	a := App{Input: bytes.NewBuffer(nil), Output: &out, Error: &err, CWD: d, Home: d, Directories: []string{d}, Environment: map[string]string{"NC_DEVICE_USERNAME": "test"}, Open: func(c connector.ConnectionConfig) collect.OpenSession {
		return func(ctx context.Context, fn func(context.Context, collect.Session) error) error {
			return fn(ctx, fakeSession{})
		}
	}}
	if code := a.Run(context.Background(), []string{"collect", "--json", "--quiet"}); code != 0 {
		t.Fatalf("code %d %s", code, err.String())
	}
	var summary vxlan.Record
	if json.Unmarshal(out.Bytes(), &summary) != nil || summary["status"] != "complete" {
		t.Fatal(out.String())
	}
	res := record.Map(record.List(summary["devices"])[0])
	if _, ok := res["error"]; ok {
		t.Fatal("successful result contains error")
	}
	if _, ok := res["duration_ms"]; !ok {
		t.Fatal("missing duration")
	}
	issues := record.Map(record.Map(res["dimensions"])["configuration"])["issues"]
	if _, ok := issues.([]any); !ok {
		t.Fatal("issues must be an array")
	}
	paths, _ := filepath.Glob(filepath.Join(d, "vxlans", "*", "evidence", "*.json"))
	if len(paths) != 1 {
		t.Fatal(paths)
	}
	out.Reset()
	if a.Run(context.Background(), []string{"review", "--batch", filepath.Dir(filepath.Dir(paths[0]))}) != 0 {
		t.Fatal(err.String())
	}
}
