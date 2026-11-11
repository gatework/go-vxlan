package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	ncconfig "github.com/gatework/go-net-connector/config"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

func TestConfigurationReadBoundary(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	options := ConfigOptions{CWD: dir, Home: dir, Directories: []string{dir}, Environment: map[string]string{}, AllowMissing: true}
	if _, err := Load(ctx, options); !errors.Is(err, context.Canceled) {
		t.Fatalf("missing-file policy swallowed cancellation: %v", err)
	}
	path := filepath.Join(dir, "vxlan.yml")
	if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if document, err := ReadYAML(t.Context(), link); err != nil || document == nil || len(document) != 0 {
		t.Fatal("readable symlink or explicit empty mapping rejected", err)
	}
	if err := os.Truncate(path, ncconfig.MaxBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(t.Context(), options); !errors.Is(err, ncconfig.ErrInvalid) {
		t.Fatal("configuration byte budget bypassed", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, ".env"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(t.Context(), options); !errors.Is(err, ncconfig.ErrInvalid) {
		t.Fatal("environment special file accepted", err)
	}
}

func TestRuntimeConfigurationOwnsDiagnosticsAndInputs(t *testing.T) {
	dir := t.TempDir()
	environment := map[string]string{"NC_DEVICE_USERNAME": "original", "NC_DEVICE_PASSWORD": "private"}
	values := vxlan.Record{
		"devices": []any{vxlan.Record{"host": "192.0.2.1", "name": "LEAF"}},
		"hosts":   []string{"192.0.2.0/24"}, "names": []string{"LEAF"},
		"dimensions": []string{"configuration"},
	}
	policyPath := filepath.Join(dir, "fabric.yml")
	if err := os.WriteFile(policyPath, []byte("fabrics:\n  A:\n    leaves: [192.0.2.1, 192.0.2.2]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	values["fabric_policy"] = policyPath
	cfg, err := Load(t.Context(), ConfigOptions{CWD: dir, Home: dir, Directories: []string{dir}, Environment: environment, Overrides: values})
	if err != nil {
		t.Fatal(err)
	}
	environment["NC_DEVICE_USERNAME"] = "changed input"
	values["names"].([]string)[0] = "different"
	cfg.Environment["NC_DEVICE_USERNAME"] = "changed display"
	record.Map(cfg.Values["ssh"])["port"] = 1234
	record.Map(record.List(cfg.Values["devices"])[0])["host"] = "198.51.100.1"
	cfg.Values["hosts"] = []string{"198.51.100.0/24"}
	cfg.Values["names"] = []string{"different"}
	cfg.Values["dimensions"].([]string)[0] = "interfaces"
	cfg.Policy["fabrics"] = vxlan.Record{}
	connection, err := Credentials(cfg)
	if err != nil || connection.Username != "original" || connection.Port != 22 {
		t.Fatal("diagnostic mutation changed validated connection settings", err)
	}
	if cfg.runtime.Dimensions[0] != "configuration" {
		t.Fatal("dimension input aliases runtime snapshot")
	}
	if len(record.Map(cfg.runtime.policy["fabrics"])) != 1 {
		t.Fatal("public policy aliases runtime snapshot")
	}
	for range 2 {
		inventory, err := FetchInventory(t.Context(), cfg)
		if err != nil || len(inventory.Devices) != 1 || record.Map(inventory.Devices[0])["host"] != "192.0.2.1" {
			t.Fatal("diagnostic or returned device mutation changed inventory", err)
		}
		record.Map(inventory.Devices[0])["host"] = "203.0.113.1"
	}
}

func TestRuntimeInventoryOwnsSourceAndCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Apikey original-key" {
			t.Error("runtime inventory credential changed")
		}
		if r.URL.Query().Get("offset") != "0" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = w.Write([]byte("[{\"ip\":\"192.0.2.1\",\"name\":\"leaf\",\"vendor\":\"Cisco\",\"os\":\"nxos\",\"model\":\"N9K\"}]"))
	}))
	defer server.Close()
	dir := t.TempDir()
	cfg, err := Load(t.Context(), ConfigOptions{
		CWD: dir, Home: dir, Directories: []string{dir}, Environment: map[string]string{"ND_API_KEY": "original-key"},
		Overrides: vxlan.Record{"netdisco": vxlan.Record{"url": server.URL, "allow_insecure_http": true, "cache_enabled": false}},
	})
	if err != nil {
		t.Fatal(err)
	}
	record.Map(cfg.Inventory["netdisco"])["url"] = "invalid source"
	cfg.Values["names"] = []string{"different"}
	cfg.Environment["ND_API_KEY"] = "changed-key"
	result, err := FetchInventory(t.Context(), cfg)
	if err != nil || len(result.Devices) != 1 {
		t.Fatal("public diagnostics changed runtime inventory", err)
	}
}
