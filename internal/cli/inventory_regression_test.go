package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/gatework/go-net-connector/netdisco"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/bootstrap"
)

func TestInventoryNamespaceAndCacheMigration(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Query().Get("offset") != "0" {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte(`[{"ip":"192.0.2.1","name":"leaf","vendor":"Cisco","os":"nxos","model":"N9K"}]`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	nd := vxlan.Record{"source": "http", "url": srv.URL, "allow_insecure_http": true, "cache_enabled": true, "cache_directory": filepath.Join(dir, "cache"), "cache_namespace": "first", "cache_mode": "refresh"}
	c := bootstrap.Config{Inventory: vxlan.Record{"netdisco": nd}, Environment: map[string]string{"ND_API_KEY": "key-one"}, Values: vxlan.Record{}}
	first, err := bootstrap.FetchInventory(t.Context(), c)
	if err != nil || len(first.Devices) != 1 || first.Cache.Status == "" || first.Cache.FetchedAt.IsZero() {
		t.Fatal("source evidence lost", first, err)
	}
	count := requests.Load()
	nd["cache_mode"] = "only"
	c.Environment["ND_API_KEY"] = "rotated-key"
	second, err := bootstrap.FetchInventory(t.Context(), c)
	if err != nil || len(second.Devices) != 1 || requests.Load() != count {
		t.Fatal("namespace failed across key rotation", second, err)
	}
	nd["cache_namespace"] = "second"
	if _, err := bootstrap.FetchInventory(t.Context(), c); !errors.Is(err, netdisco.ErrCacheRefreshRequired) {
		t.Fatal("unverified identity was reused", err)
	}
	if requests.Load() != count {
		t.Fatal("only mode fetched the network")
	}
	nd["cache_mode"] = "prefer"
	third, err := bootstrap.FetchInventory(t.Context(), c)
	if err != nil || len(third.Devices) != 1 || requests.Load() == count {
		t.Fatal("prefer did not refresh new identity", third, err)
	}
}

func TestDeliveryReviewerDeviceRules(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("offset") != "0" {
			w.Write([]byte(`[]`))
			return
		}
		w.Write([]byte(`[{"ip":"192.0.2.1","name":"leaf","vendor":"OEM","model":"N9K"}]`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	config := vxlan.Record{"netdisco": vxlan.Record{"url": srv.URL, "allow_insecure_http": true, "cache_enabled": false}, "inventory": vxlan.Record{"device_rules": []any{vxlan.Record{"vendor": "OEM", "connector": "cisco_nxos"}}}}
	b, _ := json.Marshal(config)
	os.WriteFile(filepath.Join(dir, "vxlan.yml"), b, 0600)
	c, e := bootstrap.Load(bootstrap.ConfigOptions{CWD: dir, Home: dir, Directories: []string{dir}, Environment: map[string]string{"ND_API_KEY": "test"}})
	if e != nil {
		t.Fatal(e)
	}
	result, e := bootstrap.FetchInventory(context.Background(), c)
	rows := result.Devices
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 1 {
		t.Fatalf("device_rules silently ignored: got %v; effective inventory %v", rows, c.Inventory)
	}
}
func TestDeliveryReviewerInventoryCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`[]`)) }))
	defer srv.Close()
	dir := t.TempDir()
	config := vxlan.Record{"netdisco": vxlan.Record{"url": srv.URL, "allow_insecure_http": true, "cache_enabled": false}}
	b, _ := json.Marshal(config)
	os.WriteFile(filepath.Join(dir, "vxlan.yml"), b, 0600)
	var out, err bytes.Buffer
	app := App{CWD: dir, Home: dir, Directories: []string{dir}, Environment: map[string]string{"ND_API_KEY": "test"}, Output: &out, Error: &err, Input: bytes.NewBuffer(nil)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := app.Run(ctx, []string{"collect", "--plan"}); code != 130 {
		t.Fatalf("cancel exit=%d, want 130, stderr=%s", code, err.String())
	}
}
