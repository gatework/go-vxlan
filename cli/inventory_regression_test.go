package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

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
	config := M{"netdisco": M{"url": srv.URL, "allow_insecure_http": true, "cache_enabled": false}, "inventory": M{"device_rules": []any{M{"vendor": "OEM", "connector": "cisco_nxos"}}}}
	b, _ := json.Marshal(config)
	os.WriteFile(filepath.Join(dir, "vxlan.yml"), b, 0600)
	c, e := LoadConfig(ConfigOptions{CWD: dir, Home: dir, Directories: []string{dir}, Environment: map[string]string{"ND_API_KEY": "test"}})
	if e != nil {
		t.Fatal(e)
	}
	rows, e := fetchInventory(context.Background(), c)
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
	config := M{"netdisco": M{"url": srv.URL, "allow_insecure_http": true, "cache_enabled": false}}
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
