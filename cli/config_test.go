package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestConfigLayers(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, ".env"), []byte("VXLAN_PARALLEL=2\nNC_DEVICE_PASSWORD='private#value'\n"), 0600)
	os.WriteFile(filepath.Join(d, "vxlan.yml"), []byte("parallel: 3\ndirectory: reports\ndevices:\n  - host: 192.0.2.1\n"), 0600)
	cfg, e := LoadConfig(ConfigOptions{CWD: d, Home: d, Directories: []string{d}, Environment: map[string]string{"VXLAN_PARALLEL": "5"}, Overrides: map[string]any{"parallel": 7}})
	if e != nil {
		t.Fatal(e)
	}
	if cfg.Values["parallel"] != 7 || cfg.Values["directory"] != filepath.Join(d, "reports") || cfg.Environment["NC_DEVICE_PASSWORD"] != "private#value" {
		t.Fatal(cfg)
	}
	if !reflect.DeepEqual(cfg.Values["dimensions"], []string{"configuration", "cdp_neighbors", "nve_peers", "nve_vnis", "bgp_neighbors", "ospf_neighbors", "vpc", "interfaces", "port_channels", "mac_addresses", "l2route_macs", "l2route_mac_ips"}) {
		t.Fatal(cfg.Values["dimensions"])
	}
}
func TestConfigStrict(t *testing.T) {
	for _, body := range []string{"parallel: 2\nparallel: 3\n", "devices: &x []\ndimensions: *x\n", "devices: []\n---\nparallel: 2\n", "password: secret\n", "ssh:\n  password: secret\n", "devices:\n - host: 192.0.2.1\n - host: 192.0.2.1\n"} {
		t.Run(body, func(t *testing.T) {
			d := t.TempDir()
			os.WriteFile(filepath.Join(d, "vxlan.yml"), []byte(body), 0600)
			_, e := LoadConfig(ConfigOptions{CWD: d, Home: d, Directories: []string{d}})
			if e == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestInventoryHigherLayersMaskMalformedDefaults(t *testing.T) {
	for _, tc := range []struct {
		name, env, body string
		process         map[string]string
		wantError       bool
	}{
		{name: "yaml integer", env: "ND_PAGE_SIZE=obsolete\n", body: "netdisco:\n  page_size: 23\n"},
		{name: "process integer", env: "ND_PAGE_SIZE=obsolete\n", body: "netdisco: {}\n", process: map[string]string{"ND_PAGE_SIZE": "23"}},
		{name: "yaml boolean", env: "ND_CACHE_ENABLED=obsolete\n", body: "netdisco:\n  cache_enabled: false\n"},
		{name: "yaml rules", env: "NC_DEVICE_RULES=not-json\n", body: "inventory:\n  device_rules: []\n"},
		{name: "effective bad default", env: "ND_PAGE_SIZE=obsolete\n", body: "netdisco: {}\n", wantError: true},
		{name: "effective bad process", body: "netdisco:\n  page_size: 23\n", process: map[string]string{"ND_PAGE_SIZE": "obsolete"}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			if e := os.WriteFile(filepath.Join(d, ".env"), []byte(tc.env), 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(d, "vxlan.yml"), []byte(tc.body), 0600); e != nil {
				t.Fatal(e)
			}
			process := tc.process
			if process == nil {
				process = map[string]string{}
			}
			c, e := LoadConfig(ConfigOptions{CWD: d, Home: d, Directories: []string{d}, Environment: process})
			if tc.wantError {
				if e == nil {
					t.Fatal("effective invalid value accepted")
				}
				return
			}
			if e != nil {
				t.Fatalf("overridden lower layer rejected: %v", e)
			}
			if tc.name == "yaml integer" || tc.name == "process integer" {
				if number(object(c.Inventory["netdisco"])["page_size"]) != 23 {
					t.Fatal(c.Inventory)
				}
			}
			if tc.name == "yaml boolean" && object(c.Inventory["netdisco"])["cache_enabled"] != false {
				t.Fatal(c.Inventory)
			}
		})
	}
}

func TestInventoryDefaultsAndSourceRelativePaths(t *testing.T) {
	d := t.TempDir()
	configDir := filepath.Join(d, "settings")
	if e := os.Mkdir(configDir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(configDir, ".env"), []byte("ND_PAGE_SIZE=19\nND_CACHE_DIRECTORY=cache\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(configDir, "vxlan.yml"), []byte("netdisco: {}\n"), 0600); e != nil {
		t.Fatal(e)
	}
	c, e := LoadConfig(ConfigOptions{CWD: d, Home: d, Directories: []string{configDir}, Environment: map[string]string{}})
	if e != nil {
		t.Fatal(e)
	}
	nd := object(c.Inventory["netdisco"])
	if number(nd["page_size"]) != 19 || nd["cache_directory"] != filepath.Join(configDir, "cache") {
		t.Fatal("lost defaults or source base", nd)
	}
}

func TestExternalInventoryKeepsFlatBackupSection(t *testing.T) {
	for _, body := range []string{
		"backup:\n  directory: backups\nnetdisco:\n  page_size: 23\ninventory:\n  include_names: [leaf]\n",
		"common:\n  netdisco:\n    page_size: 23\nbackup:\n  inventory:\n    include_names: [leaf]\n",
	} {
		d := t.TempDir()
		if e := os.WriteFile(filepath.Join(d, "backup.yml"), []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(d, "vxlan.yml"), []byte("netdisco_config: backup.yml\n"), 0600); e != nil {
			t.Fatal(e)
		}
		c, e := LoadConfig(ConfigOptions{CWD: d, Home: d, Directories: []string{d}, Environment: map[string]string{}})
		if e != nil {
			t.Fatal(e)
		}
		if number(object(c.Inventory["netdisco"])["page_size"]) != 23 || !reflect.DeepEqual(texts(object(c.Inventory["inventory"])["include_names"]), []string{"leaf"}) {
			t.Fatal(c.Inventory)
		}
	}
}
