package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	ncconfig "github.com/gatework/go-net-connector/config"
	"github.com/gatework/go-net-connector/fleet"
	"github.com/gatework/go-net-connector/inventory"
	"github.com/gatework/go-net-connector/netdisco"
	"github.com/gatework/go-net-connector/vendors"
)

func inventoryEnvironment(env map[string]string) map[string]string {
	m := map[string]string{}
	for k, v := range env {
		if strings.HasPrefix(k, "ND_") || strings.HasPrefix(k, "NC_INCLUDE_") || strings.HasPrefix(k, "NC_EXCLUDE_") || contains([]string{"NC_NAME_MATCH", "NC_MODEL_MATCH", "NC_VENDOR_OVERRIDES", "NC_HOST_OVERRIDES", "NC_DEVICE_RULES"}, k) {
			m[k] = v
		}
	}
	return m
}
func inventorySections(m M) M {
	out := M{}
	for _, k := range []string{"netdisco", "inventory"} {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}
func prepareInventory(c *Config, fileenv, process map[string]string, cwd, home string) error {
	if c.Values["netdisco"] == nil && c.Values["inventory"] == nil && c.Values["netdisco_config"] == nil {
		return nil
	}
	data := inventorySections(c.Values)
	if p := str(c.Values["netdisco_config"]); p != "" {
		m, e := readYAML(p)
		if e != nil {
			return e
		}
		if m["common"] != nil || object(m["backup"])["netdisco"] != nil || object(m["backup"])["inventory"] != nil {
			m = merge(object(m["common"]), object(m["backup"]))
		}
		for k := range m {
			if !contains([]string{"netdisco", "inventory", "ssh", "backup", "topology", "tftp", "parallel"}, k) {
				return fmt.Errorf("外部清单包含未知字段")
			}
		}
		data = inventorySections(m)
		resolve(data, filepath.Dir(p), home, "", map[string]string{})
	}
	overrides, e := ncconfig.FromEnvironment(inventoryEnvironment(process))
	if e != nil {
		return e
	}
	// Decode only effective defaults: the shared loader masks overridden values
	// before parsing environment types, including JSON rules and booleans.
	snap, e := ncconfig.Load(ncconfig.Options{
		Name: "backup", CWD: cwd, Home: home, Directories: []string{},
		Environment: inventoryEnvironment(fileenv),
		Defaults:    inventorySections(ncconfig.Defaults("backup")),
		Overrides:   merge(data, inventorySections(overrides)), AllowMissing: true,
	})
	if e != nil {
		return e
	}
	c.Inventory = inventorySections(snap.Public())
	if c.Values["netdisco_config"] != nil {
		c.Values["inventory_configuration"] = c.Inventory
	} else {
		for k, v := range c.Inventory {
			c.Values[k] = v
		}
	}
	return nil
}
func selectDevices(rows []any, values M) []any {
	out := []any{}
	for _, row := range rows {
		r := object(row)
		ip, _ := netip.ParseAddr(str(r["host"]))
		matchIP := func(k string, empty bool) bool {
			vs := texts(values[k])
			if len(vs) == 0 {
				return empty
			}
			for _, v := range vs {
				p, e := addressPrefix(v)
				if e == nil && p.Contains(ip) {
					return true
				}
			}
			return false
		}
		matchName := func(k string, empty bool) bool {
			vs := texts(values[k])
			if len(vs) == 0 {
				return empty
			}
			for _, v := range vs {
				if strings.Contains(strings.ToLower(str(r["name"])), strings.ToLower(v)) {
					return true
				}
			}
			return false
		}
		if matchIP("hosts", true) && !matchIP("exclude_hosts", false) && matchName("names", true) && !matchName("exclude_names", false) {
			out = append(out, r)
		}
	}
	return out
}
func fetchInventory(ctx context.Context, c Config) ([]any, error) {
	if c.Inventory == nil {
		return selectDevices(list(c.Values["devices"]), c.Values), nil
	}
	nd := object(c.Inventory["netdisco"])
	inv := object(c.Inventory["inventory"])
	opts := inventory.SelectionOptions{IncludeHosts: texts(inv["include_hosts"]), ExcludeHosts: texts(inv["exclude_hosts"]), IncludeNames: texts(inv["include_names"]), ExcludeNames: texts(inv["exclude_names"]), IncludeVendors: texts(inv["include_vendors"]), ExcludeVendors: texts(inv["exclude_vendors"]), IncludeModels: texts(inv["include_models"]), ExcludeModels: texts(inv["exclude_models"]), NameMatch: str(inv["name_match"]), ModelMatch: str(inv["model_match"])}
	toStrings := func(v any) map[string]string {
		r := map[string]string{}
		for k, x := range object(v) {
			r[k] = str(x)
		}
		return r
	}
	ruleOptions := fleet.RuleOptions{Selection: opts, VendorOverrides: toStrings(inv["vendor_overrides"]), HostOverrides: toStrings(inv["host_overrides"])}
	for _, value := range list(inv["device_rules"]) {
		m, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid device rule")
		}
		rule := fleet.Mapping{}
		for k, v := range m {
			if v == nil && (k == "os" || k == "model_prefix") {
				continue
			}
			text, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("invalid device rule")
			}
			switch k {
			case "vendor":
				rule.Vendor = text
			case "connector":
				rule.Connector = text
			case "os":
				rule.OS = &text
			case "model_prefix":
				rule.ModelPrefix = &text
			default:
				return nil, fmt.Errorf("unknown device rule field")
			}
		}
		ruleOptions.Mappings = append(ruleOptions.Mappings, rule)
	}
	rules, e := fleet.NewRules(ruleOptions, vendors.NewBuiltinRegistry())
	if e != nil {
		return nil, e
	}
	get := func(k, def string) string {
		if v := str(nd[k]); v != "" {
			return v
		}
		return def
	}
	num := func(k string, def int) int {
		if v, ok := nd[k]; ok {
			return int(number(v))
		}
		return def
	}
	mode := get("cache_mode", "prefer")
	limits := netdisco.Limits{PageSize: num("page_size", 500), MaxPages: num("max_pages", 10000), MaxDevices: num("max_devices", 100000), MaxResponseBytes: int64(num("max_response_bytes", 16<<20)), MaxInventoryBytes: int64(num("max_inventory_bytes", 128<<20)), Timeout: time.Duration(num("inventory_timeout", 300)) * time.Second}
	var source netdisco.Source
	var identity []byte
	env := c.Environment
	if get("source", "http") == "http" {
		u, err := url.Parse(get("url", ""))
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("Netdisco URL 无效")
		}
		if u.Scheme != "https" && nd["allow_insecure_http"] != true {
			return nil, fmt.Errorf("Netdisco HTTP 须显式允许")
		}
		auth := M{}
		if env["ND_API_KEY"] != "" {
			auth["api_key"] = env["ND_API_KEY"]
		} else {
			auth["username"] = env["ND_USERNAME"]
		}
		identity, _ = json.Marshal([]any{"http", u.String(), auth})
		if mode != "only" {
			source, e = netdisco.NewHTTP(netdisco.HTTPOptions{URL: u.String(), Username: env["ND_USERNAME"], Password: env["ND_PASSWORD"], APIKey: env["ND_API_KEY"], RequireHTTPS: nd["allow_insecure_http"] != true, Limits: limits})
		}
	} else if get("source", "") == "postgres" {
		dsn := []string{}
		public := M{}
		quote := func(s string) string {
			return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", `\'`) + "'"
		}
		for k, ek := range map[string]string{"host": "ND_DB_HOST", "dbname": "ND_DB_NAME", "user": "ND_DB_USER"} {
			v := env[ek]
			if v == "" {
				return nil, fmt.Errorf("Netdisco 数据库凭据缺失")
			}
			dsn = append(dsn, k+"="+quote(v))
			public[k] = v
		}
		for _, k := range []string{"port", "sslmode", "sslrootcert", "connect_timeout"} {
			if v, ok := nd["db_"+k]; ok {
				dsn = append(dsn, k+"="+quote(fmt.Sprint(v)))
				public[k] = v
			}
		}
		identity, _ = json.Marshal([]any{"postgres", public, M{"query": nd["query"], "query_params": nd["query_params"]}})
		if mode != "only" {
			dsn = append(dsn, "password="+quote(env["ND_DB_PASS"]))
			source, e = netdisco.NewPostgres(netdisco.PostgresOptions{Connection: strings.Join(dsn, " "), Query: get("query", ""), Parameters: list(nd["query_params"]), Limits: limits})
		}
	} else {
		return nil, fmt.Errorf("Netdisco source 无效")
	}
	if e != nil {
		return nil, e
	}
	var rows []inventory.Device
	if nd["cache_enabled"] == false {
		if mode == "only" {
			return nil, fmt.Errorf("cache-only 与禁用缓存冲突")
		}
		rows, e = source.Devices(ctx)
	} else {
		ttl := time.Duration(num("cache_ttl", 72*3600)) * time.Second
		cache, err := netdisco.NewCache(source, netdisco.CacheOptions{Directory: get("cache_directory", ""), Identity: netdisco.Identity(identity), TTL: &ttl, Limits: limits})
		if err != nil {
			return nil, err
		}
		result, err := cache.Fetch(ctx, mode)
		rows, e = result.Rows, err
	}
	if e != nil {
		return nil, e
	}

	out := []any{}
	for _, r := range rows {
		v := rules.Record(r)
		if v.Issue == "" && v.Vendor == "cisco_nxos" {
			name := v.Name
			if name == "" {
				name = v.Host
			}
			out = append(out, M{"host": v.Host, "name": name, "model": v.Model})
		}
	}
	out, e = normalizeDevices(out)
	if e != nil {
		return nil, e
	}
	return selectDevices(out, c.Values), nil
}
