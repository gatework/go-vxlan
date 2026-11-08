package bootstrap

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	ncconfig "github.com/gatework/go-net-connector/config"
	"github.com/gatework/go-net-connector/fleet"
	"github.com/gatework/go-net-connector/inventory"
	"github.com/gatework/go-net-connector/netdisco"
	"github.com/gatework/go-net-connector/vendors"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

func inventorySections(m vxlan.Record) vxlan.Record {
	out := vxlan.Record{}
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
	if p := record.String(c.Values["netdisco_config"]); p != "" {
		m, e := ReadYAML(p)
		if e != nil {
			return e
		}
		if m["common"] != nil || record.Map(m["backup"])["netdisco"] != nil || record.Map(m["backup"])["inventory"] != nil {
			m = record.MergeLayers(record.Map(m["common"]), record.Map(m["backup"]))
		}
		for k := range m {
			if !record.Contains([]string{"netdisco", "inventory", "ssh", "backup", "topology", "tftp", "parallel"}, k) {
				return fmt.Errorf("外部清单包含未知字段")
			}
		}
		data = inventorySections(m)
		resolve(data, filepath.Dir(p), home, "", map[string]string{})
	}
	overrides, e := ncconfig.InventoryEnvironment(process, nil)
	if e != nil {
		return e
	}
	higher := record.MergeLayers(data, overrides)
	defaults, e := ncconfig.InventoryEnvironment(fileenv, higher)
	if e != nil {
		return e
	}
	c.Inventory = record.MergeLayers(inventorySections(ncconfig.Defaults("backup")), defaults, higher)
	resolve(c.Inventory, cwd, home, "", map[string]string{})
	if e = ncconfig.ValidateInventory(c.Inventory); e != nil {
		return e
	}

	if c.Values["netdisco_config"] != nil {
		c.Values["inventory_configuration"] = c.Inventory
	} else {
		for k, v := range c.Inventory {
			c.Values[k] = v
		}
	}
	return nil
}
func selectDevices(rows []any, values vxlan.Record) []any {
	out := []any{}
	for _, row := range rows {
		r := record.Map(row)
		ip, _ := netip.ParseAddr(record.String(r["host"]))
		matchIP := func(k string, empty bool) bool {
			vs := record.Texts(values[k])
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
			vs := record.Texts(values[k])
			if len(vs) == 0 {
				return empty
			}
			for _, v := range vs {
				if strings.Contains(strings.ToLower(record.String(r["name"])), strings.ToLower(v)) {
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

type InventoryResult struct {
	Devices []any
	Cache   netdisco.CacheResult
}

func FetchInventory(ctx context.Context, c Config) (InventoryResult, error) {
	var fetched InventoryResult
	if c.Inventory == nil {
		fetched.Devices = selectDevices(record.List(c.Values["devices"]), c.Values)
		return fetched, nil
	}
	nd := record.Map(c.Inventory["netdisco"])
	inv := record.Map(c.Inventory["inventory"])
	opts := inventory.SelectionOptions{IncludeHosts: record.Texts(inv["include_hosts"]), ExcludeHosts: record.Texts(inv["exclude_hosts"]), IncludeNames: record.Texts(inv["include_names"]), ExcludeNames: record.Texts(inv["exclude_names"]), IncludeVendors: record.Texts(inv["include_vendors"]), ExcludeVendors: record.Texts(inv["exclude_vendors"]), IncludeModels: record.Texts(inv["include_models"]), ExcludeModels: record.Texts(inv["exclude_models"]), NameMatch: record.String(inv["name_match"]), ModelMatch: record.String(inv["model_match"])}
	toStrings := func(v any) map[string]string {
		r := map[string]string{}
		for k, x := range record.Map(v) {
			r[k] = record.String(x)
		}
		return r
	}
	ruleOptions := fleet.RuleOptions{Selection: opts, VendorOverrides: toStrings(inv["vendor_overrides"]), HostOverrides: toStrings(inv["host_overrides"])}
	for _, value := range record.List(inv["device_rules"]) {
		m, ok := value.(map[string]any)
		if !ok {
			return fetched, fmt.Errorf("invalid device rule")
		}
		rule := fleet.Mapping{}
		for k, v := range m {
			if v == nil && (k == "os" || k == "model_prefix") {
				continue
			}
			text, ok := v.(string)
			if !ok {
				return fetched, fmt.Errorf("invalid device rule")
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
				return fetched, fmt.Errorf("unknown device rule field")
			}
		}
		ruleOptions.Mappings = append(ruleOptions.Mappings, rule)
	}
	rules, e := fleet.NewRules(ruleOptions, vendors.NewBuiltinRegistry())
	if e != nil {
		return fetched, e
	}
	get := func(k, def string) string {
		if v := record.String(nd[k]); v != "" {
			return v
		}
		return def
	}
	num := func(k string, def int) int {
		if v, ok := nd[k]; ok {
			return int(record.NumberFloat(v))
		}
		return def
	}
	mode := get("cache_mode", "prefer")
	limits := netdisco.Limits{PageSize: num("page_size", 500), MaxPages: num("max_pages", 10000), MaxDevices: num("max_devices", 100000), MaxResponseBytes: int64(num("max_response_bytes", 16<<20)), MaxInventoryBytes: int64(num("max_inventory_bytes", 128<<20)), Timeout: time.Duration(num("inventory_timeout", 300)) * time.Second}
	options := netdisco.FetchOptions{Mode: mode}
	if nd["cache_enabled"] != false {
		ttl := time.Duration(num("cache_ttl", 72*3600)) * time.Second
		options.Cache = &netdisco.CachePolicy{Directory: get("cache_directory", ""), Namespace: get("cache_namespace", ""), TTL: &ttl}
	}
	env := c.Environment
	switch get("source", "http") {
	case "http":
		fetched.Cache, e = netdisco.FetchHTTP(ctx, netdisco.HTTPOptions{URL: get("url", ""), Username: env["ND_USERNAME"], Password: env["ND_PASSWORD"], APIKey: env["ND_API_KEY"], RequireHTTPS: nd["allow_insecure_http"] != true, Limits: limits}, options)
	case "postgres":
		dsn := []string{}
		quote := func(value string) string {
			return "'" + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), "'", `\'`) + "'"
		}
		for _, pair := range [][2]string{{"host", "ND_DB_HOST"}, {"dbname", "ND_DB_NAME"}, {"user", "ND_DB_USER"}} {
			value := env[pair[1]]
			if value == "" {
				return fetched, fmt.Errorf("Netdisco 数据库凭据缺失")
			}
			dsn = append(dsn, pair[0]+"="+quote(value))
		}
		for _, key := range []string{"port", "sslmode", "sslrootcert", "connect_timeout"} {
			if value, ok := nd["db_"+key]; ok {
				dsn = append(dsn, key+"="+quote(fmt.Sprint(value)))
			}
		}
		if mode != "only" {
			dsn = append(dsn, "password="+quote(env["ND_DB_PASS"]))
		}
		fetched.Cache, e = netdisco.FetchPostgres(ctx, netdisco.PostgresOptions{Connection: strings.Join(dsn, " "), Query: get("query", ""), Parameters: record.List(nd["query_params"]), Limits: limits}, options)
	default:
		return fetched, fmt.Errorf("Netdisco source 无效")
	}
	if e != nil {
		return fetched, e
	}

	out := []any{}
	for _, r := range fetched.Cache.Rows {
		v := rules.Record(r)
		if v.Issue == "" && v.Vendor == "cisco_nxos" {
			name := v.Name
			if name == "" {
				name = v.Host
			}
			out = append(out, vxlan.Record{"host": v.Host, "name": name, "model": v.Model})
		}
	}
	out, e = normalizeDevices(out)
	if e != nil {
		return fetched, e
	}
	fetched.Devices = selectDevices(out, c.Values)
	return fetched, nil
}
