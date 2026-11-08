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
func prepareInventory(ctx context.Context, c *Config, fileenv, process map[string]string, cwd, home string) error {
	if c.Values["netdisco"] == nil && c.Values["inventory"] == nil && c.Values["netdisco_config"] == nil {
		return nil
	}
	data := inventorySections(c.Values)
	if p := record.String(c.Values["netdisco_config"]); p != "" {
		m, e := ReadYAML(ctx, p)
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

type deviceFilter struct {
	hosts, excludeHosts []netip.Prefix
	names, excludeNames []string
}

func newDeviceFilter(values vxlan.Record) deviceFilter {
	prefixes := func(key string) []netip.Prefix {
		var out []netip.Prefix
		for _, value := range record.Texts(values[key]) {
			prefix, _ := addressPrefix(value) // validateConfig has checked each filter.
			out = append(out, prefix)
		}
		return out
	}
	names := func(key string) []string {
		out := record.Texts(values[key])
		for i := range out {
			out[i] = strings.ToLower(out[i])
		}
		return out
	}
	return deviceFilter{prefixes("hosts"), prefixes("exclude_hosts"), names("names"), names("exclude_names")}
}

func (f deviceFilter) selectDevices(rows []any) []any {
	out := []any{}
	for _, row := range rows {
		r := record.Map(row)
		ip, _ := netip.ParseAddr(record.String(r["host"]))
		matchIP := func(prefixes []netip.Prefix, empty bool) bool {
			if len(prefixes) == 0 {
				return empty
			}
			for _, prefix := range prefixes {
				if prefix.Contains(ip) {
					return true
				}
			}
			return false
		}
		name := strings.ToLower(record.String(r["name"]))
		matchName := func(patterns []string, empty bool) bool {
			if len(patterns) == 0 {
				return empty
			}
			for _, pattern := range patterns {
				if strings.Contains(name, pattern) {
					return true
				}
			}
			return false
		}
		if matchIP(f.hosts, true) && !matchIP(f.excludeHosts, false) && matchName(f.names, true) && !matchName(f.excludeNames, false) {
			out = append(out, record.Copy(r))
		}
	}
	return out
}

type inventorySettings struct {
	devices []any
	filter  deviceFilter
	rules   *fleet.Rules
	fetch   func(context.Context) (netdisco.CacheResult, error)
}

type InventoryResult struct {
	Devices []any
	Cache   netdisco.CacheResult
}

func inventorySettingsFor(c Config) (inventorySettings, error) {
	settings := inventorySettings{
		devices: record.List(record.Copy(c.Values["devices"])),
		filter:  newDeviceFilter(c.Values),
	}
	if c.Inventory == nil {
		return settings, nil
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
			return settings, fmt.Errorf("invalid device rule")
		}
		rule := fleet.Mapping{}
		for k, v := range m {
			if v == nil && (k == "os" || k == "model_prefix") {
				continue
			}
			text, ok := v.(string)
			if !ok {
				return settings, fmt.Errorf("invalid device rule")
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
				return settings, fmt.Errorf("unknown device rule field")
			}
		}
		ruleOptions.Mappings = append(ruleOptions.Mappings, rule)
	}
	rules, e := fleet.NewRules(ruleOptions, vendors.NewBuiltinRegistry())
	if e != nil {
		return settings, e
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
	settings.rules = rules
	env := c.Environment
	switch get("source", "http") {
	case "http":
		source := netdisco.HTTPOptions{URL: get("url", ""), Username: env["ND_USERNAME"], Password: env["ND_PASSWORD"], APIKey: env["ND_API_KEY"], RequireHTTPS: nd["allow_insecure_http"] != true, Limits: limits}
		settings.fetch = func(ctx context.Context) (netdisco.CacheResult, error) {
			return netdisco.FetchHTTP(ctx, source, options)
		}
	case "postgres":
		dsn := []string{}
		quote := func(value string) string {
			return "'" + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), "'", `\'`) + "'"
		}
		for _, pair := range [][2]string{{"host", "ND_DB_HOST"}, {"dbname", "ND_DB_NAME"}, {"user", "ND_DB_USER"}} {
			value := env[pair[1]]
			if value == "" {
				return settings, fmt.Errorf("Netdisco 数据库凭据缺失")
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
		source := netdisco.PostgresOptions{Connection: strings.Join(dsn, " "), Query: get("query", ""), Parameters: record.List(record.Copy(nd["query_params"])), Limits: limits}
		settings.fetch = func(ctx context.Context) (netdisco.CacheResult, error) {
			return netdisco.FetchPostgres(ctx, source, options)
		}
	default:
		return settings, fmt.Errorf("Netdisco source 无效")
	}
	return settings, nil
}

func FetchInventory(ctx context.Context, c Config) (InventoryResult, error) {
	var fetched InventoryResult
	if err := ctx.Err(); err != nil {
		return fetched, err
	}
	if c.runtime.inventoryError != nil {
		return fetched, c.runtime.inventoryError
	}
	settings := c.runtime.inventory
	if settings.fetch == nil {
		fetched.Devices = settings.filter.selectDevices(settings.devices)
		return fetched, nil
	}
	var e error
	fetched.Cache, e = settings.fetch(ctx)
	if e != nil {
		return fetched, e
	}

	out := []any{}
	for _, r := range fetched.Cache.Rows {
		v := settings.rules.Record(r)
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
	fetched.Devices = settings.filter.selectDevices(out)
	return fetched, nil
}
