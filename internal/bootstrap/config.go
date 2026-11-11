package bootstrap

import (
	"context"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-vxlan/fabric"

	ncconfig "github.com/gatework/go-net-connector/config"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

// ConfigOptions supplies configuration search locations, environment and overrides.
type ConfigOptions struct {
	CWD, Home, Program, ConfigFile, EnvFile string
	Directories                             []string
	Environment                             map[string]string
	Overrides                               vxlan.Record
	AllowMissing                            bool
	EnvironmentOnly                         bool
}

// Config owns resolved configuration, provenance and runtime bindings.
//
//nolint:recvcheck // Value formatting must redact both values and pointers; runtime binding methods mutate the configuration.
type Config struct {
	runtime             Settings
	Values              vxlan.Record
	Environment         map[string]string
	Sources             vxlan.Record
	ConfigPath, EnvPath string
	Missing             bool
	Policy              vxlan.Record
	Inventory           vxlan.Record
}

func (c Config) String() string { return "bootstrap.Config" }

// GoString returns a redacted diagnostic representation.
func (c Config) GoString() string { return c.String() }

// Absolute resolves an operator path against its source directory and home.
func Absolute(p, base, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(base, p)
}

// ReadRulesPolicy reads an assessment rule policy: rule switches,
// severity overrides and thresholds, validated later against the catalog.
func ReadRulesPolicy(ctx context.Context, path string) (assess.Policy, error) {
	b, _, e := ncconfig.ReadFile(ctx, path, false)
	if e != nil {
		return assess.Policy{}, e
	}
	return assess.DecodePolicy(b)
}

// ReadBaseline reads a frozen fabric baseline.
func ReadBaseline(ctx context.Context, path string) (*fabric.Baseline, error) {
	b, _, e := ncconfig.ReadFile(ctx, path, false)
	if e != nil {
		return nil, e
	}
	baseline, e := fabric.DecodeBaseline(b)
	if e != nil {
		return nil, e
	}
	return &baseline, nil
}

// ReadYAML reads a configuration mapping with cancellation checks.
func ReadYAML(ctx context.Context, path string) (vxlan.Record, error) {
	b, _, e := ncconfig.ReadFile(ctx, path, false)
	if e != nil {
		return nil, e
	}
	document, err := ncconfig.ParseYAMLMapping(b)
	if canceled := ctx.Err(); canceled != nil {
		return nil, canceled
	}
	return document, err
}

var configPaths = map[string]bool{"directory": true, "fabric_policy": true, "netdisco_config": true, "ssh.known_hosts": true, "netdisco.cache_directory": true, "netdisco.db_sslrootcert": true}

func resolve(m vxlan.Record, base, home, prefix string, fields map[string]string) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if child, ok := v.(map[string]any); ok {
			resolve(child, base, home, key, fields)
		} else {
			fields[key] = base
			if p, ok := v.(string); ok && configPaths[key] && !(key == "netdisco.db_sslrootcert" && p == "system") {
				m[k] = Absolute(p, base, home)
			}
		}
	}
}
func envValues(env map[string]string) vxlan.Record {
	m := vxlan.Record{}
	for e, k := range map[string]string{"VXLAN_FABRIC": "fabric", "VXLAN_DIRECTORY": "directory"} {
		if v, ok := env[e]; ok {
			m[k] = v
		}
	}
	p, ok := env["VXLAN_PARALLEL"]
	if !ok {
		p, ok = env["NC_PARALLEL"]
	}
	if ok {
		n, e := strconv.Atoi(p)
		if e == nil {
			m["parallel"] = n
		} else {
			m["parallel"] = p
		}
	}
	ssh := vxlan.Record{}
	for e, k := range map[string]string{"NC_HOST_KEY_POLICY": "host_key_policy", "NC_KNOWN_HOSTS": "known_hosts"} {
		if v, ok := env[e]; ok {
			ssh[k] = v
		}
	}
	if len(ssh) > 0 {
		m["ssh"] = ssh
	}
	return m
}

// Load resolves configuration and credentials through the documented layer order.
func Load(ctx context.Context, o ConfigOptions) (Config, error) {
	l := &configLoader{o: o, c: Config{Environment: map[string]string{}, Sources: vxlan.Record{}}}
	if err := ctx.Err(); err != nil {
		return l.c, err
	}
	l.paths()
	for _, phase := range []func(context.Context) error{l.environment, l.configuration, l.finish} {
		if err := phase(ctx); err != nil {
			return l.c, err
		}
	}
	return l.c, nil
}

type configLoader struct {
	o                     ConfigOptions
	c                     Config
	process, fileenv      map[string]string
	user                  string
	dirs, envFiles, files []string
	data, specific        vxlan.Record
	fields                map[string]string
}

func (l *configLoader) paths() {
	o := l.o
	if o.CWD == "" {
		o.CWD, _ = os.Getwd()
	}
	if o.Home == "" {
		o.Home, _ = os.UserHomeDir()
	}
	if o.Program == "" {
		p, _ := os.Executable()
		o.Program = filepath.Dir(p)
	}
	process := map[string]string{}
	if o.Environment == nil {
		for _, s := range os.Environ() {
			p := strings.SplitN(s, "=", 2)
			process[p[0]] = p[1]
		}
	} else {
		maps.Copy(process, o.Environment)
	}
	user := filepath.Join(o.Home, ".config", "net-connector")
	if x := process["XDG_CONFIG_HOME"]; x != "" {
		user = filepath.Join(x, "net-connector")
	}
	dirs := o.Directories
	if dirs == nil {
		dirs = []string{"/etc/net-connector", "/usr/local/etc/net-connector", user, o.Program, o.CWD}
	}
	unique := []string{}
	seen := map[string]bool{}
	for _, d := range dirs {
		d = Absolute(d, o.CWD, o.Home)
		if !seen[d] {
			seen[d] = true
			unique = append(unique, d)
		}
	}
	dirs = unique
	l.o, l.process, l.user, l.dirs = o, process, user, dirs
}
func (l *configLoader) environment(ctx context.Context) error {
	o, c, dirs, process := l.o, &l.c, l.dirs, l.process
	l.fileenv, l.envFiles = map[string]string{}, []string{}
	for _, d := range dirs {
		if e := l.loadEnvironmentFile(ctx, filepath.Join(d, ".env"), false); e != nil {
			return e
		}
	}
	if o.EnvFile != "" {
		o.EnvFile = Absolute(o.EnvFile, o.CWD, o.Home)
		if e := l.loadEnvironmentFile(ctx, o.EnvFile, true); e != nil {
			return e
		}
	}
	maps.Copy(c.Environment, l.fileenv)
	maps.Copy(c.Environment, process)
	l.o = o
	return nil
}
func (l *configLoader) loadEnvironmentFile(ctx context.Context, p string, explicit bool) error {
	o, fileenv, process := l.o, l.fileenv, l.process
	body, found, e := ncconfig.ReadFile(ctx, p, !explicit || o.AllowMissing)
	if e != nil || !found {
		return e
	}
	m, e := ncconfig.ParseEnvironment(string(body), fileenv, process)
	if e != nil {
		return e
	}
	for k, v := range m {
		if k == "VXLAN_DIRECTORY" || k == "NC_KNOWN_HOSTS" || k == "ND_CACHE_DIRECTORY" || k == "VXLAN_CONFIG" || (k == "ND_DB_SSLROOTCERT" && v != "system") {
			if strings.TrimSpace(v) != "" {
				v = Absolute(v, filepath.Dir(p), o.Home)
			}
		}
		fileenv[k] = v
	}
	l.envFiles = append(l.envFiles, p)
	return nil
}

func (l *configLoader) configuration(ctx context.Context) error {
	o, c, process, fileenv, user, dirs := l.o, &l.c, l.process, l.fileenv, l.user, l.dirs
	explicit := o.ConfigFile
	if explicit == "" {
		explicit = strings.TrimSpace(process["VXLAN_CONFIG"])
		if explicit == "" {
			explicit = strings.TrimSpace(fileenv["VXLAN_CONFIG"])
		}
	}
	if explicit != "" {
		explicit = Absolute(explicit, o.CWD, o.Home)
	}
	c.ConfigPath = explicit
	if c.ConfigPath == "" {
		c.ConfigPath = filepath.Join(user, "vxlan.yml")
	}
	c.EnvPath = o.EnvFile
	if c.EnvPath == "" {
		c.EnvPath = filepath.Join(user, ".env")
	}
	l.data, l.specific = vxlan.Record{}, vxlan.Record{}
	l.files = []string{}
	l.fields = map[string]string{}
	if !o.EnvironmentOnly {
		for _, d := range dirs {
			for _, name := range []string{"net-connector.yml", "vxlan.yml"} {
				p := filepath.Join(d, name)
				if p == explicit {
					continue
				}
				if e := l.loadConfigurationFile(ctx, p, false); e != nil {
					return e
				}
			}
		}
		if explicit != "" {
			if e := l.loadConfigurationFile(ctx, explicit, true); e != nil {
				return e
			}
		}
	}
	return nil
}
func (l *configLoader) loadConfigurationFile(ctx context.Context, p string, required bool) error {
	o, fields := l.o, l.fields
	body, found, e := ncconfig.ReadFile(ctx, p, !required || o.AllowMissing)
	if e != nil || !found {
		return e
	}
	m, e := ncconfig.ParseYAMLMapping(body)
	if e != nil {
		return e
	}
	l.files = append(l.files, p)
	native := filepath.Base(p) != "net-connector.yml"
	part := m
	if _, ok := m["common"]; ok || m["vxlan"] != nil {
		common, err := sharedConfiguration(m)
		if err != nil {
			return err
		}
		part = record.MergeLayers(common, record.Map(m["vxlan"]))
		l.specific = record.MergeLayers(l.specific, record.Map(m["vxlan"]))
	} else if !native {
		part = vxlan.Record{}
		for _, k := range []string{"netdisco", "inventory", "ssh"} {
			if v, ok := m[k]; ok {
				part[k] = v
			}
		}
	} else {
		l.specific = record.MergeLayers(l.specific, m)
	}
	resolve(part, filepath.Dir(p), o.Home, "", fields)
	for k := range fields {
		if fields[k] == filepath.Dir(p) {
			fields[k] = p
		}
	}
	l.data = record.MergeLayers(l.data, part)
	return nil
}

func (l *configLoader) finish(ctx context.Context) error {
	o, c, data, specific, files, fields, fileenv, process, envFiles := l.o, &l.c, l.data, l.specific, l.files, l.fields, l.fileenv, l.process, l.envFiles
	c.Missing = len(files) == 0
	if len(record.List(specific["devices"])) > 0 && specific["netdisco"] == nil && specific["inventory"] == nil && specific["netdisco_config"] == nil {
		delete(data, "netdisco")
		delete(data, "inventory")
	}
	if specific["netdisco_config"] != nil && specific["netdisco"] == nil && specific["inventory"] == nil {
		delete(data, "netdisco")
		delete(data, "inventory")
	}
	defaults := vxlan.Record{"fabric": "default", "devices": []any{}, "parallel": 4, "directory": filepath.Join(o.CWD, "vxlans"), "dimensions": nxos.DimensionNames(), "ssh": vxlan.Record{"host_key_policy": "strict", "command_timeout": 60, "login_timeout": 15}}
	pv := envValues(process)
	resolve(pv, o.CWD, o.Home, "", map[string]string{})
	overrides := record.MergeLayers(o.Overrides)
	resolve(overrides, o.CWD, o.Home, "", map[string]string{})
	c.Values = record.MergeLayers(defaults, envValues(fileenv), data, pv, overrides)
	c.Sources = vxlan.Record{"configuration_files": files, "environment_files": envFiles, "fields": fields}
	if e := validateConfig(c.Values); e != nil {
		return e
	}
	if p := record.String(c.Values["fabric_policy"]); p != "" {
		m, e := ReadYAML(ctx, p)
		if e != nil {
			return e
		}
		if e = fabric.ValidatePolicyDocument(m); e != nil {
			return e
		}
		c.Policy = m
	}
	if e := prepareInventory(ctx, c, fileenv, process, o.CWD, o.Home); e != nil {
		return e
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.freeze()
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func normalizeDevices(v any) ([]any, error) {
	a := record.List(v)
	if a == nil {
		return nil, fmt.Errorf("devices 须为数组")
	}
	out := []any{}
	seen := map[string]bool{}
	for _, x := range a {
		r, ok := x.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("设备须为映射")
		}
		for k := range r {
			if !record.Contains([]string{"host", "name", "model"}, k) {
				return nil, fmt.Errorf("devices 仅接受 host/name/model")
			}
		}
		ip, e := netip.ParseAddr(record.String(r["host"]))
		if e != nil || ip.Zone() != "" || seen[ip.String()] {
			return nil, fmt.Errorf("设备地址无效或重复")
		}
		seen[ip.String()] = true
		for _, k := range []string{"name", "model"} {
			if r[k] != nil && strings.TrimSpace(record.String(r[k])) == "" {
				return nil, fmt.Errorf("设备字段无效")
			}
		}
		name := record.String(r["name"])
		if name == "" {
			name = ip.String()
		}
		out = append(out, vxlan.Record{"host": ip.String(), "name": name, "model": r["model"]})
	}
	return out, nil
}
func validateConfig(m vxlan.Record) error {
	if v, ok := m["fabric_policy"]; ok && strings.TrimSpace(record.String(v)) == "" {
		return fmt.Errorf("fabric_policy 须为路径")
	}
	for k := range m {
		if !record.Contains([]string{"fabric", "fabric_policy", "devices", "netdisco", "inventory", "netdisco_config", "parallel", "directory", "dimensions", "ssh", "hosts", "exclude_hosts", "names", "exclude_names"}, k) {
			return fmt.Errorf("YAML 包含未知或敏感字段")
		}
	}
	p := record.NumberFloat(m["parallel"])
	if math.IsNaN(p) || p != math.Trunc(p) || p < 1 || p > 500 {
		return fmt.Errorf("parallel 须为 1～500")
	}
	m["parallel"] = int(p)
	for _, k := range []string{"fabric", "directory"} {
		if strings.TrimSpace(record.String(m[k])) == "" {
			return fmt.Errorf("%s 须为非空字符串", k)
		}
	}
	a := record.List(m["dimensions"])
	if len(a) == 0 {
		return fmt.Errorf("dimensions 不能为空")
	}
	seen := map[string]bool{}
	for _, v := range a {
		n, ok := v.(string)
		if !ok || seen[n] || nxos.Commands()[n] == "" {
			return fmt.Errorf("dimensions 包含未知或重复维度")
		}
		seen[n] = true
	}
	rows, e := normalizeDevices(m["devices"])
	if e != nil {
		return e
	}
	m["devices"] = rows
	inline := false
	for _, k := range []string{"netdisco", "inventory"} {
		if v, ok := m[k]; ok {
			inline = true
			if _, ok = v.(map[string]any); !ok {
				return fmt.Errorf("清单配置须为映射")
			}
		}
	}
	if inline && (len(rows) > 0 || m["netdisco_config"] != nil) {
		return fmt.Errorf("清单来源冲突")
	}
	if v, ok := m["netdisco_config"]; ok && (record.String(v) == "" || len(rows) > 0) {
		return fmt.Errorf("外部清单配置无效")
	}
	if err := validateFilters(m); err != nil {
		return err
	}
	return validateSSH(m)
}
func addressPrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, e := netip.ParseAddr(s)
	if e != nil {
		return netip.Prefix{}, e
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func validateFilters(m vxlan.Record) error {
	for _, k := range []string{"hosts", "exclude_hosts", "names", "exclude_names"} {
		v, ok := m[k]
		if !ok {
			m[k] = []string{}
			continue
		}
		a := record.List(v)
		if a == nil {
			return fmt.Errorf("筛选条件须为数组")
		}
		for _, x := range a {
			s, ok := x.(string)
			if !ok || strings.TrimSpace(s) == "" {
				return fmt.Errorf("筛选项不能为空")
			}
			if k == "hosts" || k == "exclude_hosts" {
				if _, e := addressPrefix(s); e != nil {
					return fmt.Errorf("地址筛选只接受 IP/CIDR")
				}
			}
		}
	}
	return nil
}

func validateSSH(m vxlan.Record) error {
	ssh, ok := m["ssh"].(map[string]any)
	if !ok {
		return fmt.Errorf("ssh 须为映射")
	}
	for k := range ssh {
		if !record.Contains([]string{"port", "command_timeout", "login_timeout", "host_key_policy", "known_hosts"}, k) {
			return fmt.Errorf("ssh 包含未知或敏感字段")
		}
	}
	if !record.Contains([]string{"strict", "accept_new"}, record.String(ssh["host_key_policy"])) {
		return fmt.Errorf("主机密钥策略无效")
	}
	for _, k := range []string{"command_timeout", "login_timeout"} {
		n := record.NumberFloat(ssh[k])
		if math.IsNaN(n) || math.IsInf(n, 0) || n <= 0 {
			return fmt.Errorf("超时须为正数")
		}
	}
	if n, ok := ssh["port"]; ok {
		p := record.NumberFloat(n)
		if math.IsNaN(p) || p != math.Trunc(p) || p < 1 || p > 65535 {
			return fmt.Errorf("端口无效")
		}
	}
	if v, ok := ssh["known_hosts"]; ok && record.String(v) == "" {
		return fmt.Errorf("known_hosts 须为路径")
	}
	return nil
}

func sharedConfiguration(m vxlan.Record) (vxlan.Record, error) {
	for k := range m {
		if !record.Contains([]string{"common", "vxlan", "wireless", "backup", "topology"}, k) {
			return nil, fmt.Errorf("共享 YAML 包含未知分区")
		}
	}
	for _, key := range []string{"common", "vxlan"} {
		if v, ok := m[key]; ok {
			if _, ok := v.(map[string]any); !ok {
				return nil, fmt.Errorf("共享分区须为映射")
			}
		}
	}
	common := record.Map(m["common"])
	for k := range common {
		if !record.Contains([]string{"netdisco", "inventory", "ssh"}, k) {
			return nil, fmt.Errorf("common 包含未知字段")
		}
	}
	return common, nil
}
