package cli

import (
	"bytes"
	"fmt"
	ncconfig "github.com/gatework/go-net-connector/config"
	vxlan "github.com/gatework/go-vxlan"
	"go.yaml.in/yaml/v3"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type M = map[string]any
type ConfigOptions struct {
	CWD, Home, Program, ConfigFile, EnvFile string
	Directories                             []string
	Environment                             map[string]string
	Overrides                               M
	AllowMissing                            bool
	EnvironmentOnly                         bool
}
type Config struct {
	Values              M
	Environment         map[string]string
	Sources             M
	ConfigPath, EnvPath string
	Missing             bool
	Policy              M
	Inventory           M
}

func (c Config) String() string   { return "cli.Config" }
func (c Config) GoString() string { return c.String() }
func object(v any) M {
	m, _ := v.(map[string]any)
	if m == nil {
		return M{}
	}
	return m
}
func list(v any) []any {
	if a, ok := v.([]M); ok {
		r := []any{}
		for _, x := range a {
			r = append(r, x)
		}
		return r
	}
	if a, ok := v.([]any); ok {
		return a
	}
	if a, ok := v.([]string); ok {
		r := []any{}
		for _, s := range a {
			r = append(r, s)
		}
		return r
	}
	return nil
}
func texts(v any) []string {
	r := []string{}
	for _, x := range list(v) {
		if s, ok := x.(string); ok {
			r = append(r, s)
		}
	}
	return r
}
func str(v any) string { s, _ := v.(string); return s }
func number(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case float64:
		return n
	case int64:
		return float64(n)
	}
	return math.NaN()
}
func merge(ms ...M) M {
	out := M{}
	for _, m := range ms {
		for k, v := range m {
			if child, ok := v.(map[string]any); ok {
				out[k] = merge(object(out[k]), child)
			} else {
				out[k] = v
			}
		}
	}
	return out
}
func absolute(p, base, home string) string {
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
func readYAML(path string) (M, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	return parseYAML(b)
}
func parseYAML(b []byte) (M, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var root yaml.Node
	if e := dec.Decode(&root); e != nil {
		return nil, fmt.Errorf("YAML 无效")
	}
	var extra yaml.Node
	if e := dec.Decode(&extra); e != io.EOF {
		return nil, fmt.Errorf("YAML 禁止多文档")
	}
	var check func(*yaml.Node) error
	check = func(n *yaml.Node) error {
		if n.Kind == yaml.AliasNode || n.Anchor != "" {
			return fmt.Errorf("YAML 禁止别名")
		}
		if n.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Tag != "!!str" || seen[k.Value] {
					return fmt.Errorf("YAML 键重复或不是字符串")
				}
				seen[k.Value] = true
			}
		}
		for _, c := range n.Content {
			if e := check(c); e != nil {
				return e
			}
		}
		return nil
	}
	if e := check(&root); e != nil {
		return nil, e
	}
	var m M
	if e := root.Decode(&m); e != nil || m == nil {
		return nil, fmt.Errorf("YAML 须为映射")
	}
	return m, nil
}

var configPaths = map[string]bool{"directory": true, "fabric_policy": true, "netdisco_config": true, "ssh.known_hosts": true, "netdisco.cache_directory": true, "netdisco.db_sslrootcert": true}

func resolve(m M, base, home, prefix string, fields map[string]string) {
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
				m[k] = absolute(p, base, home)
			}
		}
	}
}
func envValues(env map[string]string) M {
	m := M{}
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
	ssh := M{}
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
func LoadConfig(o ConfigOptions) (Config, error) {
	c := Config{Environment: map[string]string{}, Sources: M{}}
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
		for k, v := range o.Environment {
			process[k] = v
		}
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
		d = absolute(d, o.CWD, o.Home)
		if !seen[d] {
			seen[d] = true
			unique = append(unique, d)
		}
	}
	dirs = unique
	fileenv := map[string]string{}
	envFiles := []string{}
	loadEnv := func(p string, explicit bool) error {
		body, e := os.ReadFile(p)
		var m map[string]string
		if e == nil {
			m, e = ncconfig.ParseEnvironment(string(body), fileenv, process)
		}
		if os.IsNotExist(e) && (!explicit || o.AllowMissing) {
			return nil
		}
		if e != nil {
			return e
		}
		for k, v := range m {
			if k == "VXLAN_DIRECTORY" || k == "NC_KNOWN_HOSTS" || k == "ND_CACHE_DIRECTORY" || k == "VXLAN_CONFIG" || (k == "ND_DB_SSLROOTCERT" && v != "system") {
				if strings.TrimSpace(v) != "" {
					v = absolute(v, filepath.Dir(p), o.Home)
				}
			}
			fileenv[k] = v
		}
		envFiles = append(envFiles, p)
		return nil
	}
	for _, d := range dirs {
		if e := loadEnv(filepath.Join(d, ".env"), false); e != nil {
			return c, e
		}
	}
	if o.EnvFile != "" {
		o.EnvFile = absolute(o.EnvFile, o.CWD, o.Home)
		if e := loadEnv(o.EnvFile, true); e != nil {
			return c, e
		}
	}
	for k, v := range fileenv {
		c.Environment[k] = v
	}
	for k, v := range process {
		c.Environment[k] = v
	}
	explicit := o.ConfigFile
	if explicit == "" {
		explicit = strings.TrimSpace(process["VXLAN_CONFIG"])
		if explicit == "" {
			explicit = strings.TrimSpace(fileenv["VXLAN_CONFIG"])
		}
	}
	if explicit != "" {
		explicit = absolute(explicit, o.CWD, o.Home)
	}
	c.ConfigPath = explicit
	if c.ConfigPath == "" {
		c.ConfigPath = filepath.Join(user, "vxlan.yml")
	}
	c.EnvPath = o.EnvFile
	if c.EnvPath == "" {
		c.EnvPath = filepath.Join(user, ".env")
	}
	data, specific := M{}, M{}
	files := []string{}
	fields := map[string]string{}
	load := func(p string, required bool) error {
		m, e := readYAML(p)
		if os.IsNotExist(e) && (!required || o.AllowMissing) {
			return nil
		}
		if e != nil {
			return e
		}
		files = append(files, p)
		native := filepath.Base(p) != "net-connector.yml"
		part := m
		if _, ok := m["common"]; ok || m["vxlan"] != nil {
			for k := range m {
				if !contains([]string{"common", "vxlan", "wireless", "backup", "topology"}, k) {
					return fmt.Errorf("共享 YAML 包含未知分区")
				}
			}
			for _, key := range []string{"common", "vxlan"} {
				if v, ok := m[key]; ok {
					if _, ok := v.(map[string]any); !ok {
						return fmt.Errorf("共享分区须为映射")
					}
				}
			}
			common := object(m["common"])
			for k := range common {
				if !contains([]string{"netdisco", "inventory", "ssh"}, k) {
					return fmt.Errorf("common 包含未知字段")
				}
			}
			part = merge(common, object(m["vxlan"]))
			specific = merge(specific, object(m["vxlan"]))
		} else if !native {
			part = M{}
			for _, k := range []string{"netdisco", "inventory", "ssh"} {
				if v, ok := m[k]; ok {
					part[k] = v
				}
			}
		} else {
			specific = merge(specific, m)
		}
		resolve(part, filepath.Dir(p), o.Home, "", fields)
		for k := range fields {
			if fields[k] == filepath.Dir(p) {
				fields[k] = p
			}
		}
		data = merge(data, part)
		return nil
	}
	if !o.EnvironmentOnly {
		for _, d := range dirs {
			for _, name := range []string{"net-connector.yml", "vxlan.yml"} {
				p := filepath.Join(d, name)
				if p == explicit {
					continue
				}
				if e := load(p, false); e != nil {
					return c, e
				}
			}
		}
		if explicit != "" {
			if e := load(explicit, true); e != nil {
				return c, e
			}
		}
	}
	c.Missing = len(files) == 0
	if len(list(specific["devices"])) > 0 && specific["netdisco"] == nil && specific["inventory"] == nil && specific["netdisco_config"] == nil {
		delete(data, "netdisco")
		delete(data, "inventory")
	}
	if specific["netdisco_config"] != nil && specific["netdisco"] == nil && specific["inventory"] == nil {
		delete(data, "netdisco")
		delete(data, "inventory")
	}
	defaults := M{"fabric": "default", "devices": []any{}, "parallel": 4, "directory": filepath.Join(o.CWD, "vxlans"), "dimensions": vxlan.DimensionNames(), "ssh": M{"host_key_policy": "strict", "command_timeout": 60, "login_timeout": 15}}
	pv := envValues(process)
	resolve(pv, o.CWD, o.Home, "", map[string]string{})
	overrides := merge(o.Overrides)
	resolve(overrides, o.CWD, o.Home, "", map[string]string{})
	c.Values = merge(defaults, envValues(fileenv), data, pv, overrides)
	c.Sources = M{"configuration_files": files, "environment_files": envFiles, "fields": fields}
	if e := validateConfig(c.Values); e != nil {
		return c, e
	}
	if p := str(c.Values["fabric_policy"]); p != "" {
		m, e := readYAML(p)
		if e != nil {
			return c, e
		}
		c.Policy = m
	}
	if e := prepareInventory(&c, fileenv, process, o.CWD, o.Home); e != nil {
		return c, e
	}
	return c, nil
}
func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func normalizeDevices(v any) ([]any, error) {
	a := list(v)
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
			if !contains([]string{"host", "name", "model"}, k) {
				return nil, fmt.Errorf("devices 仅接受 host/name/model")
			}
		}
		ip, e := netip.ParseAddr(str(r["host"]))
		if e != nil || ip.Zone() != "" || seen[ip.String()] {
			return nil, fmt.Errorf("设备地址无效或重复")
		}
		seen[ip.String()] = true
		for _, k := range []string{"name", "model"} {
			if r[k] != nil && strings.TrimSpace(str(r[k])) == "" {
				return nil, fmt.Errorf("设备字段无效")
			}
		}
		name := str(r["name"])
		if name == "" {
			name = ip.String()
		}
		out = append(out, M{"host": ip.String(), "name": name, "model": r["model"]})
	}
	return out, nil
}
func validateConfig(m M) error {
	if v, ok := m["fabric_policy"]; ok && strings.TrimSpace(str(v)) == "" {
		return fmt.Errorf("fabric_policy 须为路径")
	}
	for k := range m {
		if !contains([]string{"fabric", "fabric_policy", "devices", "netdisco", "inventory", "netdisco_config", "parallel", "directory", "dimensions", "ssh", "hosts", "exclude_hosts", "names", "exclude_names"}, k) {
			return fmt.Errorf("YAML 包含未知或敏感字段")
		}
	}
	p := number(m["parallel"])
	if math.IsNaN(p) || p != math.Trunc(p) || p < 1 || p > 500 {
		return fmt.Errorf("parallel 须为 1～500")
	}
	m["parallel"] = int(p)
	for _, k := range []string{"fabric", "directory"} {
		if strings.TrimSpace(str(m[k])) == "" {
			return fmt.Errorf("%s 须为非空字符串", k)
		}
	}
	a := list(m["dimensions"])
	if len(a) == 0 {
		return fmt.Errorf("dimensions 不能为空")
	}
	seen := map[string]bool{}
	for _, v := range a {
		n, ok := v.(string)
		if !ok || seen[n] || vxlan.Commands()[n] == "" {
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
	if v, ok := m["netdisco_config"]; ok && (str(v) == "" || len(rows) > 0) {
		return fmt.Errorf("外部清单配置无效")
	}
	for _, k := range []string{"hosts", "exclude_hosts", "names", "exclude_names"} {
		v, ok := m[k]
		if !ok {
			m[k] = []string{}
			continue
		}
		a := list(v)
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
	ssh, ok := m["ssh"].(map[string]any)
	if !ok {
		return fmt.Errorf("ssh 须为映射")
	}
	for k := range ssh {
		if !contains([]string{"port", "command_timeout", "login_timeout", "host_key_policy", "known_hosts"}, k) {
			return fmt.Errorf("ssh 包含未知或敏感字段")
		}
	}
	if !contains([]string{"strict", "accept_new"}, str(ssh["host_key_policy"])) {
		return fmt.Errorf("主机密钥策略无效")
	}
	for _, k := range []string{"command_timeout", "login_timeout"} {
		n := number(ssh[k])
		if math.IsNaN(n) || math.IsInf(n, 0) || n <= 0 {
			return fmt.Errorf("超时须为正数")
		}
	}
	if n, ok := ssh["port"]; ok {
		p := number(n)
		if math.IsNaN(p) || p != math.Trunc(p) || p < 1 || p > 65535 {
			return fmt.Errorf("端口无效")
		}
	}
	if v, ok := ssh["known_hosts"]; ok && str(v) == "" {
		return fmt.Errorf("known_hosts 须为路径")
	}
	return nil
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
