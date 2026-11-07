// Package cli owns inventory, credentials, scheduling, persistence and terminal interaction.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gatework/go-net-connector/connector"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/adapter"
	"github.com/spf13/pflag"
	"go.yaml.in/yaml/v3"
	"golang.org/x/term"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const Version = "0.1.0"

type App struct {
	Input              io.Reader
	Output, Error      io.Writer
	CWD, Home, Program string
	Directories        []string
	Environment        map[string]string
	Open               func(connector.ConnectionConfig) vxlan.OpenSession
	Terminal           func() bool
}

func (a *App) defaults() {
	if a.Input == nil {
		a.Input = os.Stdin
	}
	if a.Output == nil {
		a.Output = os.Stdout
	}
	if a.Error == nil {
		a.Error = os.Stderr
	}
	if a.CWD == "" {
		a.CWD, _ = os.Getwd()
	}
	if a.Home == "" {
		a.Home, _ = os.UserHomeDir()
	}
	if a.Open == nil {
		a.Open = adapter.Open
	}
}
func (a *App) tty() bool {
	if a.Terminal != nil {
		return a.Terminal()
	}
	for _, v := range []any{a.Input, a.Output, a.Error} {
		f, ok := v.(interface{ Fd() uintptr })
		if !ok || !term.IsTerminal(int(f.Fd())) {
			return false
		}
	}
	return true
}
func (a *App) Run(ctx context.Context, args []string) (code int) {
	a.defaults()
	output, errout := a.Output, a.Error
	ow, ew := &checkedWriter{Writer: output}, &checkedWriter{Writer: errout}
	a.Output, a.Error = ow, ew
	defer func() {
		a.Output, a.Error = output, errout
		if ctx.Err() != nil {
			code = 130
		}
		if (ow.failed || ew.failed) && code != 130 {
			code = 2
		}
	}()
	if len(args) == 0 {
		if a.usage() != nil {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "-h", "--help", "--help-all":
		if len(args) != 1 {
			return a.fail(fmt.Errorf("多余参数"))
		}
		if a.usage() != nil {
			return 2
		}
		return 0
	case "-v", "--version":
		if len(args) != 1 {
			return a.fail(fmt.Errorf("多余参数"))
		}
		if _, e := fmt.Fprintln(a.Output, Version); e != nil {
			return 2
		}
		return 0
	case "parse":
		return a.parse(ctx, args[1:])
	case "collect":
		return a.collect(ctx, args[1:])
	case "review":
		return a.review(args[1:])
	case "apply":
		return a.apply(ctx, args[1:])
	default:
		return a.fail(fmt.Errorf("未知命令；使用 vxlan --help"))
	}
}
func (a *App) usage() error {
	_, e := fmt.Fprintln(a.Output, "用法：vxlan collect [选项]  只读采集与报告\n      vxlan parse [选项]    离线文件或 stdin 解析\n      vxlan review --batch DIR  离线诊断与修复建议\n      vxlan apply --plan FILE --item ID  交互确认后下发\n      vxlan --version\n使用各子命令 --help 查看参数。")
	return e
}
func (a *App) fail(e error) int {
	fmt.Fprintf(a.Error, "VXLAN 参数或执行错误：%s\n", e)
	return 2
}
func (a *App) json(v any) error {
	enc := json.NewEncoder(a.Output)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
func (a *App) flags(name string) *pflag.FlagSet {
	f := pflag.NewFlagSet(name, pflag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.BoolP("help", "h", false, "查看帮助，不读取配置或连接设备")
	return f
}
func flagBool(f *pflag.FlagSet, k string) bool     { v, _ := f.GetBool(k); return v }
func flagString(f *pflag.FlagSet, k string) string { v, _ := f.GetString(k); return v }
func (a *App) parse(ctx context.Context, args []string) int {
	f := a.flags("parse")
	f.String("file", "", "输入文件；默认读取 stdin")
	f.String("dimension", "configuration", "解析维度")
	f.String("model", "", "设备型号")
	f.Bool("complete", false, "声明输入已完整采集")
	f.Bool("json", false, "输出解析事实 JSON")
	f.Bool("examples", false, "示例")
	f.Bool("help-all", false, "全部帮助")
	if e := f.Parse(args); e != nil {
		return a.fail(e)
	}
	if f.NArg() != 0 {
		return a.fail(fmt.Errorf("不接受位置参数"))
	}
	if flagBool(f, "help") || flagBool(f, "help-all") || flagBool(f, "examples") {
		fmt.Fprintln(a.Output, "用法：vxlan parse --dimension configuration --file running.cfg --complete --json\n"+f.FlagUsages()+"维度："+strings.Join(vxlan.DimensionNames(), ", "))
		return 0
	}
	if name := flagString(f, "dimension"); vxlan.Commands()[name] == "" {
		return a.fail(fmt.Errorf("未知解析维度"))
	}
	reader := a.Input
	if p := flagString(f, "file"); p != "" {
		file, e := os.Open(absolute(p, a.CWD, a.Home))
		if e != nil {
			return a.fail(fmt.Errorf("输入文件无法读取"))
		}
		defer file.Close()
		reader = file
	}
	body, e := readContext(ctx, reader)
	if e != nil {
		return a.fail(fmt.Errorf("输入读取失败"))
	}
	name := flagString(f, "dimension")
	profile, e := vxlan.DefaultParserRegistry().Fetch("cisco_nxos", flagString(f, "model"))
	if e != nil {
		return a.fail(e)
	}
	o, e := profile.Parse(name, string(body), flagBool(f, "complete"))
	if e != nil {
		return a.fail(e)
	}
	if flagBool(f, "json") {
		e = a.json(o)
	} else {
		codes := []string{}
		for _, i := range o.Issues {
			codes = append(codes, str(i["code"]))
		}
		_, e = fmt.Fprintf(a.Output, "维度：%s；状态：%s；记录：%d\n诊断：%s\n", name, o.Status, len(o.Records), strings.Join(codes, ", "))
	}
	if e != nil {
		return 2
	}
	if o.Complete() {
		return 0
	}
	return 1
}
func (a *App) collectFlags(args []string) (*pflag.FlagSet, Config, error) {
	f := a.flags("collect")
	for _, k := range []string{"config", "env-file", "directory", "fabric-policy", "fabric"} {
		f.String(k, "", "公开配置或路径")
	}
	f.IntP("parallel", "p", 4, "设备并发 1～500")
	for _, k := range []string{"dimensions", "host", "hosts", "exclude-hosts", "name", "exclude-name"} {
		f.StringArray(k, nil, "筛选或维度；逗号分隔，重复条件取并集")
	}
	for _, k := range []string{"init", "interactive", "non-interactive", "plan", "inventory-only", "show-config", "json", "quiet", "no-progress", "scripts", "no-scripts", "verbose", "help-all", "examples"} {
		f.Bool(k, false, "启用 "+k)
	}
	if e := f.Parse(args); e != nil {
		return f, Config{}, e
	}
	if f.NArg() != 0 {
		return f, Config{}, fmt.Errorf("不接受位置参数")
	}
	if flagBool(f, "help") || flagBool(f, "help-all") || flagBool(f, "examples") {
		return f, Config{}, nil
	}
	if flagBool(f, "interactive") && !a.tty() {
		return f, Config{}, fmt.Errorf("--interactive 需要真实终端")
	}
	overrides := M{}
	for _, k := range []string{"directory", "fabric-policy", "fabric"} {
		if f.Changed(k) {
			overrides[strings.ReplaceAll(k, "-", "_")] = flagString(f, k)
		}
	}
	if f.Changed("parallel") {
		v, _ := f.GetInt("parallel")
		overrides["parallel"] = v
	}
	for flag, key := range map[string]string{"dimensions": "dimensions", "host": "hosts", "hosts": "hosts", "exclude-hosts": "exclude_hosts", "name": "names", "exclude-name": "exclude_names"} {
		if !f.Changed(flag) {
			continue
		}
		values, _ := f.GetStringArray(flag)
		parts := texts(overrides[key])
		for _, v := range values {
			for _, item := range strings.Split(v, ",") {
				item = strings.TrimSpace(item)
				if item == "" {
					return f, Config{}, fmt.Errorf("列表不能包含空项")
				}
				parts = append(parts, item)
			}
		}
		overrides[key] = parts
	}
	c, e := LoadConfig(ConfigOptions{CWD: a.CWD, Home: a.Home, Program: a.Program, Directories: a.Directories, ConfigFile: flagString(f, "config"), EnvFile: flagString(f, "env-file"), Environment: a.Environment, Overrides: overrides, AllowMissing: flagBool(f, "init"), EnvironmentOnly: flagBool(f, "init")})
	return f, c, e
}
func (a *App) initialize(c Config, f *pflag.FlagSet) error {
	values := merge(c.Values)
	delete(values, "inventory_configuration")
	if !f.Changed("parallel") && c.Environment["VXLAN_PARALLEL"] == "" {
		delete(values, "parallel")
	}
	body, e := yaml.Marshal(values)
	if e != nil {
		return e
	}
	for p, b := range map[string][]byte{c.ConfigPath: body, c.EnvPath: []byte("# 设备凭据；可用 SSH key/agent\nNC_DEVICE_USERNAME=\nNC_DEVICE_PASSWORD=\n")} {
		if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			return e
		}
		file, err := os.CreateTemp(filepath.Dir(p), ".vxlan-init-*.tmp")
		if err != nil {
			return err
		}
		tmp := file.Name()
		err = file.Chmod(0600)
		if err == nil {
			_, err = file.Write(b)
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Link(tmp, p)
		}
		os.Remove(tmp)
		if os.IsExist(err) {
			fmt.Fprintln(a.Output, "已保留："+p)
			continue
		}
		if err != nil {
			return err
		}
		if err = syncDirectory(filepath.Dir(p)); err != nil {
			return err
		}
		fmt.Fprintln(a.Output, "已创建："+p)
	}
	_, e = fmt.Fprintln(a.Output, "请检查配置及凭据后再次运行；本次未连接设备。")
	return e
}
func (a *App) missingConfig(ctx context.Context, c Config, f *pflag.FlagSet) (bool, error) {
	if !c.Missing {
		return false, nil
	}
	if a.tty() && !flagBool(f, "non-interactive") {
		fmt.Fprint(a.Error, "配置不存在，是否创建配置与环境模板？[y/N] ")
		line, e := readLineContext(ctx, a.Input)
		if e != nil {
			return false, e
		}
		if strings.EqualFold(strings.TrimSpace(line), "y") || strings.EqualFold(strings.TrimSpace(line), "yes") {
			return true, a.initialize(c, f)
		}
	}
	return false, fmt.Errorf("配置不存在；请执行 collect --init --non-interactive")
}

type checkedWriter struct {
	io.Writer
	failed bool
}

func (w *checkedWriter) Write(b []byte) (int, error) {
	n, e := w.Writer.Write(b)
	if n != len(b) && e == nil {
		e = io.ErrShortWrite
	}
	if e != nil {
		w.failed = true
	}
	return n, e
}
func (w *checkedWriter) Fd() uintptr {
	if f, ok := w.Writer.(interface{ Fd() uintptr }); ok {
		return f.Fd()
	}
	return ^uintptr(0)
}
