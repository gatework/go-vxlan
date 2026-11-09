package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/bootstrap"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/parser"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

const Version = "0.3.1"

type App struct {
	profiles           *parser.Registry
	Input              io.Reader
	Output, Error      io.Writer
	CWD, Home, Program string
	Directories        []string
	Environment        map[string]string
	Open               bootstrap.OpenFunc
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
	dependencies := bootstrap.NewDependencies(a.Open)
	a.Open, a.profiles = dependencies.Open, dependencies.Profiles
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
	return a.runCommands(ctx, args)
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
func (a *App) collectOptions(ctx context.Context, f *pflag.FlagSet) (bootstrap.Config, error) {
	if f.NArg() != 0 {
		return bootstrap.Config{}, fmt.Errorf("不接受位置参数")
	}
	if flagBool(f, "help") || flagBool(f, "help-all") || flagBool(f, "examples") {
		return bootstrap.Config{}, nil
	}
	if flagBool(f, "interactive") && !a.tty() {
		return bootstrap.Config{}, fmt.Errorf("--interactive 需要真实终端")
	}
	overrides := vxlan.Record{}
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
		parts := record.Texts(overrides[key])
		for _, v := range values {
			for _, item := range strings.Split(v, ",") {
				item = strings.TrimSpace(item)
				if item == "" {
					return bootstrap.Config{}, fmt.Errorf("列表不能包含空项")
				}
				parts = append(parts, item)
			}
		}
		overrides[key] = parts
	}
	c, e := bootstrap.Load(ctx, bootstrap.ConfigOptions{CWD: a.CWD, Home: a.Home, Program: a.Program, Directories: a.Directories, ConfigFile: flagString(f, "config"), EnvFile: flagString(f, "env-file"), Environment: a.Environment, Overrides: overrides, AllowMissing: flagBool(f, "init"), EnvironmentOnly: flagBool(f, "init")})
	return c, e
}
func (a *App) initialize(ctx context.Context, c bootstrap.Config, f *pflag.FlagSet) error {
	results, err := bootstrap.Initialize(ctx, c, f.Changed("parallel"))
	for _, result := range results {
		status := "已创建："
		if result.Preserved {
			status = "已保留："
		}
		if _, writeErr := fmt.Fprintln(a.Output, status+result.Path); writeErr != nil {
			return writeErr
		}
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.Output, "请检查配置及凭据后再次运行；本次未连接设备。")
	return err
}
func (a *App) missingConfig(ctx context.Context, c bootstrap.Config, f *pflag.FlagSet) (bool, error) {
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
			return true, a.initialize(ctx, c, f)
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
