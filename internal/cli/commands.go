package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type commandExit int

func (e commandExit) Error() string { return "command incomplete" }
func (a *App) runCommands(ctx context.Context, args []string) int {
	if len(args) > 1 {
		switch args[0] {
		case "--help", "-h", "--help-all", "--version", "-v":
			return a.fail(fmt.Errorf("多余参数"))
		}
	}
	helpCode := 0
	root := &cobra.Command{Use: "vxlan", SilenceErrors: true, SilenceUsage: true, Args: cobra.NoArgs}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetArgs(args)
	root.SetIn(a.Input)
	root.SetOut(a.Output)
	root.SetErr(a.Error)
	root.Flags().Bool("help-all", false, "全部帮助")
	root.Flags().BoolP("version", "v", false, "显示版本")
	root.RunE = func(c *cobra.Command, _ []string) error {
		if flagBool(c.Flags(), "version") {
			_, err := fmt.Fprintln(a.Output, Version)
			return err
		}
		return a.usage()
	}
	root.SetHelpFunc(func(c *cobra.Command, _ []string) {
		if c == root {
			if err := a.usage(); err != nil {
				helpCode = 2
			}
		}
	})
	root.SetHelpCommand(&cobra.Command{Use: "help", Hidden: true, RunE: func(*cobra.Command, []string) error { return fmt.Errorf("未知命令；使用 vxlan --help") }})
	add := func(name string, run func(context.Context, *pflag.FlagSet) int) {
		c := &cobra.Command{Use: name, Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true}
		c.Flags().AddFlagSet(a.commandFlags(name))
		c.RunE = func(c *cobra.Command, _ []string) error {
			if code := run(c.Context(), c.Flags()); code != 0 {
				return commandExit(code)
			}
			return nil
		}
		c.SetHelpFunc(func(c *cobra.Command, _ []string) { helpCode = run(c.Context(), c.Flags()) })
		root.AddCommand(c)
	}
	add("parse", a.parse)
	add("collect", a.collect)
	add("apply", a.apply)
	add("review", a.review)
	add("baseline", a.baseline)
	err := root.ExecuteContext(ctx)
	if err != nil {
		var code commandExit
		if errors.As(err, &code) {
			return int(code)
		}
		return a.fail(err)
	}
	return helpCode
}
func (a *App) commandFlags(name string) *pflag.FlagSet {
	f := a.flags(name)
	switch name {
	case "parse":
		f.String("file", "", "输入文件；默认读取 stdin")
		f.String("dimension", "configuration", "解析维度")
		f.String("model", "", "设备型号")
		f.Bool("complete", false, "声明输入已完整采集")
		f.Bool("json", false, "输出解析事实 JSON")
		f.Bool("examples", false, "示例")
		f.Bool("help-all", false, "全部帮助")
	case "collect":
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
	case "review":
		for _, k := range []string{"batch", "output", "fabric-policy"} {
			f.String(k, "", "批次或输出路径")
		}
		f.String("rules-policy", "", "风险规则策略 YAML：启用/禁用、严重级别、阈值")
		f.String("baseline", "", "冻结的 Fabric 基线 YAML：报告偏离声明意图的配置")
		f.String("previous", "", "上一批次目录：报告自上次采集以来的变化")
	case "baseline":
		for _, k := range []string{"batch", "fabric-policy", "output"} {
			f.String(k, "", "批次、策略或输出路径")
		}
		f.Bool("scripts", false, "导出候选配置")
		f.Bool("no-scripts", false, "不导出候选配置")
	case "apply":
		f.String("plan", "", "批次 plan.json（需要 SHA256 校验文件）")
		f.String("item", "", "明确选择单个计划项")
		f.String("env-file", "", "显式凭据文件")
		f.String("directory", filepath.Join(a.CWD, "vxlan-executions"), "私有执行记录目录")
		f.Int("port", 22, "SSH 端口")
	}
	return f
}
