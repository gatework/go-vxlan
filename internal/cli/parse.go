package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/gatework/go-vxlan/internal/bootstrap"
	"github.com/gatework/go-vxlan/internal/record"

	"github.com/spf13/pflag"
)

func (a *App) parse(ctx context.Context, f *pflag.FlagSet) int {
	profile, e := a.profiles.Fetch("cisco_nxos", flagString(f, "model"))
	if e != nil {
		return a.fail(e)
	}
	if f.NArg() != 0 {
		return a.fail(fmt.Errorf("不接受位置参数"))
	}
	if flagBool(f, "help") || flagBool(f, "help-all") || flagBool(f, "examples") {
		fmt.Fprintln(a.Output, "用法：vxlan parse --dimension configuration --file running.cfg --complete --json\n"+f.FlagUsages()+"维度："+strings.Join(profile.Dimensions(), ", "))
		return 0
	}
	if name := flagString(f, "dimension"); profile.Command(name) == "" {
		return a.fail(fmt.Errorf("未知解析维度"))
	}
	reader := a.Input
	if p := flagString(f, "file"); p != "" {
		file, e := os.Open(bootstrap.Absolute(p, a.CWD, a.Home))
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
	o, e := profile.Parse(name, string(body), flagBool(f, "complete"))
	if e != nil {
		return a.fail(e)
	}
	if flagBool(f, "json") {
		e = a.json(o)
	} else {
		codes := []string{}
		for _, i := range o.Issues {
			codes = append(codes, record.String(i["code"]))
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
