package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/pflag"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/internal/bootstrap"
	"github.com/gatework/go-vxlan/internal/workflow"
	"github.com/gatework/go-vxlan/report"
)

const baselineHeader = `# Fabric 基线（schema_version 1）：由当前采集的多数值生成，仅为待审核草案。
# 多数值不等于正确值：逐项确认设计意图（例如 vPC 与独立 Leaf 的 NVE 源接口可能本应不同），
# 删除不应约束的字段，再以 vxlan review --baseline 冻结使用。未声明的字段不检查。
`

func (a *App) baseline(ctx context.Context, f *pflag.FlagSet) int {
	if flagBool(f, "help") {
		fmt.Fprintln(a.Output, "用法：vxlan baseline --batch DIR --fabric-policy FILE [--output FILE]\n"+f.FlagUsages())
		return 0
	}
	if f.NArg() != 0 || flagString(f, "batch") == "" || flagString(f, "fabric-policy") == "" {
		return a.fail(errors.New("需要 --batch DIR 和 --fabric-policy FILE"))
	}
	sources, e := report.ReadSources(ctx, bootstrap.Absolute(flagString(f, "batch"), a.CWD, a.Home))
	if e != nil {
		return a.fail(e)
	}
	var policy vxlan.Record
	if policy, e = bootstrap.ReadYAML(ctx, bootstrap.Absolute(flagString(f, "fabric-policy"), a.CWD, a.Home)); e != nil {
		return a.fail(e)
	}
	if e = fabric.ValidatePolicyDocument(policy); e != nil {
		return a.fail(e)
	}
	b, e := workflow.DeriveBaseline(ctx, sources, policy)
	if e != nil {
		return a.fail(e)
	}
	body, e := b.Encode()
	if e != nil {
		return a.fail(e)
	}
	body = append([]byte(baselineHeader), body...)
	out := flagString(f, "output")
	if out == "" {
		if _, e = a.Output.Write(body); e != nil {
			return 2
		}
		return 0
	}
	path := bootstrap.Absolute(out, a.CWD, a.Home)
	file, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if e != nil {
		return a.fail(fmt.Errorf("无法创建基线文件（不覆盖已有文件）：%w", e))
	}
	_, e = file.Write(body)
	if e = errors.Join(e, file.Sync(), file.Close()); e != nil {
		return a.fail(e)
	}
	fmt.Fprintf(a.Output, "基线草案已写入：%s；请审核后再用于 review --baseline。\n", path)
	return 0
}
