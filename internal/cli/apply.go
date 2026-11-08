package cli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/pflag"

	"github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/internal/bootstrap"
	"github.com/gatework/go-vxlan/internal/record"
	applypkg "github.com/gatework/go-vxlan/internal/workflow/apply"
	"github.com/gatework/go-vxlan/report"
)

func (a *App) apply(ctx context.Context, f *pflag.FlagSet) int {
	if flagBool(f, "help") {
		fmt.Fprintln(a.Output, "用法：vxlan apply --plan FILE --item ID（必须真实终端明确确认）\n"+f.FlagUsages())
		return 0
	}
	if !a.tty() {
		return a.fail(fmt.Errorf("必须使用真实交互终端"))
	}
	port, _ := f.GetInt("port")
	id := flagString(f, "item")
	if f.NArg() != 0 || flagString(f, "plan") == "" || !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(id) || port < 1 || port > 65535 {
		return a.fail(fmt.Errorf("需要有效 --plan 和 --item"))
	}
	path := bootstrap.Absolute(flagString(f, "plan"), a.CWD, a.Home)
	body, e := os.ReadFile(path)
	if e != nil {
		return a.fail(fmt.Errorf("计划无法读取"))
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(body))
	checksum, e := os.ReadFile(path + ".sha256")
	if e != nil || strings.TrimSpace(string(checksum)) != hash {
		return a.fail(fmt.Errorf("计划校验失败"))
	}
	bound, e := change.NewExecutionPlan(body, id)
	if e != nil {
		return a.fail(e)
	}
	plan, device, host := bound.Presentation(), bound.Device(), bound.Host()
	token := bound.ConfirmationToken()
	if _, e = fmt.Fprintf(a.Output, "目标：%s（%s）；%s；%s\n影响：%s\n条件：%s\n计划 SHA256：%s\n拟执行命令：\n%s\n条件回退（不自动执行）：\n%s\n确认业务策略及维护窗口后输入 %s；其他输入取消：", device["name"], host, plan["scope"], plan["title"], plan["impact"], strings.Join(record.Texts(plan["prerequisites"]), "；"), hash, strings.Join(bound.Commands(), "\n"), strings.Join(bound.Rollback(), "\n"), token); e != nil {
		return 2
	}
	line, e := readLineContext(ctx, a.Input)
	if e != nil || strings.TrimSpace(line) != token {
		fmt.Fprintln(a.Output, "已取消，未连接设备。")
		return 1
	}
	cfg, e := bootstrap.Load(bootstrap.ConfigOptions{CWD: a.CWD, Home: a.Home, Program: a.Program, Directories: a.Directories, Environment: a.Environment, EnvFile: flagString(f, "env-file"), AllowMissing: true, EnvironmentOnly: true})
	if e != nil {
		return a.fail(fmt.Errorf("凭据配置无法读取"))
	}
	open, e := bootstrap.Application(cfg, host, port, a.Open)
	if e != nil {
		return a.fail(e)
	}
	r, e := report.New(bootstrap.Absolute(flagString(f, "directory"), a.CWD, a.Home))
	if e != nil {
		return a.fail(e)
	}
	result, err := applypkg.Run(ctx, bound, open, r)
	if err != nil {
		if result.ReportUnconfirmed {
			fmt.Fprintln(a.Error, "执行日志收尾未确认；保留已有检查点，禁止重放配置。")
		}
		fmt.Fprintln(a.Error, "下发停止；效果未完整确认，先回读核对，不自动重放或回退。")
		if result.Interrupted {
			return 130
		}
		return 2
	}
	if _, e = fmt.Fprintf(a.Output, "配置回读已确认；仍需完成业务验收，未执行保存配置。日志：%s/execution.json\n", r.Directory); e != nil {
		return 2
	}
	return 0
}
