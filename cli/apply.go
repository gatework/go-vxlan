package cli

import (
	"context"
	"crypto/sha256"
	"fmt"
	vxlan "github.com/gatework/go-vxlan"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

func (a *App) apply(ctx context.Context, args []string) int {
	f := a.flags("apply")
	f.String("plan", "", "批次 plan.json（需要 SHA256 校验文件）")
	f.String("item", "", "明确选择单个计划项")
	f.String("env-file", "", "显式凭据文件")
	f.String("directory", filepath.Join(a.CWD, "vxlan-executions"), "私有执行记录目录")
	f.Int("port", 22, "SSH 端口")
	if e := f.Parse(args); e != nil {
		return a.fail(e)
	}
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
	path := absolute(flagString(f, "plan"), a.CWD, a.Home)
	body, e := os.ReadFile(path)
	if e != nil {
		return a.fail(fmt.Errorf("计划无法读取"))
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(body))
	checksum, e := os.ReadFile(path + ".sha256")
	if e != nil || strings.TrimSpace(string(checksum)) != hash {
		return a.fail(fmt.Errorf("计划校验失败"))
	}
	doc, decodeErr := decodeDocument(body)
	if decodeErr != nil || !integerInRange(doc["schema_version"], 2, 2) || doc["platform"] != "cisco_nxos" {
		return a.fail(fmt.Errorf("计划类型不匹配"))
	}
	plan, ok := object(doc["changes"])[id].(map[string]any)
	if !ok || !integerInRange(plan["schema_version"], 1, 1) || plan["platform"] != "cisco_nxos" {
		return a.fail(fmt.Errorf("计划项无效"))
	}
	device := object(plan["device"])
	host := str(device["host"])
	ip, e := netip.ParseAddr(host)
	if e != nil || ip.String() != host || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(str(plan["expected_config_sha256"])) {
		return a.fail(fmt.Errorf("目标或配置指纹无效"))
	}
	for _, key := range []string{"commands", "rollback"} {
		values, ok := plan[key].([]any)
		if !ok {
			return a.fail(fmt.Errorf("计划命令列表无效"))
		}
		for _, v := range values {
			if _, ok := v.(string); !ok {
				return a.fail(fmt.Errorf("计划命令列表无效"))
			}
		}
	}
	change, e := vxlan.NewChangePlan(object(plan["change"]))
	if e != nil || !reflect.DeepEqual(change.Commands(), texts(plan["commands"])) || !reflect.DeepEqual(change.Rollback(), texts(plan["rollback"])) {
		return a.fail(fmt.Errorf("计划命令被修改或参数无效"))
	}
	token := "APPLY " + host + " " + hash[:12] + " " + id
	if _, e = fmt.Fprintf(a.Output, "目标：%s（%s）；%s；%s\n影响：%s\n条件：%s\n计划 SHA256：%s\n拟执行命令：\n%s\n条件回退（不自动执行）：\n%s\n确认业务策略及维护窗口后输入 %s；其他输入取消：", device["name"], host, plan["scope"], plan["title"], plan["impact"], strings.Join(texts(plan["prerequisites"]), "；"), hash, strings.Join(change.Commands(), "\n"), strings.Join(change.Rollback(), "\n"), token); e != nil {
		return 2
	}
	line, e := readLineContext(ctx, a.Input)
	if e != nil || strings.TrimSpace(line) != token {
		fmt.Fprintln(a.Output, "已取消，未连接设备。")
		return 1
	}
	cfg, e := LoadConfig(ConfigOptions{CWD: a.CWD, Home: a.Home, Program: a.Program, Directories: a.Directories, Environment: a.Environment, EnvFile: flagString(f, "env-file"), AllowMissing: true, EnvironmentOnly: true})
	if e != nil {
		return a.fail(fmt.Errorf("凭据配置无法读取"))
	}
	settings, e := credentials(cfg)
	if e != nil {
		return a.fail(e)
	}
	settings.Host = host
	settings.Port = port
	settings.HostKeyPolicy = "strict"
	r, e := NewReport(absolute(flagString(f, "directory"), a.CWD, a.Home))
	if e != nil {
		return a.fail(e)
	}
	state := M{"status": "confirmed", "device": device, "plan_sha256": hash, "plan_item": id, "expected_config_sha256": plan["expected_config_sha256"], "commands": plan["commands"], "steps": []any{}}
	if e = r.Publish("execution.json", jsonBytes(state)); e != nil {
		return a.fail(e)
	}
	started, opened, verified := false, false, false
	e = a.Open(settings)(ctx, func(ctx context.Context, session vxlan.Session) error {
		if opened {
			return fmt.Errorf("session_reentered")
		}
		opened = true
		readConfig := func() (M, error) {
			for _, cmd := range []string{"terminal length 0", "terminal width 511"} {
				c, e := session.Read(ctx, cmd)
				if e != nil || !c.Complete {
					return nil, fmt.Errorf("配置读取准备失败")
				}
			}
			capture, e := session.Read(ctx, "show running-config")
			if e != nil || !capture.Complete {
				return nil, fmt.Errorf("配置回读失败")
			}
			o := vxlan.ParseConfig(capture.Body, true)
			if !o.Complete() || len(o.Records) != 1 {
				return nil, fmt.Errorf("配置证据不完整")
			}
			return normalize(o.Records[0]), nil
		}
		before, e := readConfig()
		if e != nil {
			return e
		}
		if vxlan.Fingerprint(before) != plan["expected_config_sha256"] || !change.Eligible(before) {
			return fmt.Errorf("配置已变化或前提不满足")
		}
		writer, ok := session.(interface {
			Write(context.Context, string) error
		})
		if !ok {
			return fmt.Errorf("会话不支持配置写入")
		}
		for i, cmd := range change.Commands() {
			if e = ctx.Err(); e != nil {
				return e
			}
			state["status"] = "executing"
			state["pending_command"] = i
			if e = r.Publish("execution.json", jsonBytes(state)); e != nil {
				return e
			}
			started = true
			if e = writer.Write(ctx, cmd); e != nil {
				return fmt.Errorf("设备命令未确认")
			}
			state["steps"] = append(list(state["steps"]), M{"index": i, "status": "acknowledged"})
			delete(state, "pending_command")
			if e = r.Publish("execution.json", jsonBytes(state)); e != nil {
				return e
			}
		}
		after, e := readConfig()
		if e != nil {
			return e
		}
		if !change.Satisfied(after, before) {
			return fmt.Errorf("配置验收未通过")
		}
		state["observed_config_sha256"] = vxlan.Fingerprint(after)
		verified = true
		return nil
	})
	if e == nil && !verified {
		e = fmt.Errorf("会话未完成配置验证")
	}
	if e != nil || ctx.Err() != nil {
		state["status"] = "failed"
		if started {
			state["status"] = "uncertain"
		}
		state["error"] = "execution_failed"
		if ctx.Err() != nil {
			state["error"] = "interrupted"
		}
		if r.Publish("execution.json", jsonBytes(state)) != nil {
			fmt.Fprintln(a.Error, "执行日志收尾未确认；保留已有检查点，禁止重放配置。")
		}
		fmt.Fprintln(a.Error, "下发停止；效果未完整确认，先回读核对，不自动重放或回退。")
		if ctx.Err() != nil {
			return 130
		}
		return 2
	}
	state["status"] = "configuration_verified"
	if e = r.Publish("execution.json", jsonBytes(state)); e != nil {
		state["status"] = "uncertain"
		state["error"] = "execution_finalization_unconfirmed"
		_ = r.Publish("execution.json", jsonBytes(state))
		return a.fail(e)
	}
	if _, e = fmt.Fprintf(a.Output, "配置回读已确认；仍需完成业务验收，未执行保存配置。日志：%s/execution.json\n", r.Directory); e != nil {
		return 2
	}
	return 0
}
