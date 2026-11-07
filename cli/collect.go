package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gatework/go-net-connector/connector"
	vxlan "github.com/gatework/go-vxlan"
)

func credentials(c Config) (connector.ConnectionConfig, error) {
	secret := func(vendor, general string) string {
		v := c.Environment[vendor]
		if strings.TrimSpace(v) == "" {
			v = c.Environment[general]
		}
		return v
	}
	username := secret("NC_CISCO_NXOS_USERNAME", "NC_DEVICE_USERNAME")
	if strings.TrimSpace(username) == "" {
		return connector.ConnectionConfig{}, fmt.Errorf("请设置 NC_DEVICE_USERNAME 或 NC_CISCO_NXOS_USERNAME")
	}
	ssh := object(c.Values["ssh"])
	port := 22
	if v, ok := ssh["port"]; ok {
		port = int(number(v))
	}
	return connector.ConnectionConfig{
		Username:       username,
		Password:       secret("NC_CISCO_NXOS_PASSWORD", "NC_DEVICE_PASSWORD"),
		EnablePassword: c.Environment["NC_ENABLE_PASSWORD"],
		Protocol:       connector.ProtocolSSH,
		Port:           port,
		HostKeyPolicy:  connector.HostKeyPolicy(str(ssh["host_key_policy"])),
		KnownHosts:     str(ssh["known_hosts"]),
		LoginTimeout:   time.Duration(number(ssh["login_timeout"]) * float64(time.Second)),
		CommandTimeout: time.Duration(number(ssh["command_timeout"]) * float64(time.Second)),
	}, nil
}
func (a *App) collect(ctx context.Context, args []string) int {
	f, c, e := a.collectFlags(args)
	if e != nil {
		return a.fail(e)
	}
	if flagBool(f, "help") || flagBool(f, "help-all") || flagBool(f, "examples") {
		fmt.Fprintln(a.Output, "用法：vxlan collect [选项]\n"+f.FlagUsages()+"维度："+strings.Join(vxlan.DimensionNames(), ", ")+"\n优先级：CLI > 进程环境 > YAML > .env > 默认。\n示例：vxlan collect --init --non-interactive\n      vxlan collect --name leaf --plan\n      vxlan collect --dimensions configuration,nve_peers --json\n凭据：NC_DEVICE_USERNAME/NC_DEVICE_PASSWORD，或 NC_CISCO_NXOS_USERNAME/NC_CISCO_NXOS_PASSWORD。\n退出码：0 完整/预览；1 未完成/无目标；2 参数/报告错误；130 取消。")
		return 0
	}
	if flagBool(f, "init") {
		if e = a.initialize(c, f); e != nil {
			return a.fail(e)
		}
		return 0
	}
	if handled, err := a.missingConfig(ctx, c, f); err != nil {
		return a.fail(err)
	} else if handled {
		return 0
	}
	if c.Policy != nil {
		if e = vxlan.ValidateFabricPolicy(c.Policy); e != nil {
			return a.fail(e)
		}
	}
	if flagBool(f, "show-config") {
		if e = a.json(merge(c.Values, M{"sources": c.Sources})); e != nil {
			return 2
		}
		return 0
	}
	quiet := flagBool(f, "quiet") || flagBool(f, "no-progress")
	outputFailed := false
	notice := func(format string, args ...any) {
		if !quiet {
			if _, err := fmt.Fprintf(a.Error, format, args...); err != nil {
				outputFailed = true
			}
		}
	}
	notice("读取清单…\n")
	devices, e := fetchInventory(ctx, c)
	if e != nil {
		return a.fail(fmt.Errorf("设备清单读取失败"))
	}
	if flagBool(f, "plan") || flagBool(f, "inventory-only") {
		if flagBool(f, "json") {
			e = a.json(devices)
		} else {
			for _, d := range devices {
				v := object(d)
				if _, err := fmt.Fprintf(a.Output, "%s\t%s\t%v\n", v["host"], v["name"], v["model"]); err != nil {
					e = err
				}
			}
		}
		if e != nil {
			return 2
		}
		if len(devices) == 0 {
			return 1
		}
		return 0
	}
	if len(devices) == 0 {
		notice("没有匹配设备，未建立连接。\n")
		if flagBool(f, "json") {
			if a.json(M{"status": "no_devices", "total": 0}) != nil {
				return 2
			}
		}
		return 1
	}
	settings, e := credentials(c)
	if e != nil {
		return a.fail(e)
	}
	workers := min(int(number(c.Values["parallel"])), len(devices))
	if e = prepareResources(ctx, workers); e != nil {
		return a.fail(fmt.Errorf("并发资源不足"))
	}
	names := map[string]bool{}
	for _, d := range devices {
		n := basename(object(d))
		if names[n] {
			return a.fail(fmt.Errorf("设备报告名称冲突"))
		}
		names[n] = true
	}
	r, e := NewReport(str(c.Values["directory"]))
	if e != nil {
		return a.fail(e)
	}
	notice("VXLAN 只读采集：%d 台，并发 %d\n", len(devices), workers)
	type outcome struct {
		result   M
		snapshot *vxlan.Snapshot
	}
	jobs := make(chan M)
	out := make(chan outcome, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for device := range jobs {
				if ctx.Err() != nil {
					return
				}
				func() {
					started := time.Now()
					result := M{"device": device, "status": "failed", "dimensions": M{}, "report_saved": false}
					var snapshot *vxlan.Snapshot
					defer func() {
						if recover() != nil {
							result["error"] = "collection_failed"
						}
						result["duration_ms"] = (time.Since(started) + 500*time.Microsecond) / time.Millisecond
						out <- outcome{result, snapshot}
					}()
					config := settings
					config.Host = str(device["host"])
					s, err := vxlan.Collect(ctx, a.Open(config), vxlan.Request{Target: device, FabricKey: c.Values["fabric"], Platform: "cisco_nxos", Model: str(device["model"]), Dimensions: texts(c.Values["dimensions"])})
					if err != nil {
						result["error"] = "collection_failed"
						return
					}
					snapshot = &s
					result["status"] = s.Dimensions["collection"].Status
					dims := M{}
					for name, o := range s.Dimensions {
						codes := []string{}
						seen := map[string]bool{}
						for _, issue := range o.Issues {
							code := str(issue["code"])
							if !seen[code] {
								codes = append(codes, code)
								seen[code] = true
							}
						}
						dims[name] = M{"status": o.Status, "records": len(o.Records), "issues": codes}
					}
					result["dimensions"] = dims
				}()
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, d := range devices {
			select {
			case jobs <- object(d):
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(out) }()
	results := []M{}
	failures := M{}
	scripts := flagBool(f, "scripts") && !flagBool(f, "no-scripts")
	for item := range out {
		res := item.result
		body := merge(res, M{"snapshot": item.snapshot})
		delete(body, "report_saved")
		doc := normalize(body)
		doc["recommendations"] = adviceFor(doc, scripts, nil)
		name := basename(object(res["device"]))
		if err := r.Publish("evidence/"+name+".json", jsonBytes(doc)); err != nil {
			failures["report_error"] = "device_report_failed"
		} else {
			text := fmt.Sprintf("设备：%s（%s）\n状态：%s\n证据完整性不代表 Fabric 健康。\n", object(res["device"])["name"], object(res["device"])["host"], res["status"]) + string(jsonBytes(doc["recommendations"]))
			if err = r.Publish("devices/"+name+".txt", []byte(text)); err != nil {
				failures["report_error"] = "device_report_failed"
			} else {
				res["report_saved"] = true
			}
		}
		results = append(results, res)
		if flagBool(f, "verbose") || len(results)%25 == 0 || len(results) == len(devices) {
			notice("采集 %d/%d：%s %s\n", len(results), len(devices), object(res["device"])["host"], res["status"])
		}
	}
	if len(results) > 0 {
		sources, err := readSources(r.Directory)
		if err == nil {
			review, err := buildReview(r, sources, c.Policy, scripts, false)
			if err != nil {
				failures["report_error"] = "review_report_failed"
			} else {
				r.Review = review
			}
		} else {
			failures["report_error"] = "review_evidence_failed"
		}
	}
	if outputFailed {
		failures["output_error"] = M{"error_type": "write_failed"}
	}
	summary, err := r.Finish(results, devices, ctx.Err() != nil, failures)
	if err != nil {
		if ctx.Err() != nil {
			return 130
		}
		return a.fail(err)
	}
	notice("报告：%s\n", filepath.Join(r.Directory, "summary.txt"))
	if flagBool(f, "json") {
		if err = a.json(summary); err != nil {
			failures["output_error"] = M{"error_type": "write_failed"}
			_, _ = r.Finish(results, devices, ctx.Err() != nil, failures)
			return 2
		}
	}
	if outputFailed && summary["output_error"] == nil {
		failures["output_error"] = M{"error_type": "write_failed"}
		_, _ = r.Finish(results, devices, ctx.Err() != nil, failures)
	}
	if ctx.Err() != nil {
		return 130
	}
	if len(failures) > 0 {
		return 2
	}
	if summary["status"] == "complete" {
		return 0
	}
	return 1
}
