package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/pflag"

	"github.com/gatework/go-net-connector/netdisco"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/bootstrap"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/internal/workflow"
)

func (a *App) collect(ctx context.Context, f *pflag.FlagSet) int {
	c, e := a.collectOptions(ctx, f)
	if e != nil {
		return a.fail(e)
	}
	if handled, code := a.collectConfigurationModes(ctx, c, f); handled {
		return code
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
	inventory, e := bootstrap.FetchInventory(ctx, c)
	if e != nil {
		if errors.Is(e, netdisco.ErrCacheRefreshRequired) {
			return a.fail(fmt.Errorf("设备清单缓存身份无法验证；请先使用 refresh 模式刷新清单"))
		}
		return a.fail(fmt.Errorf("设备清单读取失败"))
	}
	devices := inventory.Devices
	if inventory.Cache.RefreshErrorCode != "" || inventory.Cache.WriteErrorType != "" {
		notice("清单缓存：%s；刷新错误：%s；写入错误：%s\n", inventory.Cache.Status, inventory.Cache.RefreshErrorCode, inventory.Cache.WriteErrorType)
	}
	if flagBool(f, "plan") || flagBool(f, "inventory-only") {
		return a.inventoryPreview(f, devices)
	}
	if len(devices) == 0 {
		notice("没有匹配设备，未建立连接。\n")
		if flagBool(f, "json") {
			if a.json(vxlan.Record{"status": "no_devices", "total": 0}) != nil {
				return 2
			}
		}
		return 1
	}
	request, e := bootstrap.Collection(ctx, c, devices, a.Open)
	if e != nil {
		return a.fail(e)
	}
	request.Scripts = flagBool(f, "scripts") && !flagBool(f, "no-scripts")
	request.Verbose = flagBool(f, "verbose")
	request.Observe = func(event workflow.CollectionEvent) error {
		return a.collectionProgress(event, quiet, &outputFailed)
	}
	if flagBool(f, "json") {
		request.Deliver = func(value vxlan.Record) error { return a.json(value) }
	}
	if outputFailed {
		request.InitialOutputFailure = true
	}
	result := workflow.Collect(ctx, request)
	return a.collectionExit(result)
}

func (a *App) inventoryPreview(f *pflag.FlagSet, devices []any) int {
	var e error
	if flagBool(f, "json") {
		e = a.json(devices)
	} else {
		for _, d := range devices {
			v := record.Map(d)
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

func (a *App) collectConfigurationModes(ctx context.Context, c bootstrap.Config, f *pflag.FlagSet) (bool, int) {
	if flagBool(f, "help") || flagBool(f, "help-all") || flagBool(f, "examples") {
		profile, err := a.profiles.Fetch("cisco_nxos", "")
		if err != nil {
			return true, a.fail(err)
		}
		fmt.Fprintln(a.Output, "用法：vxlan collect [选项]\n"+f.FlagUsages()+"维度："+strings.Join(profile.Dimensions(), ", ")+"\n优先级：CLI > 进程环境 > YAML > .env > 默认。\n示例：vxlan collect --init --non-interactive\n      vxlan collect --name leaf --plan\n      vxlan collect --dimensions configuration,nve_peers --json\n凭据：NC_DEVICE_USERNAME/NC_DEVICE_PASSWORD，或 NC_CISCO_NXOS_USERNAME/NC_CISCO_NXOS_PASSWORD。\n退出码：0 完整/预览；1 未完成/无目标；2 参数/报告错误；130 取消。")
		return true, 0
	}
	if flagBool(f, "init") {
		if e := a.initialize(ctx, c, f); e != nil {
			return true, a.fail(e)
		}
		return true, 0
	}
	if handled, err := a.missingConfig(ctx, c, f); err != nil {
		return true, a.fail(err)
	} else if handled {
		return true, 0
	}
	if flagBool(f, "show-config") {
		if e := a.json(record.MergeLayers(c.Values, vxlan.Record{"sources": c.Sources})); e != nil {
			return true, 2
		}
		return true, 0
	}
	return false, 0
}

func (a *App) collectionProgress(event workflow.CollectionEvent, quiet bool, outputFailed *bool) error {
	if quiet {
		return nil
	}
	var err error
	switch event.Kind {
	case workflow.CollectionStarted:
		_, err = fmt.Fprintf(a.Error, "VXLAN 只读采集：%d 台，并发 %d\n", event.Total, event.Workers)
	case workflow.CollectionProgress:
		_, err = fmt.Fprintf(a.Error, "采集 %d/%d：%s %s\n", event.Current, event.Total, event.Device["host"], event.Status)
	case workflow.CollectionPublished:
		_, err = fmt.Fprintf(a.Error, "报告：%s\n", event.Path)
	}
	if err != nil {
		*outputFailed = true
	}
	return err
}

func (a *App) collectionExit(result workflow.CollectionResult) int {
	if result.Err != nil {
		return a.fail(result.Err)
	}
	switch result.State {
	case workflow.CollectionComplete:
		return 0
	case workflow.CollectionPartial:
		return 1
	case workflow.CollectionInterrupted:
		return 130
	default:
		return 2
	}
}
