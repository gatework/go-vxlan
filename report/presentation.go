package report

import (
	"context"
	"crypto/sha256"
	"fmt"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
	"strings"
)

// PublishReviewDevice renders review artifacts without constructing executable plans.
func (r *Report) PublishReviewDevice(ctx context.Context, advice, entry vxlan.Record, scripts bool) (vxlan.Record, error) {
	entry = record.Copy(entry).(vxlan.Record)
	device := record.Map(entry["device"])
	name := record.String(entry["basename"])
	sourceHash := record.String(entry["source_sha256"])
	scriptLines := []string{"! 候选配置，未执行；禁止整批直接粘贴。", "! apply 只读取 plan.json 中明确选择的单项。"}
	candidates := 0
	for _, x := range record.List(advice["items"]) {
		item := record.Map(x)
		if scripts && item["status"] == "candidate" && len(record.Texts(item["commands"])) > 0 {
			candidates++
			scriptLines = append(scriptLines, "", "! "+record.String(item["scope"])+" / "+record.String(item["title"]))
			for _, p := range record.Texts(item["prerequisites"]) {
				scriptLines = append(scriptLines, "! 条件："+p)
			}
			scriptLines = append(scriptLines, record.Texts(item["commands"])...)
			scriptLines = append(scriptLines, "! 条件回退（不自动执行）：")
			for _, cmd := range record.Texts(item["rollback"]) {
				scriptLines = append(scriptLines, "! "+cmd)
			}
		}
	}
	if candidates > 0 {
		body := []byte(strings.Join(scriptLines, "\n") + "\n")
		entry["script"] = "scripts/" + name + ".cfg"
		entry["script_sha256"] = fmt.Sprintf("%x", sha256.Sum256(body))
		if e := r.Publish(ctx, record.String(entry["script"]), body); e != nil {
			return nil, e
		}
	}
	text := fmt.Sprintf("设备：%s（%s）\n模式：诊断与计划，未执行设备配置\n来源：%s\n源文件 SHA256：%s\n命令文件：%v\n", device["name"], device["host"], entry["source"], sourceHash, entry["script"])
	for i, x := range record.List(advice["items"]) {
		item := record.Map(x)
		text += fmt.Sprintf("\n%d. %s — %s\n状态：%s；规则：%s\n影响：%s\n", i+1, item["scope"], item["title"], item["status"], item["code"], item["impact"])
		for _, key := range []string{"evidence", "prerequisites", "blockers", "commands", "rollback", "verify", "expected", "plan_id"} {
			if v, ok := item[key]; ok {
				encoded, err := EncodeJSON(v)
				if err != nil {
					return nil, err
				}
				text += key + "：\n" + string(encoded)
			}
		}
	}
	if e := r.Publish(ctx, record.String(entry["report"]), []byte(text)); e != nil {
		return nil, e
	}
	return entry, nil
}

// PublishReviewSummary renders human-readable review guidance; summary.json is authoritative.
func (r *Report) PublishReviewSummary(ctx context.Context, summary, audit vxlan.Record, hasFabric bool) error {
	encoded, err := EncodeJSON(summary)
	if err != nil {
		return err
	}
	text := "VXLAN 诊断与配置建议；未执行设备变更。\n完整状态以 summary.json 为准；证据完整性不代表网络健康。\n阅读顺序：summary.txt → devices/ → scripts/ → plan.json 指定单项。\n" + string(encoded)
	if hasFabric {
		encoded, err := EncodeJSON(audit)
		if err != nil {
			return err
		}
		text += "Fabric 共同业务一致性\n" + string(encoded)
	}
	if e := r.Publish(ctx, "summary.txt", []byte(text)); e != nil {
		return e
	}
	return nil
}

// PublishCollectionDevice persists accepted evidence before its human-readable report.
func (r *Report) PublishCollectionDevice(ctx context.Context, document, result vxlan.Record) error {
	device := record.Map(result["device"])
	name := Basename(device)
	if err := r.PublishJSON(ctx, "evidence/"+name+".json", document); err != nil {
		return err
	}
	encoded, err := EncodeJSON(document["recommendations"])
	if err != nil {
		return err
	}
	text := fmt.Sprintf("设备：%s（%s）\n状态：%s\n证据完整性不代表 Fabric 健康。\n", device["name"], device["host"], result["status"]) + string(encoded)
	return r.Publish(ctx, "devices/"+name+".txt", []byte(text))
}
