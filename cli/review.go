package cli

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	vxlan "github.com/gatework/go-vxlan"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func normalize(v any) M {
	b, _ := json.Marshal(v)
	m, _ := decodeDocument(b)
	if m == nil {
		return M{}
	}
	return m
}
func adviceFor(doc M, scripts bool, additions []vxlan.Record) M {
	advice := normalize(vxlan.CombineRecommendations(vxlan.Recommendations(doc), additions))
	if !scripts {
		for _, x := range list(advice["items"]) {
			m := object(x)
			delete(m, "change")
			delete(m, "template")
			m["commands"] = []string{}
			m["rollback"] = []string{}
		}
	}
	return advice
}
func validateDocument(doc M) error {
	d, ok := doc["device"].(map[string]any)
	if !ok {
		return fmt.Errorf("无设备身份")
	}
	host := str(d["host"])
	ip, e := netip.ParseAddr(host)
	if e != nil || ip.String() != host || str(d["name"]) == "" {
		return fmt.Errorf("设备身份无效")
	}
	v, ok := doc["snapshot"]
	if !ok {
		return fmt.Errorf("无快照字段")
	}
	if v == nil {
		return nil
	}
	snap, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("快照结构错误")
	}
	dims, ok := snap["dimensions"].(map[string]any)
	if !ok {
		return fmt.Errorf("观测结构错误")
	}
	if target, ok := snap["target"]; ok && str(object(target)["host"]) != host {
		return fmt.Errorf("设备与快照身份不一致")
	}
	for name, value := range dims {
		o, ok := value.(map[string]any)
		if !ok || !contains([]string{"complete", "partial", "failed", "unsupported", "not_requested"}, str(o["status"])) {
			return fmt.Errorf("观测状态无效")
		}
		rows, ok := o["records"].([]any)
		if !ok {
			return fmt.Errorf("观测记录须为数组")
		}
		if issues, ok := o["issues"]; ok {
			if _, ok = issues.([]any); !ok {
				return fmt.Errorf("诊断须为数组")
			}
			for _, x := range list(issues) {
				if _, ok = x.(map[string]any); !ok {
					return fmt.Errorf("诊断须为记录")
				}
			}
		}
		for _, row := range rows {
			r, ok := row.(map[string]any)
			if !ok {
				return fmt.Errorf("观测记录无效")
			}
			if name == "configuration" {
				if e := validateConfigurationRecord(r); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
func validateConfigurationRecord(r M) error {
	records := func(v any) error {
		a, ok := v.([]any)
		if !ok {
			return fmt.Errorf("配置列表无效")
		}
		for _, x := range a {
			if _, ok := x.(map[string]any); !ok {
				return fmt.Errorf("配置条目无效")
			}
		}
		return nil
	}
	if v, ok := r["review_findings"]; ok {
		if e := records(v); e != nil {
			return e
		}
	}
	for _, x := range object(r["evpn"]) {
		if v, ok := object(x)["route_targets"]; ok {
			if e := records(v); e != nil {
				return e
			}
		}
	}
	hashes := func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("配置映射无效")
		}
		for _, x := range m {
			if _, ok = x.(map[string]any); !ok {
				return fmt.Errorf("配置记录无效")
			}
		}
		return nil
	}
	for _, k := range []string{"interfaces", "vrfs", "evpn"} {
		if v, ok := r[k]; ok {
			if e := hashes(v); e != nil {
				return e
			}
		}
	}
	for _, k := range []string{"nve", "vlan_vnis", "acls", "address_groups"} {
		if v, ok := r[k]; ok {
			if _, ok = v.(map[string]any); !ok {
				return fmt.Errorf("配置容器无效")
			}
		}
	}
	if v, ok := object(r["nve"])["members"]; ok {
		if e := hashes(v); e != nil {
			return e
		}
	}
	for _, x := range object(r["interfaces"]) {
		v := object(x)
		if a, ok := v["addresses"]; ok {
			if list(a) == nil {
				return fmt.Errorf("接口地址无效")
			}
			for _, addr := range list(a) {
				if _, e := netip.ParsePrefix(str(addr)); e != nil {
					return fmt.Errorf("接口地址无效")
				}
			}
		}
		if b, ok := v["acl_bindings"]; ok {
			m, ok := b.(map[string]any)
			if !ok {
				return fmt.Errorf("ACL 绑定无效")
			}
			for direction, name := range m {
				if !contains([]string{"in", "out"}, direction) || str(name) == "" {
					return fmt.Errorf("ACL 绑定无效")
				}
			}
		}
	}
	for _, v := range object(r["acls"]) {
		if list(v) == nil {
			return fmt.Errorf("ACL 规则无效")
		}
		for _, x := range list(v) {
			entry, ok := x.(map[string]any)
			if !ok || !contains([]string{"permit", "deny", "remark"}, str(entry["action"])) || !integerInRange(entry["sequence"], 1, 4294967295) {
				return fmt.Errorf("ACL 规则无效")
			}
			if _, ok := entry["expression"].(string); !ok {
				return fmt.Errorf("ACL 表达式无效")
			}
		}
	}
	for _, v := range object(r["address_groups"]) {
		if list(v) == nil {
			return fmt.Errorf("地址组无效")
		}
		for _, x := range list(v) {
			p, e := netip.ParsePrefix(str(x))
			if e != nil || !p.Addr().Is4() {
				return fmt.Errorf("地址组成员无效")
			}
		}
	}
	return nil
}

type reviewSource struct {
	Path     string
	Body     []byte
	Document M
}

func (a *App) review(args []string) int {
	f := a.flags("review")
	for _, k := range []string{"batch", "output", "fabric-policy"} {
		f.String(k, "", "批次或输出路径")
	}
	f.Bool("scripts", false, "导出候选配置")
	f.Bool("no-scripts", false, "不导出候选配置")
	if e := f.Parse(args); e != nil {
		return a.fail(e)
	}
	if flagBool(f, "help") {
		fmt.Fprintln(a.Output, "用法：vxlan review --batch DIR [--output DIR] [--scripts]\n"+f.FlagUsages())
		return 0
	}
	if f.NArg() != 0 || flagString(f, "batch") == "" {
		return a.fail(fmt.Errorf("需要 --batch DIR"))
	}
	batch := absolute(flagString(f, "batch"), a.CWD, a.Home)
	sources, e := readSources(batch)
	if e != nil {
		return a.fail(e)
	}
	var policy M
	if p := flagString(f, "fabric-policy"); p != "" {
		policy, e = readYAML(absolute(p, a.CWD, a.Home))
		if e != nil {
			return a.fail(e)
		}
		if e = vxlan.ValidateFabricPolicy(policy); e != nil {
			return a.fail(e)
		}
	}
	out := flagString(f, "output")
	if out == "" {
		out = filepath.Join(batch, "reviews")
	}
	r, e := NewReport(absolute(out, a.CWD, a.Home))
	if e != nil {
		return a.fail(e)
	}
	_, e = buildReview(r, sources, policy, flagBool(f, "scripts") && !flagBool(f, "no-scripts"), true)
	if e != nil {
		return a.fail(e)
	}
	fmt.Fprintf(a.Output, "建议已生成：%s/summary.txt；%d 台；未执行设备变更。\n", r.Directory, len(sources))
	return 0
}
func readSources(batch string) ([]reviewSource, error) {
	paths, e := filepath.Glob(filepath.Join(batch, "evidence", "*.json"))
	if e != nil || len(paths) == 0 {
		return nil, fmt.Errorf("无设备报告")
	}
	sort.Strings(paths)
	sources := []reviewSource{}
	hosts, names := map[string]bool{}, map[string]bool{}
	for _, p := range paths {
		body, e := os.ReadFile(p)
		if e != nil {
			return nil, e
		}
		doc, e := decodeDocument(body)
		if e != nil {
			return nil, fmt.Errorf("证据 JSON 无效")
		}
		if e = validateDocument(doc); e != nil {
			return nil, e
		}
		device := object(doc["device"])
		host, name := str(device["host"]), basename(device)
		if hosts[host] || names[name] {
			return nil, fmt.Errorf("设备身份或输出名重复")
		}
		hosts[host], names[name] = true, true
		sources = append(sources, reviewSource{p, body, doc})
	}
	return sources, nil
}
func buildReview(r *Report, sources []reviewSource, policy M, scripts, standalone bool) (M, error) {
	documents := []vxlan.Record{}
	for _, s := range sources {
		documents = append(documents, s.Document)
	}
	var fabric M
	if policy != nil {
		audit, e := vxlan.ReviewFabric(documents, policy)
		if e != nil {
			return nil, e
		}
		fabric = normalize(audit)
	}
	entries, audits, events := []any{}, []any{}, []string{}
	changes := M{}
	totals := M{}
	for _, src := range sources {
		device := object(src.Document["device"])
		additions := []vxlan.Record{}
		for _, x := range list(object(fabric["device_items"])[str(device["host"])]) {
			additions = append(additions, object(x))
		}
		advice := adviceFor(src.Document, scripts, additions)
		sourceHash := fmt.Sprintf("%x", sha256.Sum256(src.Body))
		advice["source"], advice["source_sha256"] = src.Path, sourceHash
		name := basename(device)
		entry := M{"device": device, "counts": advice["counts"], "basename": name, "report": "devices/" + name + ".txt", "source": src.Path, "source_sha256": sourceHash, "script": nil, "script_sha256": nil, "plans": []string{}}
		config := vxlan.CompleteConfig(src.Document)
		scriptLines := []string{"! 候选配置，未执行；禁止整批直接粘贴。", "! apply 只读取 plan.json 中明确选择的单项。"}
		candidates := 0
		for _, x := range list(advice["items"]) {
			item := object(x)
			if scripts && config != nil && item["status"] == "candidate" && item["change"] != nil {
				plan := vxlan.CandidateChangePlan(object(item["change"]), config)
				if plan != nil {
					change := plan.Change()
					parts := []string{name, str(change["kind"]), fmt.Sprintf("vlan%d", int(number(change["vlan"])))}
					if direction := str(change["direction"]); direction != "" {
						parts = append(parts, direction)
					}
					parts = append(parts, vxlan.Fingerprint(change)[:12])
					id := strings.Join(parts, "--")
					changes[id] = M{"schema_version": 1, "platform": "cisco_nxos", "device": device, "expected_config_sha256": vxlan.Fingerprint(config), "source": src.Path, "source_sha256": sourceHash, "change": change, "commands": plan.Commands(), "rollback": plan.Rollback(), "scope": item["scope"], "title": item["title"], "prerequisites": item["prerequisites"], "impact": item["impact"], "verify": item["verify"]}
					item["plan_id"] = id
					entry["plans"] = append(texts(entry["plans"]), id)
				}
			}
			if scripts && item["status"] == "candidate" && len(texts(item["commands"])) > 0 {
				candidates++
				scriptLines = append(scriptLines, "", "! "+str(item["scope"])+" / "+str(item["title"]))
				for _, p := range texts(item["prerequisites"]) {
					scriptLines = append(scriptLines, "! 条件："+p)
				}
				scriptLines = append(scriptLines, texts(item["commands"])...)
				scriptLines = append(scriptLines, "! 条件回退（不自动执行）：")
				for _, cmd := range texts(item["rollback"]) {
					scriptLines = append(scriptLines, "! "+cmd)
				}
			}
		}
		if candidates > 0 {
			body := []byte(strings.Join(scriptLines, "\n") + "\n")
			entry["script"] = "scripts/" + name + ".cfg"
			entry["script_sha256"] = fmt.Sprintf("%x", sha256.Sum256(body))
			if e := r.Publish(str(entry["script"]), body); e != nil {
				return nil, e
			}
		}
		text := fmt.Sprintf("设备：%s（%s）\n模式：诊断与计划，未执行设备配置\n来源：%s\n源文件 SHA256：%s\n命令文件：%v\n", device["name"], device["host"], src.Path, sourceHash, entry["script"])
		for i, x := range list(advice["items"]) {
			item := object(x)
			text += fmt.Sprintf("\n%d. %s — %s\n状态：%s；规则：%s\n影响：%s\n", i+1, item["scope"], item["title"], item["status"], item["code"], item["impact"])
			for _, key := range []string{"evidence", "prerequisites", "blockers", "commands", "rollback", "verify", "expected", "plan_id"} {
				if v, ok := item[key]; ok {
					text += key + "：\n" + string(jsonBytes(v))
				}
			}
		}
		if e := r.Publish(str(entry["report"]), []byte(text)); e != nil {
			return nil, e
		}
		for k, v := range object(advice["counts"]) {
			n, _ := totals[k].(int)
			totals[k] = n + int(number(v))
		}
		entries = append(entries, entry)
		audits = append(audits, advice)
		event, _ := json.Marshal(M{"event": "device_reviewed", "host": device["host"], "source_sha256": sourceHash, "counts": advice["counts"], "report": entry["report"], "script": entry["script"], "executed": false})
		events = append(events, string(event))
	}
	auditPublic := merge(fabric)
	delete(auditPublic, "device_items")
	var fabricValue any
	if fabric != nil {
		fabricValue = auditPublic
	}
	plan := M{"schema_version": 2, "platform": "cisco_nxos", "mode": "review", "devices": entries, "audits": audits, "changes": changes, "fabric": fabricValue}
	body := jsonBytes(plan)
	summary := M{"layout_version": 3, "mode": "review", "status": "incomplete", "review_only": true, "devices": len(entries), "counts": totals, "reports": entries, "plan": "plan.json", "plan_sha256": fmt.Sprintf("%x", sha256.Sum256(body)), "fabric_findings": len(list(fabric["findings"]))}
	if len(sources) > 0 {
		summary["source_batch"] = filepath.Dir(filepath.Dir(sources[0].Path))
	}
	if standalone {
		if e := r.Publish("summary.json", jsonBytes(summary)); e != nil {
			return nil, e
		}
	}
	for _, artifact := range []struct {
		name string
		body []byte
	}{{"plan.json", body}, {"plan.json.sha256", []byte(str(summary["plan_sha256"]) + "\n")}, {"events.jsonl", []byte(strings.Join(events, "\n") + "\n")}} {
		if e := r.Publish(artifact.name, artifact.body); e != nil {
			return nil, e
		}
	}
	if standalone {
		text := "VXLAN 诊断与配置建议；未执行设备变更。\n完整状态以 summary.json 为准；证据完整性不代表网络健康。\n阅读顺序：summary.txt → devices/ → scripts/ → plan.json 指定单项。\n" + string(jsonBytes(summary))
		if fabric != nil {
			text += "Fabric 共同业务一致性\n" + string(jsonBytes(auditPublic))
		}
		if e := r.Publish("summary.txt", []byte(text)); e != nil {
			return nil, e
		}
		checkpoint := jsonBytes(summary)
		summary["status"] = "complete"
		if e := r.Publish("summary.json", jsonBytes(summary)); e != nil {
			if r.Publish("summary.json", checkpoint) != nil {
				r.invalidate()
			}
			return nil, e
		}
	}
	summary["status"] = "complete"
	return summary, nil
}
