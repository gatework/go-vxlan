package workflow

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/gatework/go-netops/assess"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/rules"
)

type plannedIncrement struct {
	id  string
	inc rules.Increment
}

// subjectMentions reports whether a subject path names the device.
func subjectMentions(s assess.Subject, host string) bool {
	for cur := &s; cur != nil; cur = cur.Parent {
		if (cur.Kind == "device" || cur.Kind == "controller") && cur.Key == host {
			return true
		}
	}
	return false
}

// deviceFindings collects every finding about one device: its own rules and
// the fabric, baseline and change findings that name it, highest risk first.
func deviceFindings(r rules.Report, host string) []assess.Finding {
	var out []assess.Finding
	for _, d := range append(slices.Clone(r.Devices), r.Changes...) {
		if d.Device.Host == host {
			out = append(out, d.Assessment.Findings...)
		}
	}
	for _, f := range append(slices.Clone(r.Fabrics), r.Baseline...) {
		for _, finding := range f.Assessment.Findings {
			if subjectMentions(finding.Subject, host) {
				out = append(out, finding)
			}
		}
	}
	slices.SortStableFunc(out, func(a, b assess.Finding) int {
		return cmp.Or(cmp.Compare(b.Severity, a.Severity), cmp.Compare(a.Rule, b.Rule), cmp.Compare(a.Subject.String(), b.Subject.String()))
	})
	return out
}

func severityCounts(findings []assess.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		out[f.Severity.String()]++
	}
	return out
}

func countsText(counts map[assess.Severity]int) string {
	var parts []string
	for _, s := range assess.Severities() {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", s, n))
		}
	}
	if len(parts) == 0 {
		return "无发现项"
	}
	return strings.Join(parts, "，")
}

func compact(v any) string {
	if v == nil {
		return ""
	}
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(body)
}

// deviceReport renders one device's findings for the operator.
func deviceReport(device, entry vxlan.Record, findings []assess.Finding, planned []plannedIncrement) string {
	var b strings.Builder
	fmt.Fprintf(&b, "设备：%v（%v）\n模式：诊断与计划，未执行设备配置\n来源：%v\n源文件 SHA256：%v\n命令文件：%v\n", device["name"], device["host"], entry["source"], entry["source_sha256"], entry["script"])
	counts := map[assess.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(&b, "风险：%s；可执行增量 %d 项\n证据完整性不代表网络健康；证据不完整的规则不会给出结论。\n", countsText(counts), len(planned))
	for i, f := range findings {
		fmt.Fprintf(&b, "\n%d. [%s] %s\n对象：%s\n规则：%s（%s）\n", i+1, strings.ToUpper(f.Severity.String()), f.Title, f.Subject.String(), f.Rule, f.Category)
		if f.Detail != "" {
			fmt.Fprintf(&b, "说明：%s\n", f.Detail)
		}
		if f.Expected != nil || f.Actual != nil {
			fmt.Fprintf(&b, "期望：%s\n实际：%s\n", compact(f.Expected), compact(f.Actual))
		}
		if len(f.Verify) > 0 {
			fmt.Fprintf(&b, "复核：%s\n", strings.Join(f.Verify, "；"))
		}
		if r := f.Remediation; r != nil {
			fmt.Fprintf(&b, "修复：%s\n", r.Status)
			for _, p := range r.Prerequisites {
				fmt.Fprintf(&b, "  前提：%s\n", p)
			}
			for _, x := range r.Blockers {
				fmt.Fprintf(&b, "  阻断：%s\n", x)
			}
			if r.Impact != "" {
				fmt.Fprintf(&b, "  影响：%s\n", r.Impact)
			}
		}
	}
	for _, p := range planned {
		fmt.Fprintf(&b, "\n可执行增量 %s\n范围：%s / %s\n", p.id, p.inc.Scope, p.inc.Title)
	}
	return b.String()
}

// candidateScript renders executable increments as a reviewable script that
// is never executed directly.
func candidateScript(planned []plannedIncrement) string {
	lines := []string{"! 候选配置，未执行；禁止整批直接粘贴。", "! apply 只读取 plan.json 中明确选择的单项。"}
	for _, p := range planned {
		lines = append(lines, "", "! "+p.inc.Scope+" / "+p.inc.Title, "! plan item: "+p.id)
		for _, pre := range p.inc.Prerequisites {
			lines = append(lines, "! 条件："+pre)
		}
		lines = append(lines, p.inc.Script...)
		lines = append(lines, "! 条件回退（不自动执行）：")
		for _, cmd := range p.inc.Undo {
			lines = append(lines, "! "+cmd)
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// summaryText renders the review overview; summary.json and assessment.json
// are authoritative.
func summaryText(r rules.Report, devices, increments int) string {
	var b strings.Builder
	b.WriteString("VXLAN 风险评估与配置建议；未执行设备变更。\n完整状态以 summary.json 与 assessment.json 为准；证据完整性不代表网络健康。\n阅读顺序：summary.txt → devices/ → scripts/ → plan.json 指定单项。\n")
	fmt.Fprintf(&b, "\n设备 %d 台；风险：%s；可执行增量 %d 项\n", devices, countsText(r.Counts), increments)
	if r.Incomplete {
		b.WriteString("注意：部分规则因证据不完整未运行，未运行的规则不代表无风险。\n")
	}
	if len(r.Unassigned) > 0 {
		fmt.Fprintf(&b, "未纳入 Fabric 策略的设备：%s\n", strings.Join(r.Unassigned, "、"))
	}
	section := func(title string, fas []rules.FabricAssessment) {
		for _, fa := range fas {
			fmt.Fprintf(&b, "\n%s %s：成员 %d 台", title, fa.Name, len(fa.Members))
			if len(fa.Missing) > 0 {
				fmt.Fprintf(&b, "，缺少报告 %s", strings.Join(fa.Missing, "、"))
			}
			fmt.Fprintf(&b, "；%s\n", countsText(fa.Assessment.Counts))
			for _, f := range fa.Assessment.Findings {
				fmt.Fprintf(&b, "  [%s] %s — %s\n", strings.ToUpper(f.Severity.String()), f.Title, f.Subject.String())
			}
		}
	}
	section("Fabric", r.Fabrics)
	section("基线", r.Baseline)
	if len(r.Appeared)+len(r.Disappeared) > 0 {
		fmt.Fprintf(&b, "\n与上一批次相比：新增 %s；消失 %s\n", strings.Join(r.Appeared, "、"), strings.Join(r.Disappeared, "、"))
	}
	return b.String()
}
