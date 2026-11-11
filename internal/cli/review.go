package cli

import (
	"context"

	"fmt"
	"path/filepath"

	"github.com/gatework/go-netops/assess"

	"github.com/spf13/pflag"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/internal/bootstrap"
	"github.com/gatework/go-vxlan/internal/workflow"
	"github.com/gatework/go-vxlan/report"
)

func (a *App) review(ctx context.Context, f *pflag.FlagSet) int {
	if flagBool(f, "help") {
		fmt.Fprintln(a.Output, "用法：vxlan review --batch DIR [--output DIR] [--fabric-policy FILE] [--rules-policy FILE] [--baseline FILE] [--previous DIR] [--scripts]\n"+f.FlagUsages())
		return 0
	}
	if f.NArg() != 0 || flagString(f, "batch") == "" {
		return a.fail(fmt.Errorf("需要 --batch DIR"))
	}
	batch := bootstrap.Absolute(flagString(f, "batch"), a.CWD, a.Home)
	sources, e := report.ReadSources(ctx, batch)
	if e != nil {
		return a.fail(e)
	}
	var policy vxlan.Record
	if p := flagString(f, "fabric-policy"); p != "" {
		policy, e = bootstrap.ReadYAML(ctx, bootstrap.Absolute(p, a.CWD, a.Home))
		if e != nil {
			return a.fail(e)
		}
		if e = fabric.ValidatePolicyDocument(policy); e != nil {
			return a.fail(e)
		}
	}
	var rulesPolicy assess.Policy
	if p := flagString(f, "rules-policy"); p != "" {
		rulesPolicy, e = bootstrap.ReadRulesPolicy(ctx, bootstrap.Absolute(p, a.CWD, a.Home))
		if e != nil {
			return a.fail(e)
		}
	}
	var baseline *fabric.Baseline
	if p := flagString(f, "baseline"); p != "" {
		if baseline, e = bootstrap.ReadBaseline(ctx, bootstrap.Absolute(p, a.CWD, a.Home)); e != nil {
			return a.fail(e)
		}
	}
	var previous []report.Source
	if p := flagString(f, "previous"); p != "" {
		if previous, e = report.ReadSources(ctx, bootstrap.Absolute(p, a.CWD, a.Home)); e != nil {
			return a.fail(e)
		}
	}
	out := flagString(f, "output")
	if out == "" {
		out = filepath.Join(batch, "reviews")
	}
	r, e := report.New(bootstrap.Absolute(out, a.CWD, a.Home))
	if e != nil {
		return a.fail(e)
	}
	queries, e := a.profiles.Fetch("cisco_nxos", "")
	if e != nil {
		return a.fail(e)
	}
	_, e = workflow.Review(ctx, r, workflow.ReviewOptions{Sources: sources, Policy: policy, Rules: rulesPolicy, Baseline: baseline, Previous: previous, Queries: queries, Scripts: flagBool(f, "scripts") && !flagBool(f, "no-scripts"), Standalone: true})
	if e != nil {
		return a.fail(e)
	}
	fmt.Fprintf(a.Output, "建议已生成：%s/summary.txt；%d 台；未执行设备变更。\n", r.Directory, len(sources))
	return 0
}
