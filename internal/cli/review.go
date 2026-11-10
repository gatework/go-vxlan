package cli

import (
	"context"

	"fmt"
	"github.com/gatework/go-netops/assess"
	"path/filepath"

	"github.com/spf13/pflag"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/bootstrap"
	"github.com/gatework/go-vxlan/internal/workflow"
	"github.com/gatework/go-vxlan/report"
	reviewpkg "github.com/gatework/go-vxlan/review"
)

func (a *App) review(ctx context.Context, f *pflag.FlagSet) int {
	if flagBool(f, "help") {
		fmt.Fprintln(a.Output, "用法：vxlan review --batch DIR [--output DIR] [--fabric-policy FILE] [--rules-policy FILE] [--scripts]\n"+f.FlagUsages())
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
		if e = reviewpkg.ValidateFabricPolicy(policy); e != nil {
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
	_, e = workflow.Review(ctx, r, workflow.ReviewOptions{Sources: sources, Policy: policy, Rules: rulesPolicy, Queries: queries, Scripts: flagBool(f, "scripts") && !flagBool(f, "no-scripts"), Standalone: true})
	if e != nil {
		return a.fail(e)
	}
	fmt.Fprintf(a.Output, "建议已生成：%s/summary.txt；%d 台；未执行设备变更。\n", r.Directory, len(sources))
	return 0
}
