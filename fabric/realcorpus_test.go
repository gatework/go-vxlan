package fabric_test

import (
	"cmp"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gatework/go-netops/evidence"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

// realCorpus returns the operator-supplied directory of "show running-config"
// captures (*.txt), or skips. Device data never enters the repository; only
// aggregate statistics are logged.
func realCorpus(t *testing.T) []string {
	t.Helper()
	dir := os.Getenv("VXLAN_REAL_CORPUS")
	if dir == "" {
		t.Skip("set VXLAN_REAL_CORPUS to a directory of NX-OS running-config captures")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var nxosFiles []string
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "\nfeature nv overlay") {
			nxosFiles = append(nxosFiles, f)
		}
	}
	if len(nxosFiles) == 0 {
		t.Skip("no NX-OS VXLAN configurations in corpus")
	}
	return nxosFiles
}

// configText strips the capture preamble before "!Command: show running-config".
func configText(body string) string {
	if i := strings.Index(body, "!Command: show running-config"); i >= 0 {
		return body[i:]
	}
	return body
}

func TestRealConfigurationsAreModeled(t *testing.T) {
	files := realCorpus(t)
	statuses := map[string]int{}
	issues := map[string]int{}
	unsupported := map[string]int{}
	for _, f := range files {
		body, _ := os.ReadFile(f)
		text := configText(string(body))
		o, err := nxos.ParseConfigChecked(text, true)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
			continue
		}
		statuses[o.Status]++
		d := fabric.NewDevice(fabric.Identity{Host: "192.0.2.1"}, map[evidence.Dimension]fabric.Observed{fabric.DimConfiguration: observed(t, o)})
		if len(o.Records) == 1 {
			if err := lossless(generic(t, o.Records[0]), generic(t, d.Configuration), "configuration"); err != nil {
				t.Errorf("real configuration not decoded losslessly: %v", err)
			}
		}
		for _, i := range d.Issues[fabric.DimConfiguration] {
			issues[i.Code]++
			if i.Code == fabric.IssueUnmodeled {
				t.Errorf("%s: unmodeled fact: %s", filepath.Base(f), i.Detail)
			}
			if i.Code == "unsupported_configuration" && i.Line > 0 {
				lines := strings.Split(text, "\n")
				if i.Line <= len(lines) {
					unsupported[statementKind(lines[i.Line-1])]++
				}
			}
		}
	}
	t.Logf("configurations: %d, statuses: %v", len(files), statuses)
	t.Logf("issue codes: %v", issues)
	type kv struct {
		k string
		n int
	}
	var top []kv
	for k, n := range unsupported {
		top = append(top, kv{k, n})
	}
	slices.SortFunc(top, func(a, b kv) int { return cmp.Or(b.n-a.n, strings.Compare(a.k, b.k)) })
	for _, e := range top[:min(40, len(top))] { // kinds only, never values
		t.Logf("unsupported %5d  %s", e.n, e.k)
	}
}

// statementKind reduces a configuration line to its first keywords, so
// statistics never carry addresses, names or secrets.
func statementKind(line string) string {
	var words []string
	for _, w := range strings.Fields(line) {
		// Two keywords at most: a third word can be a name or secret.
		if len(words) == 2 || strings.ContainsAny(w, "0123456789./:") {
			break
		}
		words = append(words, w)
	}
	return strings.Join(words, " ")
}

func TestRealConfigurationCoverage(t *testing.T) {
	files := realCorpus(t)
	byState := map[nxos.LineState]map[string]int{}
	totals := map[nxos.LineState]int{}
	for _, f := range files {
		body, _ := os.ReadFile(f)
		var p nxos.ConfigurationParser
		if _, err := p.Parse(configText(string(body)), true); err != nil {
			t.Fatal(err)
		}
		doc := p.Document()
		lines := doc.Lines()
		for i, st := range doc.States() {
			totals[st]++
			if st == nxos.LineParsed {
				continue
			}
			if byState[st] == nil {
				byState[st] = map[string]int{}
			}
			byState[st][statementKind(lines[i].Text())]++
		}
	}
	t.Logf("line states: %v", totals)
	for _, st := range slices.Sorted(maps.Keys(byState)) {
		kinds := byState[st]
		keys := slices.SortedFunc(maps.Keys(kinds), func(a, b string) int { return cmp.Or(kinds[b]-kinds[a], strings.Compare(a, b)) })
		for _, k := range keys[:min(120, len(keys))] {
			t.Logf("%-11s %6d  %s", st, kinds[k], k)
		}
	}
	_ = fmt.Sprint
}
