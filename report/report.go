package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
	"golang.org/x/sys/unix"
)

type Report struct {
	Directory     string
	SyncDirectory func(string) error
	removeFile    func(string) error
	renameFile    func(string, string) error
	Review        vxlan.Record
}
type PublishError struct {
	Relative, Phase string
	Committed       bool
	cause           error
}

func (e *PublishError) Error() string {
	return fmt.Sprintf("报告写入失败：%s；阶段 %s；committed=%t", e.Relative, e.Phase, e.Committed)
}
func (e *PublishError) Unwrap() error              { return e.cause }
func (e *PublishError) PublicationCommitted() bool { return e.Committed }

func SyncDirectory(path string) error {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}
func privateDirectory(path string) error {
	st, e := os.Lstat(path)
	if os.IsNotExist(e) {
		parent := filepath.Dir(path)
		missing := []string{}
		for p := parent; ; p = filepath.Dir(p) {
			if info, err := os.Stat(p); err == nil {
				if !info.IsDir() {
					return fmt.Errorf("报告父路径不是目录")
				}
				break
			} else if !os.IsNotExist(err) {
				return err
			}
			missing = append(missing, p)
		}
		if e = os.MkdirAll(parent, 0700); e != nil {
			return e
		}
		for i := len(missing) - 1; i >= 0; i-- {
			real, err := filepath.EvalSymlinks(filepath.Dir(missing[i]))
			if err != nil {
				return err
			}
			if e = SyncDirectory(real); e != nil {
				return e
			}
		}
		if e = os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
			return e
		}
		if e = SyncDirectory(parent); e != nil {
			return e
		}
		st, e = os.Lstat(path)
	}
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("报告目录须为真实私有目录（0700）")
	}
	return nil
}
func New(root string) (*Report, error) {
	root, e := filepath.Abs(root)
	if e != nil {
		return nil, e
	}
	if e = privateDirectory(root); e != nil {
		return nil, e
	}
	stem := time.Now().UTC().Format("2006-01-02_15-04-05")
	for i := 0; ; i++ {
		name := stem
		if i > 0 {
			name = fmt.Sprintf("%s_%d", stem, i)
		}
		dir := filepath.Join(root, name)
		e = os.Mkdir(dir, 0700)
		if os.IsExist(e) {
			continue
		}
		if e != nil {
			return nil, e
		}
		if e = SyncDirectory(root); e != nil {
			return nil, e
		}
		return &Report{Directory: dir, SyncDirectory: SyncDirectory}, nil
	}
}
func (r *Report) Publish(ctx context.Context, relative string, body []byte) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if filepath.IsAbs(relative) || relative == "." || strings.Contains(relative, "\\") || filepath.Clean(relative) != relative || strings.HasPrefix(relative, "../") {
		return fmt.Errorf("非法报告路径")
	}
	target := filepath.Join(r.Directory, relative)
	dir := filepath.Dir(target)
	if e := privateDirectory(dir); e != nil {
		return e
	}
	phase, committed := "temporary_file", false
	defer func() {
		if err != nil {
			err = &PublishError{Relative: relative, Phase: phase, Committed: committed, cause: err}
		}
	}()
	f, e := os.CreateTemp(dir, ".vxlan-*.tmp")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	phase = "write"
	if e = f.Chmod(0600); e != nil {
		return e
	}
	if _, e = f.Write(body); e != nil {
		return e
	}
	phase = "file_sync"
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	phase = "rename"
	rename := os.Rename
	if r.renameFile != nil {
		rename = r.renameFile
	}
	if e = rename(name, target); e != nil {
		return e
	}
	committed = true
	phase = "directory_sync"
	return r.SyncDirectory(dir)
}
func EncodeJSON(v any) ([]byte, error) {
	// A wrapper allows the same checked projection for scalar/text report fields.
	projected, err := vxlan.ProjectRecord(vxlan.Record{"value": v})
	if err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(projected["value"], "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
func (r *Report) PublishJSON(ctx context.Context, relative string, value any) error {
	body, err := EncodeJSON(value)
	if err != nil {
		return err
	}
	return r.Publish(ctx, relative, body)
}
func Basename(d vxlan.Record) string {
	clean := func(s string) string { return regexp.MustCompile(`[^A-Za-z0-9_.-]`).ReplaceAllString(s, "_") }
	name := clean(record.String(d["name"]))
	if len(name) > 100 {
		name = name[:100]
	}
	return name + "-" + clean(record.String(d["host"]))
}
func (r *Report) Finish(ctx context.Context, results []vxlan.Record, requested []any, interrupted bool, failures vxlan.Record) (vxlan.Record, error) {
	results = append([]vxlan.Record{}, results...)
	sort.SliceStable(results, func(i, j int) bool {
		return record.String(record.Map(results[i]["device"])["host"]) < record.String(record.Map(results[j]["device"])["host"])
	})
	done := map[string]bool{}
	counts := vxlan.Record{}
	complete := len(results) > 0 && len(failures) == 0
	for _, res := range results {
		done[record.String(record.Map(res["device"])["host"])] = true
		status := record.String(res["status"])
		n, _ := counts[status].(int)
		counts[status] = n + 1
		if status != "complete" || res["report_saved"] == false {
			complete = false
		}
	}
	pending := []any{}
	for _, d := range requested {
		if !done[record.String(record.Map(d)["host"])] {
			pending = append(pending, d)
		}
	}
	complete = complete && len(pending) == 0
	status := "incomplete"
	if complete {
		status = "complete"
	}
	if interrupted {
		status = "interrupted"
	}
	s := record.MergeLayers(vxlan.Record{"status": status, "total": max(len(requested), len(results)), "completed": len(results), "pending": pending, "counts": counts, "devices": results, "directory": r.Directory, "evidence_only": true}, failures)
	if r.Review != nil {
		s["review"] = r.Review
	}
	checkpoint := record.MergeLayers(s, vxlan.Record{"status": "incomplete", "report_error": "report_finalization_unconfirmed"})
	if interrupted {
		checkpoint["status"] = "interrupted"
	}
	if e := r.PublishJSON(ctx, "summary.json", checkpoint); e != nil {
		r.Invalidate()
		return s, e
	}
	text := fmt.Sprintf("VXLAN 证据：%s；完成 %d 台\n证据完整性不代表 Fabric 健康。\n逐设备诊断：devices/；报告状态以 summary.json 为准。\n", status, len(results))
	for _, res := range results {
		d := record.Map(res["device"])
		text += fmt.Sprintf("%s\t%s\t%s\t保存确认=%v\n", d["host"], d["name"], res["status"], res["report_saved"])
	}
	if e := r.Publish(ctx, "summary.txt", []byte(text)); e != nil {
		return s, e
	}
	if e := r.PublishJSON(ctx, "summary.json", s); e != nil {
		var p *PublishError
		if errors.As(e, &p) && p.Committed {
			if r.PublishJSON(context.WithoutCancel(ctx), "summary.json", checkpoint) != nil {
				r.Invalidate()
			}
		}
		return s, e
	}
	return s, nil
}
func (r *Report) Invalidate() {
	p := filepath.Join(r.Directory, "summary.json")
	b, e := os.ReadFile(p)
	if e != nil {
		return
	}
	var m vxlan.Record
	if json.Unmarshal(b, &m) == nil && m["status"] == "complete" {
		os.Remove(p)
		_ = SyncDirectory(r.Directory)
	}
}
