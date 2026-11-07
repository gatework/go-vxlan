package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Report struct {
	Directory     string
	SyncDirectory func(string) error
	Review        M
}
type PublishError struct {
	Relative, Phase string
	Committed       bool
}

func (e *PublishError) Error() string {
	return fmt.Sprintf("报告写入失败：%s；阶段 %s；committed=%t", e.Relative, e.Phase, e.Committed)
}
func syncDirectory(path string) error {
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
			if e = syncDirectory(real); e != nil {
				return e
			}
		}
		if e = os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
			return e
		}
		if e = syncDirectory(parent); e != nil {
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
func NewReport(root string) (*Report, error) {
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
		if e = syncDirectory(root); e != nil {
			return nil, e
		}
		return &Report{Directory: dir, SyncDirectory: syncDirectory}, nil
	}
}
func (r *Report) Publish(relative string, body []byte) (err error) {
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
			err = &PublishError{Relative: relative, Phase: phase, Committed: committed}
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
	phase = "rename"
	if e = os.Rename(name, target); e != nil {
		return e
	}
	committed = true
	phase = "directory_sync"
	return r.SyncDirectory(dir)
}
func jsonBytes(v any) []byte { b, _ := json.MarshalIndent(v, "", "  "); return append(b, '\n') }
func basename(d M) string {
	clean := func(s string) string { return regexp.MustCompile(`[^A-Za-z0-9_.-]`).ReplaceAllString(s, "_") }
	name := clean(str(d["name"]))
	if len(name) > 100 {
		name = name[:100]
	}
	return name + "-" + clean(str(d["host"]))
}
func (r *Report) Finish(results []M, requested []any, interrupted bool, failures M) (M, error) {
	results = append([]M{}, results...)
	sort.SliceStable(results, func(i, j int) bool {
		return str(object(results[i]["device"])["host"]) < str(object(results[j]["device"])["host"])
	})
	done := map[string]bool{}
	counts := M{}
	complete := len(results) > 0 && len(failures) == 0
	for _, res := range results {
		done[str(object(res["device"])["host"])] = true
		status := str(res["status"])
		n, _ := counts[status].(int)
		counts[status] = n + 1
		if status != "complete" || res["report_saved"] == false {
			complete = false
		}
	}
	pending := []any{}
	for _, d := range requested {
		if !done[str(object(d)["host"])] {
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
	s := merge(M{"status": status, "total": max(len(requested), len(results)), "completed": len(results), "pending": pending, "counts": counts, "devices": results, "directory": r.Directory, "evidence_only": true}, failures)
	if r.Review != nil {
		s["review"] = r.Review
	}
	checkpoint := merge(s, M{"status": "incomplete", "report_error": "report_finalization_unconfirmed"})
	if interrupted {
		checkpoint["status"] = "interrupted"
	}
	if e := r.Publish("summary.json", jsonBytes(checkpoint)); e != nil {
		r.invalidate()
		return s, e
	}
	text := fmt.Sprintf("VXLAN 证据：%s；完成 %d 台\n证据完整性不代表 Fabric 健康。\n逐设备诊断：devices/；报告状态以 summary.json 为准。\n", status, len(results))
	for _, res := range results {
		d := object(res["device"])
		text += fmt.Sprintf("%s\t%s\t%s\t保存确认=%v\n", d["host"], d["name"], res["status"], res["report_saved"])
	}
	if e := r.Publish("summary.txt", []byte(text)); e != nil {
		return s, e
	}
	if e := r.Publish("summary.json", jsonBytes(s)); e != nil {
		var p *PublishError
		if errors.As(e, &p) && p.Committed {
			if r.Publish("summary.json", jsonBytes(checkpoint)) != nil {
				r.invalidate()
			}
		}
		return s, e
	}
	return s, nil
}
func (r *Report) invalidate() {
	p := filepath.Join(r.Directory, "summary.json")
	b, e := os.ReadFile(p)
	if e != nil {
		return
	}
	var m M
	if json.Unmarshal(b, &m) == nil && m["status"] == "complete" {
		os.Remove(p)
		_ = syncDirectory(r.Directory)
	}
}
