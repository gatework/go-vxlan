package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateAtomicReports(t *testing.T) {
	root := filepath.Join(t.TempDir(), "reports")
	r, e := NewReport(root)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Publish("summary.json", []byte(`{"status":"incomplete"}`)); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(filepath.Join(r.Directory, "summary.json"))
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
	r.SyncDirectory = func(string) error { return errors.New("disk") }
	e = r.Publish("summary.json", []byte(`{"status":"complete"}`))
	var p *PublishError
	if !errors.As(e, &p) || !p.Committed {
		t.Fatal(e)
	}
	public := t.TempDir()
	os.Chmod(public, 0755)
	if _, e = NewReport(public); e == nil {
		t.Fatal("public root allowed")
	}
}
func TestSummaryFailureCannotClaimComplete(t *testing.T) {
	r, e := NewReport(filepath.Join(t.TempDir(), "reports"))
	if e != nil {
		t.Fatal(e)
	}
	n := 0
	r.SyncDirectory = func(p string) error {
		n++
		if n == 3 {
			return errors.New("disk")
		}
		return syncDirectory(p)
	}
	_, e = r.Finish([]M{{"device": M{"host": "192.0.2.1"}, "status": "complete", "report_saved": true}}, []any{M{"host": "192.0.2.1"}}, false, nil)
	if e == nil {
		t.Fatal("expected failure")
	}
	b, e := os.ReadFile(filepath.Join(r.Directory, "summary.json"))
	if e != nil {
		t.Fatal(e)
	}
	var s M
	json.Unmarshal(b, &s)
	if s["status"] == "complete" {
		t.Fatal("success left after failed durability")
	}
}
