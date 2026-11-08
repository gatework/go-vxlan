package report

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
)

func TestExecutionFinalizationKeepsIndependentCheckpoint(t *testing.T) {
	for _, mode := range []string{"success", "committed", "recovery_and_removal", "checkpoint_remove"} {
		t.Run(mode, func(t *testing.T) {
			r, err := New(filepath.Join(t.TempDir(), "reports"))
			if err != nil {
				t.Fatal(err)
			}
			finalErr, recoveryErr, removeErr := errors.New("final sync"), errors.New("recovery sync"), errors.New("remove")
			calls := 0
			r.SyncDirectory = func(path string) error {
				calls++
				if calls == 2 && (mode == "committed" || mode == "recovery_and_removal") {
					return finalErr
				}
				if calls == 3 && mode == "recovery_and_removal" {
					return recoveryErr
				}
				return SyncDirectory(path)
			}
			r.removeFile = func(path string) error {
				if mode == "recovery_and_removal" || mode == "checkpoint_remove" {
					return removeErr
				}
				return os.Remove(path)
			}
			err = r.FinalizeExecution(context.Background(), vxlan.Record{"status": "configuration_verified", "steps": []any{}})
			if mode == "success" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(filepath.Join(r.Directory, "execution-checkpoint.json")); !os.IsNotExist(err) {
					t.Fatal("confirmed checkpoint not retired")
				}
				return
			}
			if err == nil {
				t.Fatal("false success")
			}
			if mode == "recovery_and_removal" && (!errors.Is(err, finalErr) || !errors.Is(err, recoveryErr) || !errors.Is(err, removeErr)) {
				t.Fatal("independent failures lost", err)
			}
			body, err := os.ReadFile(filepath.Join(r.Directory, "execution-checkpoint.json"))
			if err != nil {
				t.Fatal("durable checkpoint lost", err)
			}
			checkpoint, err := vxlan.DecodeDocument(body)
			if err != nil || checkpoint["status"] != "uncertain" {
				t.Fatal("checkpoint claimed success", checkpoint, err)
			}
			body, err = os.ReadFile(filepath.Join(r.Directory, "execution.json"))
			if err == nil {
				state, err := vxlan.DecodeDocument(body)
				if err != nil || state["status"] == "configuration_verified" {
					t.Fatal("unconfirmed final publication retained", state, err)
				}
			}
		})
	}
}

func TestCheckpointRemovalDurabilityFailures(t *testing.T) {
	for _, storageLost := range []bool{false, true} {
		t.Run(map[bool]string{false: "recoverable", true: "storage_lost"}[storageLost], func(t *testing.T) {
			r, err := New(filepath.Join(t.TempDir(), "reports"))
			if err != nil {
				t.Fatal(err)
			}
			syncErr, checkpointErr, recoveryErr, removeErr := errors.New("checkpoint removal sync"), errors.New("checkpoint recreation"), errors.New("execution recovery"), errors.New("execution removal")
			syncs := 0
			r.SyncDirectory = func(path string) error {
				syncs++
				if syncs == 3 {
					return syncErr
				}
				return SyncDirectory(path)
			}
			renamed := 0
			r.renameFile = func(old, target string) error {
				renamed++
				if storageLost && renamed == 3 {
					return checkpointErr
				}
				if storageLost && renamed == 4 {
					return recoveryErr
				}
				return os.Rename(old, target)
			}
			r.removeFile = func(path string) error {
				if storageLost && filepath.Base(path) == "execution.json" {
					return removeErr
				}
				return os.Remove(path)
			}
			err = r.FinalizeExecution(context.Background(), vxlan.Record{"status": "configuration_verified", "steps": []any{}})
			if !errors.Is(err, syncErr) {
				t.Fatal("checkpoint removal uncertainty lost", err)
			}
			if storageLost {
				if !errors.Is(err, checkpointErr) || !errors.Is(err, recoveryErr) || !errors.Is(err, removeErr) {
					t.Fatal("storage failure chain lost", err)
				}
				// A completely unwritable medium can retain the visible final file.
				// The execution API must still report failure, never certify it.
				return
			}
			body, err := os.ReadFile(filepath.Join(r.Directory, "execution-checkpoint.json"))
			if err != nil {
				t.Fatal(err)
			}
			checkpoint, err := vxlan.DecodeDocument(body)
			if err != nil || checkpoint["status"] != "uncertain" {
				t.Fatal("recovery checkpoint missing", checkpoint, err)
			}
		})
	}
}

func TestPrivateAtomicReports(t *testing.T) {
	root := filepath.Join(t.TempDir(), "reports")
	r, e := New(root)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Publish(context.Background(), "summary.json", []byte(`{"status":"incomplete"}`)); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(filepath.Join(r.Directory, "summary.json"))
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
	r.SyncDirectory = func(string) error { return errors.New("disk") }
	e = r.Publish(context.Background(), "summary.json", []byte(`{"status":"complete"}`))
	var p *PublishError
	if !errors.As(e, &p) || !p.Committed {
		t.Fatal(e)
	}
	public := t.TempDir()
	os.Chmod(public, 0755)
	if _, e = New(public); e == nil {
		t.Fatal("public root allowed")
	}
}
func TestSummaryFailureCannotClaimComplete(t *testing.T) {
	r, e := New(filepath.Join(t.TempDir(), "reports"))
	if e != nil {
		t.Fatal(e)
	}
	n := 0
	r.SyncDirectory = func(p string) error {
		n++
		if n == 3 {
			return errors.New("disk")
		}
		return SyncDirectory(p)
	}
	_, e = r.Finish(context.Background(), []vxlan.Record{{"device": vxlan.Record{"host": "192.0.2.1"}, "status": "complete", "report_saved": true}}, []any{vxlan.Record{"host": "192.0.2.1"}}, false, nil)
	if e == nil {
		t.Fatal("expected failure")
	}
	b, e := os.ReadFile(filepath.Join(r.Directory, "summary.json"))
	if e != nil {
		t.Fatal(e)
	}
	var s vxlan.Record
	json.Unmarshal(b, &s)
	if s["status"] == "complete" {
		t.Fatal("success left after failed durability")
	}
}
