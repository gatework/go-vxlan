package collect

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/parser"
	"github.com/gatework/go-vxlan/vendors"
)

type testSession struct {
	commands []string
	fail     string
}

func (s *testSession) Read(ctx context.Context, c string) (Capture, error) {
	s.commands = append(s.commands, c)
	if c == s.fail {
		return Capture{}, errors.New("transport")
	}
	body := ""
	if c == "show running-config" {
		body = "hostname LEAF\n"
	}
	return Capture{Body: body, Complete: true}, nil
}
func TestCollectOwnershipAndOrder(t *testing.T) {
	start := time.Date(2026, time.November, 7, 12, 0, 0, 0, time.UTC)
	s := &timestampSession{timestamp: start}
	req := Request{Profile: testProfile(), Target: vxlan.Record{"host": "192.0.2.1"}, FabricKey: "LAB", Dimensions: []string{"vpc", "configuration", "nve_peers"}}
	snapshot, e := CollectSession(context.Background(), s, req)
	if e != nil {
		t.Fatal(e)
	}
	if !snapshot.Complete() {
		t.Fatal(snapshot.Dimensions)
	}
	if strings.Join(s.commands, ",") != "terminal length 0,terminal width 511,show running-config,show nve peers" {
		t.Fatal(s.commands)
	}
	req.Target["host"] = "changed"
	if snapshot.Target["host"] != "192.0.2.1" {
		t.Fatal("input alias")
	}
	s.timestamp = s.timestamp.Add(time.Hour)
	for dimension, seconds := range map[string]int{"configuration": 3, "nve_peers": 4} {
		got := snapshot.Dimensions[dimension]
		want := start.Add(time.Duration(seconds) * time.Second)
		if got.StartedAt == nil || got.CompletedAt == nil || !got.StartedAt.Equal(want) || !got.CompletedAt.Equal(want) {
			t.Fatalf("%s timestamps changed with reused capture: %v / %v", dimension, got.StartedAt, got.CompletedAt)
		}
	}
}

type timestampSession struct {
	testSession
	timestamp time.Time
}

func (s *timestampSession) Read(ctx context.Context, command string) (Capture, error) {
	c, err := s.testSession.Read(ctx, command)
	s.timestamp = s.timestamp.Add(time.Second)
	c.StartedAt, c.CompletedAt = &s.timestamp, &s.timestamp
	return c, err
}
func TestCollectFailureNoReplay(t *testing.T) {
	s := &testSession{fail: "show nve peers"}
	snap, e := CollectSession(context.Background(), s, Request{Profile: testProfile(), Target: vxlan.Record{}, Dimensions: []string{"nve_peers", "nve_vnis"}})
	if e != nil {
		t.Fatal(e)
	}
	if len(s.commands) != 3 || snap.Complete() || snap.Dimensions["nve_vnis"].Issues[0]["skipped"] != true {
		t.Fatal(s.commands, snap)
	}
}
func TestCollectMissingAndClose(t *testing.T) {
	req := Request{Profile: testProfile(), Target: vxlan.Record{}, Dimensions: []string{"configuration"}}
	snap, e := Collect(context.Background(), func(context.Context, func(context.Context, Session) error) error { return nil }, req)
	if e != nil || snap.Dimensions["collection"].Issues[0]["code"] != "session_not_opened" {
		t.Fatal(snap, e)
	}
	snap, e = Collect(context.Background(), func(ctx context.Context, fn func(context.Context, Session) error) error {
		if err := fn(ctx, &testSession{}); err != nil {
			return err
		}
		return errors.New("close")
	}, req)
	if e != nil || !snap.Dimensions["configuration"].Complete() || snap.Complete() {
		t.Fatal(snap, e)
	}
	snap, e = Collect(t.Context(), func(ctx context.Context, fn func(context.Context, Session) error) error {
		if err := fn(ctx, &testSession{}); err != nil {
			return err
		}
		return fn(ctx, &testSession{})
	}, req)
	issues := snap.Dimensions["collection"].Issues
	if e != nil || !snap.Dimensions["configuration"].Complete() || len(issues) != 1 || issues[0]["code"] != "session_reentered" {
		t.Fatal("reentry lost facts or produced a spurious close failure", snap, e)
	}
}

type continuingSession struct{ testSession }

func (s *continuingSession) Connected() bool { return true }
func TestCommandFailureCanContinueWhenSessionKnownUsable(t *testing.T) {
	s := &continuingSession{testSession{fail: "show nve peers"}}
	snap, e := CollectSession(context.Background(), s, Request{Profile: testProfile(), Target: vxlan.Record{}, Dimensions: []string{"nve_peers", "nve_vnis"}})
	if e != nil || len(s.commands) != 4 {
		t.Fatal(s.commands, snap, e)
	}
}

type readSession func(context.Context, string) (Capture, error)

func (read readSession) Read(ctx context.Context, command string) (Capture, error) {
	return read(ctx, command)
}

type codedCollectionError string

func (e codedCollectionError) Error() string       { return "private failure detail" }
func (e codedCollectionError) FailureCode() string { return string(e) }

func TestCollectPreservesAcceptedFactsAfterFailure(t *testing.T) {
	for _, complete := range []bool{true, false} {
		t.Run(fmt.Sprintf("complete=%t", complete), func(t *testing.T) {
			var commands []string
			session := readSession(func(_ context.Context, command string) (Capture, error) {
				commands = append(commands, command)
				if command == "show running-config" {
					return Capture{Body: "hostname LEAF\n", Complete: complete, Evidence: []vxlan.Record{{"sha256": "received", "bytes": 14}}}, codedCollectionError("logging_failed")
				}
				return Capture{Complete: true}, nil
			})
			snapshot, err := CollectSession(t.Context(), session, Request{Profile: testProfile(), Target: vxlan.Record{}, Dimensions: []string{"configuration", "nve_peers"}})
			if err != nil {
				t.Fatal(err)
			}
			configuration := snapshot.Dimensions["configuration"]
			if configuration.Complete() != complete || len(configuration.Records) != map[bool]int{true: 1, false: 0}[complete] {
				t.Fatalf("accepted facts do not match receipt: %v", configuration)
			}
			if len(configuration.Evidence) != 1 || configuration.Evidence[0]["sha256"] != "received" {
				t.Fatal("lost received evidence")
			}
			collection := snapshot.Dimensions["collection"]
			want := "failed"
			if complete {
				want = "partial"
			}
			if snapshot.Complete() || collection.Status != want || collection.Issues[0]["code"] != "logging_failed" {
				t.Fatalf("late failure hidden: %v", collection)
			}
			if len(commands) != 3 || snapshot.Dimensions["nve_peers"].Issues[0]["skipped"] != true {
				t.Fatal("failed session reused or command replayed", commands)
			}
		})
	}
}

func TestCollectRetainsPreparationEvidence(t *testing.T) {
	for _, command := range []string{"terminal length 0", "terminal width 511"} {
		t.Run(command, func(t *testing.T) {
			var commands []string
			session := readSession(func(_ context.Context, cmd string) (Capture, error) {
				commands = append(commands, cmd)
				capture := Capture{Complete: true, Evidence: []vxlan.Record{{"command": cmd, "bytes": 3}}}
				if cmd == command {
					capture.Complete = false
					return capture, context.DeadlineExceeded
				}
				return capture, nil
			})
			snapshot, err := CollectSession(t.Context(), session, Request{Profile: testProfile(), Target: vxlan.Record{}, Dimensions: []string{"configuration"}})
			collection := snapshot.Dimensions["collection"]
			if err != nil || collection.Status != "failed" || len(collection.Evidence) != len(commands) {
				t.Fatal(collection, err)
			}
			if collection.Issues[0]["code"] != "timeout" || collection.Evidence[len(commands)-1]["command"] != command {
				t.Fatal("lost failed preparation evidence", collection)
			}
			if slices.Contains(commands, "show running-config") {
				t.Fatal("continued after preparation failure")
			}
		})
	}
}

func TestCollectUsesOperationContext(t *testing.T) {
	parent := t.Context()
	operation, cancel := context.WithCancel(parent)
	defer cancel()
	var commands []string
	session := readSession(func(ctx context.Context, command string) (Capture, error) {
		if ctx != operation {
			t.Fatal("collection did not receive the admitted operation context")
		}
		commands = append(commands, command)
		if command == "show running-config" {
			cancel()
			return Capture{Body: "hostname LEAF\n", Complete: true}, ctx.Err()
		}
		return Capture{Complete: true}, nil
	})
	snapshot, err := Collect(parent, func(_ context.Context, fn func(context.Context, Session) error) error {
		return fn(operation, session)
	}, Request{Profile: testProfile(), Target: vxlan.Record{}, Dimensions: []string{"configuration", "nve_peers"}})
	if err != nil || parent.Err() != nil || len(commands) != 3 || !snapshot.Dimensions["configuration"].Complete() {
		t.Fatal(snapshot, commands, err)
	}
	if snapshot.Dimensions["collection"].Issues[0]["code"] != "interrupted" || snapshot.Dimensions["nve_peers"].Issues[0]["skipped"] != true {
		t.Fatal("operation cancellation was lost", snapshot.Dimensions)
	}
}

func TestCollectKeepsIndependentOperationAndCloseFailures(t *testing.T) {
	late := codedCollectionError("logging_failed")
	closeErr := codedCollectionError("session_close_failed")
	for _, test := range []struct {
		name  string
		err   error
		codes []string
	}{
		{"canceled", fmt.Errorf("operation: %w", context.Canceled), []string{"interrupted"}},
		{"timeout and close", fmt.Errorf("operation: %w", errors.Join(context.DeadlineExceeded, closeErr)), []string{"timeout", "session_close_failed"}},
		{"late and close", errors.Join(late, closeErr, late), []string{"logging_failed", "session_close_failed"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := readSession(func(_ context.Context, command string) (Capture, error) {
				if command == "show running-config" {
					var err error
					if test.name == "late and close" {
						err = late
					}
					return Capture{Body: "hostname LEAF\n", Complete: true}, err
				}
				return Capture{Complete: true}, nil
			})
			snapshot, err := Collect(t.Context(), func(ctx context.Context, fn func(context.Context, Session) error) error {
				return errors.Join(fn(ctx, session), test.err)
			}, Request{Profile: testProfile(), Target: vxlan.Record{}, Dimensions: []string{"configuration"}})
			if err != nil || !snapshot.Dimensions["configuration"].Complete() || snapshot.Complete() {
				t.Fatal(snapshot, err)
			}
			var codes []string
			for _, issue := range snapshot.Dimensions["collection"].Issues {
				codes = append(codes, issue["code"].(string))
			}
			if !slices.Equal(codes, test.codes) {
				t.Fatalf("failure causes changed: got %v want %v", codes, test.codes)
			}
		})
	}
}

func testProfile() *parser.Profile {
	profile, err := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
	if err != nil {
		panic(err)
	}
	return profile
}
