package apply

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	changepkg "github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

const configuration = "hostname LEAF\nvlan 8\n  vn-segment 10008\ninterface Vlan8\n  vrf member tenant\n  fabric forwarding mode anycast-gateway\n"

type testSession struct {
	writes   int
	writeErr error
}

func (s *testSession) ReadConfiguration(context.Context) (vxlan.Record, error) {
	body := configuration
	if s.writes > 0 {
		body += "  ip address 192.0.2.254/24\n"
	}
	return nxos.ParseConfig(body, true).Records[0], nil
}
func (s *testSession) Write(context.Context, string) error { s.writes++; return s.writeErr }

type testJournal struct {
	write    func(vxlan.Record) error
	finalize func(vxlan.Record) error
}

func (j testJournal) WriteExecution(_ context.Context, state vxlan.Record) error {
	if j.write != nil {
		return j.write(state)
	}
	return nil
}
func (j testJournal) FinalizeExecution(_ context.Context, state vxlan.Record) error {
	if j.finalize != nil {
		return j.finalize(state)
	}
	return nil
}

type publicationError struct {
	cause     error
	committed bool
}

func (e publicationError) Error() string              { return "publication failed" }
func (e publicationError) Unwrap() error              { return e.cause }
func (e publicationError) PublicationCommitted() bool { return e.committed }

func testPlan(t *testing.T) *changepkg.ExecutionPlan {
	t.Helper()
	digest, err := vxlan.Fingerprint(nxos.ParseConfig(configuration, true).Records[0])
	if err != nil {
		t.Fatal(err)
	}
	change, err := changepkg.NewChangePlan(vxlan.Record{"kind": "svi_gateway_add", "vlan": 8, "vni": 10008, "vrf": "tenant", "address": "192.0.2.254/24"})
	if err != nil {
		t.Fatal(err)
	}
	item := vxlan.Record{"schema_version": 1, "platform": "cisco_nxos", "device": vxlan.Record{"host": "192.0.2.1"}, "expected_config_sha256": digest, "change": change.Change(), "commands": change.Commands(), "rollback": change.Rollback()}
	body, err := json.Marshal(vxlan.Record{"schema_version": 2, "platform": "cisco_nxos", "changes": vxlan.Record{"one": item}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := changepkg.NewExecutionPlan(body, "one")
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestExecutionFailureBoundaries(t *testing.T) {
	for _, mode := range []string{"success", "intent_uncommitted", "intent_committed", "intent_cancel", "ack_cancel", "callback_ignored", "callback_duplicate_ignored", "callback_missing", "cleanup", "finalize", "finalize_cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cause := errors.New("private failure")
			session := &testSession{}
			if mode == "callback_ignored" {
				session.writeErr = cause
			}
			journal := testJournal{write: func(state vxlan.Record) error {
				if state["status"] != "executing" {
					return nil
				}
				if _, pending := state["pending_command"]; pending {
					switch mode {
					case "intent_uncommitted", "intent_committed":
						return publicationError{cause, mode == "intent_committed"}
					case "intent_cancel":
						cancel()
					}
				} else if mode == "ack_cancel" {
					cancel()
				}
				return nil
			}, finalize: func(vxlan.Record) error {
				if mode == "finalize" {
					return cause
				}
				if mode == "finalize_cancel" {
					cancel()
				}
				return nil
			}}
			open := func(ctx context.Context, run func(context.Context, Session) error) error {
				if mode == "callback_missing" {
					return nil
				}
				err := run(ctx, session)
				if mode == "callback_ignored" {
					return nil
				}
				if mode == "callback_duplicate_ignored" {
					_ = run(ctx, session)
				}
				if mode == "cleanup" {
					return errors.Join(err, cause)
				}
				return err
			}
			plan := testPlan(t)
			result, err := Run(ctx, plan, open, journal)
			if mode == "success" {
				if err != nil || result.State["status"] != "configuration_verified" || session.writes != len(plan.Commands()) {
					t.Fatalf("success: %+v %v", result, err)
				}
				return
			}
			if err == nil || result.State["status"] == "configuration_verified" {
				t.Fatalf("false success: %+v %v", result, err)
			}
			if mode == "intent_uncommitted" || mode == "callback_missing" {
				if result.State["status"] != "failed" {
					t.Fatal(result.State)
				}
			} else if result.State["status"] != "uncertain" {
				t.Fatal(result.State)
			}
			if mode == "intent_uncommitted" || mode == "intent_committed" || mode == "intent_cancel" || mode == "callback_missing" {
				if session.writes != 0 {
					t.Fatal("write before durable intent/callback")
				}
			}
			if mode == "ack_cancel" || mode == "callback_ignored" {
				if session.writes != 1 {
					t.Fatal("replayed command")
				}
			}
			if mode == "callback_ignored" || mode == "intent_uncommitted" || mode == "intent_committed" || mode == "cleanup" || mode == "finalize" {
				if !errors.Is(err, cause) {
					t.Fatal("cause lost")
				}
			}
		})
	}
}

type blockedSession struct {
	testSession
	entered, release chan struct{}
}

func (s *blockedSession) Write(ctx context.Context, command string) error {
	if s.writes == 0 {
		close(s.entered)
		<-s.release
	}
	return s.testSession.Write(ctx, command)
}

func TestRunJoinsAdmittedCallbackBeforePublication(t *testing.T) {
	session := &blockedSession{entered: make(chan struct{}), release: make(chan struct{})}
	opened := make(chan struct{})
	finalized := make(chan struct{})
	done := make(chan error, 1)
	open := func(ctx context.Context, run func(context.Context, Session) error) error {
		go func() { _ = run(ctx, session) }()
		<-session.entered
		close(opened)
		return nil
	}
	journal := testJournal{finalize: func(vxlan.Record) error { close(finalized); return nil }}
	plan := testPlan(t)
	go func() { _, err := Run(t.Context(), plan, open, journal); done <- err }()
	<-opened
	select {
	case <-finalized:
		t.Fatal("finalized while command was active")
	default:
	}
	close(session.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-finalized:
	default:
		t.Fatal("missing final publication")
	}
}
