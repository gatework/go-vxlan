package netconnector

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	expect "github.com/gatework/go-expect"
	"github.com/gatework/go-net-connector/connector"
	ncvendors "github.com/gatework/go-net-connector/vendors"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/collect"
	"github.com/gatework/go-vxlan/parser"
	"github.com/gatework/go-vxlan/vendors"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

const receiptCommand = "show running-config"

// Use the real command/response engine, with only its byte transport replaced.
func readDevice(t *testing.T, profile connector.Driver, serve func(net.Conn) error) *connector.Device {
	t.Helper()
	return readDeviceTransport(t, profile, serve, func(conn net.Conn) io.ReadWriteCloser { return conn })
}

func readDeviceTransport(t *testing.T, profile connector.Driver, serve func(net.Conn) error, transport func(net.Conn) io.ReadWriteCloser) *connector.Device {
	t.Helper()
	done := make(chan error, 1)
	device, err := connector.New(profile, connector.ConnectionConfig{
		Host: "fixture", LoginTimeout: time.Second, CommandTimeout: 100 * time.Millisecond,
	}, connector.WithTransportFactory(func(context.Context, connector.ConnectionConfig) (io.ReadWriteCloser, error) {
		client, peer := net.Pipe()
		go func() {
			defer peer.Close()
			if _, err := io.WriteString(peer, "leaf#"); err != nil {
				done <- err
				return
			}
			command, err := bufio.NewReader(peer).ReadString('\n')
			if err == nil && command != receiptCommand+"\n" {
				err = errors.New("unexpected fixture command")
			}
			if err == nil {
				err = serve(peer)
			}
			done <- err
		}()
		return transport(client), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := device.Close(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	if err := device.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	return device
}

type firstCloseFailure struct {
	net.Conn
	cause error
	calls atomic.Int32
}

func (c *firstCloseFailure) Close() error {
	err := c.Conn.Close()
	if c.calls.Add(1) == 1 {
		return errors.Join(err, c.cause)
	}
	return err
}

type receiptSession func(context.Context, string) (collect.Capture, error)

func (read receiptSession) Read(ctx context.Context, command string) (collect.Capture, error) {
	return read(ctx, command)
}

type codedHookError struct{ error }

func (codedHookError) FailureCode() string { return "private_hook_code" }

func TestReadPreservesBodyFraming(t *testing.T) {
	platform, err := ncvendors.NewBuiltinRegistry().Lookup("cisco_nxos")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, wire, want string
	}{
		{"echo_and_indent", receiptCommand + "\r\n  hostname LEAF\r\nleaf#", "  hostname LEAF"},
		{"without_echo", "  hostname LEAF\r\nleaf#", "  hostname LEAF"},
		{"blank_lines", receiptCommand + "\r\n\r\n  hostname LEAF\r\n\r\nleaf#", "\n  hostname LEAF\n"},
		{"echo_only", receiptCommand + "\r\nleaf#", ""},
		{"repeated_command", receiptCommand + "\r\n" + receiptCommand + "\r\nleaf#", receiptCommand},
	} {
		t.Run(test.name, func(t *testing.T) {
			device := readDevice(t, platform, func(peer net.Conn) error {
				if _, err := io.WriteString(peer, test.wire); err != nil {
					return err
				}
				_, err := io.Copy(io.Discard, peer)
				return err
			})
			err := device.WithOperation(t.Context(), func(ctx context.Context, op *connector.Operation) error {
				capture, err := (Session{Operation: op, Device: device}).Read(ctx, receiptCommand)
				if err == nil && (!capture.Complete || capture.Body != test.want) {
					t.Errorf("capture body = %q, complete = %t; want %q", capture.Body, capture.Complete, test.want)
				}
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConfigurationReadStopsAfterAcceptedBodyWithError(t *testing.T) {
	cause := errors.New("post-acceptance failure")
	commands := []string{}
	session := receiptSession(func(_ context.Context, command string) (collect.Capture, error) {
		commands = append(commands, command)
		if command == nxos.Commands()["configuration"] {
			return collect.Capture{Complete: true, Body: "hostname LEAF\n"}, cause
		}
		return collect.Capture{Complete: true}, nil
	})
	configuration, err := (ConfigurationSession{Session: session}).ReadConfiguration(t.Context())
	if configuration != nil || !errors.Is(err, cause) {
		t.Fatal("post-acceptance error authorized configuration", configuration, err)
	}
	if strings.Join(commands, ",") != "terminal length 0,terminal width 511,show running-config" {
		t.Fatal("configuration read protocol changed", commands)
	}
}

func TestBorrowedReadPreservesAcceptedBodyAndCleanup(t *testing.T) {
	platform, err := ncvendors.NewBuiltinRegistry().Lookup("cisco_nxos")
	if err != nil {
		t.Fatal(err)
	}
	profile := connector.StaticDriver{Grammar: platform.Terminal()}
	hookErr, closeErr := errors.New("private hook"), errors.New("private close")
	profile.AfterCommand = func(context.Context, connector.Command, connector.StepResult, connector.Executor) error {
		return hookErr
	}
	device := readDeviceTransport(t, profile, func(peer net.Conn) error {
		if _, err := io.WriteString(peer, receiptCommand+"\r\nhostname LEAF\r\nleaf#"); err != nil {
			return err
		}
		_, err := io.Copy(io.Discard, peer)
		return err
	}, func(conn net.Conn) io.ReadWriteCloser { return &firstCloseFailure{Conn: conn, cause: closeErr} })
	var capture collect.Capture
	operationErr, cleanupErr := device.WithBorrowedOperation(t.Context(), func(ctx context.Context, op *connector.Operation) error {
		var err error
		capture, err = (Session{Operation: op, Device: device}).Read(ctx, receiptCommand)
		return err
	})
	if !capture.Complete || !strings.Contains(capture.Body, "hostname LEAF") || len(capture.Evidence) != 1 {
		t.Fatal("accepted body/attempt evidence lost", capture)
	}
	if !errors.Is(operationErr, hookErr) || !errors.Is(cleanupErr, closeErr) {
		t.Fatal("borrowed operation failures lost", operationErr, cleanupErr)
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(cleanupErr, closeErr) {
		t.Fatal("successful retry erased first cleanup failure")
	}
}

func TestCollectionRetainsInternalCleanupFailureAfterSuccessfulRetry(t *testing.T) {
	platform, err := ncvendors.NewBuiltinRegistry().Lookup("cisco_nxos")
	if err != nil {
		t.Fatal(err)
	}
	profile := connector.StaticDriver{Grammar: platform.Terminal()}
	hookErr := errors.New("private hook detail")
	closeErr := errors.New("private cleanup detail")
	profile.AfterCommand = func(context.Context, connector.Command, connector.StepResult, connector.Executor) error {
		return hookErr
	}
	var transport *firstCloseFailure
	device := readDeviceTransport(t, profile, func(peer net.Conn) error {
		if _, err := io.WriteString(peer, receiptCommand+"\r\nhostname LEAF\r\nleaf#"); err != nil {
			return err
		}
		_, err := io.Copy(io.Discard, peer)
		return err
	}, func(conn net.Conn) io.ReadWriteCloser {
		transport = &firstCloseFailure{Conn: conn, cause: closeErr}
		return transport
	})
	var snapshot vxlan.Snapshot
	var readErr error
	err = device.WithOperation(t.Context(), func(ctx context.Context, op *connector.Operation) error {
		session := receiptSession(func(ctx context.Context, command string) (collect.Capture, error) {
			// Isolate the command/cleanup path from terminal preparation.
			if strings.HasPrefix(command, "terminal ") {
				return collect.Capture{Complete: true}, nil
			}
			capture, err := (Session{Operation: op, Device: device}).Read(ctx, command)
			readErr = err
			return capture, err
		})
		var err error
		snapshot, err = collect.CollectSession(ctx, session, collect.Request{Profile: testProfile(), Target: vxlan.Record{}, Dimensions: []string{"configuration"}})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := device.Close(); err != nil || transport.calls.Load() < 2 {
		t.Fatalf("cleanup did not recover: calls=%d error=%v", transport.calls.Load(), err)
	}
	if !errors.Is(readErr, hookErr) || !errors.Is(readErr, closeErr) {
		t.Fatal("underlying failure identities lost")
	}
	configuration, collection := snapshot.Dimensions["configuration"], snapshot.Dimensions["collection"]
	if !configuration.Complete() || len(configuration.Records) != 1 || collection.Status != "partial" {
		t.Fatal("accepted facts or failed execution lost", snapshot)
	}
	if len(collection.Issues) != 2 || collection.Issues[0]["code"] != "after_command_failed" || collection.Issues[1]["code"] != "command_failed" {
		t.Fatal("independent unclassified cleanup cause lost", collection.Issues)
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", readErr, readErr, collection.Issues), "private") {
		t.Fatal("failure diagnostics exposed private details")
	}
}

func TestReadRetainsFailureEvidenceAndAcceptedFacts(t *testing.T) {
	for _, test := range []struct {
		name, body, code string
		prompt, accepted bool
		closePeer        bool
		hook             string
	}{
		{name: "timeout", body: "private-prefix\r\n", code: "timeout"},
		{name: "eof", body: "private-prefix\r\n", code: "connection_closed", closePeer: true},
		{name: "rejected", body: "% Invalid command\r\nleaf#", code: "device_error", prompt: true},
		{name: "invalid encoding", body: "description 中文\xff\r\nleaf#", code: "invalid_output_encoding", prompt: true},
		{name: "after command error", body: "hostname LEAF\r\nleaf#", code: "after_command_failed", prompt: true, accepted: true, hook: "error"},
		{name: "coded callback", body: "hostname LEAF\r\nleaf#", code: "after_command_failed", prompt: true, accepted: true, hook: "coded"},
		{name: "late cancel", body: "hostname LEAF\r\nleaf#", code: "interrupted", prompt: true, accepted: true, hook: "cancel"},
	} {
		t.Run(test.name, func(t *testing.T) {
			platform, err := ncvendors.NewBuiltinRegistry().Lookup("cisco_nxos")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			profile := connector.StaticDriver{Grammar: platform.Terminal()}
			callbackErr := errors.New("private callback detail")
			if test.hook == "coded" {
				callbackErr = codedHookError{callbackErr}
			}
			if test.hook != "" {
				profile.AfterCommand = func(context.Context, connector.Command, connector.StepResult, connector.Executor) error {
					if test.hook == "cancel" {
						cancel()
						return nil
					}
					return callbackErr
				}
			}
			wire := receiptCommand + "\r\n" + test.body
			device := readDevice(t, profile, func(peer net.Conn) error {
				if _, err := io.WriteString(peer, wire); err != nil {
					return err
				}
				if !test.closePeer {
					_, err := io.Copy(io.Discard, peer)
					return err
				}
				return nil
			})
			var capture collect.Capture
			err = device.WithOperation(ctx, func(ctx context.Context, op *connector.Operation) error {
				var readErr error
				capture, readErr = (Session{Operation: op, Device: device}).Read(ctx, receiptCommand)
				return readErr
			})
			coded, ok := errors.AsType[collect.CodedError](err)
			if !ok || coded.FailureCode() != test.code {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
			if capture.Complete != test.accepted || device.Connected() {
				t.Fatalf("complete=%t connected=%t", capture.Complete, device.Connected())
			}
			if test.accepted {
				if capture.Body != "hostname LEAF" {
					t.Fatalf("accepted body = %q", capture.Body)
				}
			} else if capture.Body != "" {
				t.Fatal("unaccepted raw evidence became parser input")
			}
			if len(capture.Evidence) != 1 {
				t.Fatalf("evidence count = %d", len(capture.Evidence))
			}
			evidence := capture.Evidence[0]
			if evidence["sha256"] != fmt.Sprintf("%x", sha256.Sum256([]byte(wire))) || evidence["bytes"] != len(wire) || evidence["written"] != len(receiptCommand)+1 || evidence["prompt_matched"] != test.prompt || evidence["attempt"] != 1 {
				t.Fatal("attempt evidence does not describe the wire exchange")
			}
			if !test.accepted && evidence["error_code"] != test.code {
				t.Fatalf("attempt code = %v", evidence["error_code"])
			}
			if capture.StartedAt == nil || capture.CompletedAt == nil || capture.CompletedAt.Before(*capture.StartedAt) {
				t.Fatal("receipt timestamps missing or out of order")
			}
			if (test.hook == "error" || test.hook == "coded") && !errors.Is(err, callbackErr) {
				t.Fatal("callback cause hidden")
			}
			if test.hook == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation cause hidden")
			}
			metadata, err := json.Marshal(capture.Evidence)
			if err != nil || strings.Contains(string(metadata), "private-prefix") || strings.Contains(string(metadata), "hostname LEAF") || strings.Contains(fmt.Sprintf("%+v %#v", coded, capture), "private callback detail") {
				t.Fatal("implicit output contains response or callback details")
			}
		})
	}
}

func TestReadFingerprintsRawPagedEncodedResponse(t *testing.T) {
	platform, err := ncvendors.NewBuiltinRegistry().Lookup("cisco_nxos")
	if err != nil {
		t.Fatal(err)
	}
	first := receiptCommand + "\r\n description \xd6\xd0\xce\xc4\r\n--More--"
	last := "\r\n description \xba\xcb\xd0\xc4\r\nleaf#"
	device := readDevice(t, platform, func(peer net.Conn) error {
		if _, err := io.WriteString(peer, first); err != nil {
			return err
		}
		reply := make([]byte, 1)
		if _, err := io.ReadFull(peer, reply); err != nil {
			return err
		}
		if string(reply) != " " {
			return errors.New("unexpected paging reply")
		}
		if _, err := io.WriteString(peer, last); err != nil {
			return err
		}
		_, err := io.Copy(io.Discard, peer)
		return err
	})
	err = device.WithOperation(t.Context(), func(ctx context.Context, op *connector.Operation) error {
		capture, err := (Session{Operation: op, Device: device}).Read(ctx, receiptCommand)
		if err != nil {
			return err
		}
		if !capture.Complete || capture.Body != " description 中文\n\n description 核心" {
			t.Fatalf("visible body = %q", capture.Body)
		}
		wire := first + last
		if len(capture.Evidence) != 1 || capture.Evidence[0]["sha256"] != fmt.Sprintf("%x", sha256.Sum256([]byte(wire))) || capture.Evidence[0]["bytes"] != len(wire) {
			t.Fatal("wire fingerprint was replaced by decoded/depaged output")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadKeepsHookAttemptsWithoutExposingHookText(t *testing.T) {
	platform, err := ncvendors.NewBuiltinRegistry().Lookup("cisco_nxos")
	if err != nil {
		t.Fatal(err)
	}
	profile := connector.StaticDriver{Grammar: platform.Terminal()}
	profile.AfterCommand = func(ctx context.Context, _ connector.Command, _ connector.StepResult, executor connector.Executor) error {
		if _, err := executor.Execute(ctx, connector.Command{
			Text: "private-hook-command", Sensitive: true, OutputSensitive: true,
		}); err != nil {
			return err
		}
		return errors.New("private-hook-failure")
	}
	wires := []string{
		receiptCommand + "\r\nhostname LEAF\r\nleaf#",
		"private-hook-command\r\nprivate-hook-output\r\nleaf#",
	}
	device := readDevice(t, profile, func(peer net.Conn) error {
		if _, err := io.WriteString(peer, wires[0]); err != nil {
			return err
		}
		command, err := bufio.NewReader(peer).ReadString('\n')
		if err != nil {
			return err
		}
		if command != "private-hook-command\n" {
			return errors.New("unexpected hook command")
		}
		if _, err := io.WriteString(peer, wires[1]); err != nil {
			return err
		}
		_, err = io.Copy(io.Discard, peer)
		return err
	})
	err = device.WithOperation(t.Context(), func(ctx context.Context, op *connector.Operation) error {
		capture, err := (Session{Operation: op, Device: device}).Read(ctx, receiptCommand)
		if err == nil || !capture.Complete || capture.Body != "hostname LEAF" || len(capture.Evidence) != len(wires) {
			t.Fatalf("receipt = %v, error = %v", capture, err)
			return err
		}
		for i, evidence := range capture.Evidence {
			if evidence["command"] != receiptCommand || evidence["attempt"] != i+1 || evidence["sha256"] != fmt.Sprintf("%x", sha256.Sum256([]byte(wires[i]))) || evidence["bytes"] != len(wires[i]) {
				t.Fatal("hook attempt identity or raw fingerprint lost")
			}
		}
		if strings.Contains(fmt.Sprintf("%v %v %#v", capture.Evidence, err, err), "private-hook") {
			t.Fatal("hook text exposed by implicit output")
		}
		return err
	})
	if coded, ok := errors.AsType[collect.CodedError](err); !ok || coded.FailureCode() != "after_command_failed" {
		t.Fatalf("hook failure lost: %v", err)
	}
}

func TestSessionErrorsPreserveIdentityAndSafeDiagnostics(t *testing.T) {
	for _, test := range []struct {
		cause error
		code  string
	}{
		{context.Canceled, "interrupted"},
		{context.DeadlineExceeded, "timeout"},
		{expect.ErrTimeout, "timeout"},
	} {
		wrapped := sessionError{fmt.Errorf("private transport detail: %w", test.cause)}
		closeCause := errors.New("private close detail")
		closed := sessionCloseError{closeCause}
		joined := errors.Join(wrapped, closed)
		if !errors.Is(joined, test.cause) || !errors.Is(joined, closeCause) || wrapped.FailureCode() != test.code || closed.FailureCode() != "session_close_failed" {
			t.Fatal("error identity or classification lost")
		}
		nested := sessionError{sessionError{joined}}
		codes := nested.FailureCodes()
		if len(codes) != 2 || codes[0] != test.code || codes[1] != "session_close_failed" || !errors.Is(nested, closeCause) {
			t.Fatal("nested session wrapping lost independent causes", codes)
		}
		if strings.Contains(fmt.Sprintf("%v %+v %#v %q", joined, wrapped, closed, wrapped), "private") {
			t.Fatal("implicit error output exposed private details")
		}
	}
}

func testProfile() *parser.Profile {
	profile, err := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
	if err != nil {
		panic(err)
	}
	return profile
}
