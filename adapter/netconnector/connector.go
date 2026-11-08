package netconnector

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	expect "github.com/gatework/go-expect"
	"github.com/gatework/go-net-connector/connector"
	"github.com/gatework/go-net-connector/vendors"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/collect"
)

type Session struct {
	Operation *connector.Operation
	Device    *connector.Device
}

func (s Session) Read(ctx context.Context, command string) (capture collect.Capture, err error) {
	defer func() {
		if err != nil {
			err = sessionError{err}
		}
	}()
	if s.Operation == nil {
		return capture, errors.New("missing operation")
	}
	prompt := s.Operation.RawPrompt()
	if prompt == "" {
		return capture, errors.New("missing current prompt")
	}
	started := time.Now().UTC()
	result, err := s.Operation.ExecuteCommand(ctx, connector.Command{Text: command, OutputSensitive: true, Prompt: expect.Line(prompt)}, connector.ExecuteOptions{SkipPrivilege: true})
	ended := time.Now().UTC()
	capture.StartedAt, capture.CompletedAt = &started, &ended
	for i, attempt := range result.Attempts() {
		raw := attempt.Response().Raw()
		evidence := vxlan.Record{
			"command": command, "attempt": i + 1, "written": attempt.Written(),
			"prompt_matched": attempt.Complete(), "bytes": len(raw),
			"sha256":      fmt.Sprintf("%x", sha256.Sum256([]byte(raw))),
			"observed_at": ended.Format("2006-01-02T15:04:05.000000Z"),
		}
		if attempt.Err() != nil {
			evidence["error_code"] = (sessionError{attempt.Err()}).FailureCode()
		}
		capture.Evidence = append(capture.Evidence, evidence)
	}
	// An accepted step survives later hooks, logging and cancellation errors.
	// A matched prompt in Attempts alone does not establish acceptance.
	steps := result.Steps()
	if len(steps) != 1 || steps[0].Command().Text != command {
		if err == nil {
			err = errors.New("invalid command result")
		}
		return capture, err
	}
	response := steps[0].Response()
	rendered, renderErr := response.Rendered()
	promptText, promptErr := response.Prompt()
	if textErr := errors.Join(renderErr, promptErr); textErr != nil {
		return capture, errors.Join(err, textErr)
	}
	capture.Body = commandBody(rendered, promptText, command)
	capture.Complete = true
	return capture, err
}

// Strip only the acknowledged prompt and matching first echo line. Rendering
// applies terminal edits; it must not erase unknown configuration syntax.
func commandBody(output, prompt, command string) string {
	body := strings.TrimSuffix(output, prompt)
	first, rest, hasNewline := strings.Cut(body, "\n")
	if strings.TrimSpace(first) == strings.TrimSpace(command) {
		if hasNewline {
			return rest
		}
		return ""
	}
	return body
}
func (s Session) Write(ctx context.Context, command string) error {
	if s.Operation == nil {
		return sessionError{fmt.Errorf("missing operation")}
	}
	result, e := s.Operation.ExecuteCommand(ctx, connector.Command{Text: command, OutputSensitive: true}, connector.ExecuteOptions{SkipPrivilege: true})
	if e != nil {
		return sessionError{e}
	}
	if steps := result.Steps(); len(steps) != 1 || steps[0].Command().Text != command {
		return sessionError{fmt.Errorf("invalid write receipt")}
	}
	return nil
}
func (s Session) Connected() bool { return s.Operation != nil && s.Operation.Connected() }

type sessionError struct{ error }

func (e sessionError) FailureCode() string {
	if code := interruptionCode(e.error); code != "" {
		return code
	}
	if codes := e.FailureCodes(); len(codes) > 0 {
		return codes[0]
	}
	return "command_failed"
}

func interruptionCode(err error) string {
	if errors.Is(err, context.Canceled) {
		return "interrupted"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, expect.ErrTimeout) {
		return "timeout"
	}
	return ""
}

// Keep independent causes visible without changing the original error tree.
// Connector errors already classify their causes; only unclassified wrappers
// and joins are traversed. Unknown secondary failures must not be guessed to
// be cleanup errors from private upstream types or diagnostic text.
func (e sessionError) FailureCodes() []string {
	var codes []string
	var visit func(error)
	visit = func(err error) {
		if err == nil {
			return
		}
		if multiple, ok := err.(interface{ FailureCodes() []string }); ok {
			if classified := multiple.FailureCodes(); len(classified) > 0 {
				codes = append(codes, classified...)
				return
			}
		}
		code := "command_failed"
		switch classified := err.(type) {
		case collect.CodedError:
			code = classified.FailureCode()
		case *connector.Error:
			// Preserve the semantic code instead of also classifying its cause.
			code = classified.Code
		default:
			switch wrapped := err.(type) {
			case interface{ Unwrap() []error }:
				for _, cause := range wrapped.Unwrap() {
					visit(cause)
				}
				return
			case interface{ Unwrap() error }:
				if cause := wrapped.Unwrap(); cause != nil {
					visit(cause)
					return
				}
			}
		}
		if code != "session_close_failed" {
			if interrupted := interruptionCode(err); interrupted != "" {
				code = interrupted
			}
		}
		codes = append(codes, code)
	}
	visit(e.error)
	return codes
}

func (e sessionError) Error() string    { return e.FailureCode() }
func (e sessionError) GoString() string { return e.Error() }
func (e sessionError) Unwrap() error    { return e.error }

type sessionCloseError struct{ error }

func (e sessionCloseError) FailureCode() string { return "session_close_failed" }
func (e sessionCloseError) Error() string       { return e.FailureCode() }
func (e sessionCloseError) GoString() string    { return e.Error() }
func (e sessionCloseError) Unwrap() error       { return e.error }

// Open lends one operation lease for the entire collection and retains close failures.
func Open(config connector.ConnectionConfig) collect.OpenSession {
	return func(ctx context.Context, fn func(context.Context, collect.Session) error) (err error) {
		platform, e := vendors.NewBuiltinRegistry().Lookup("cisco_nxos")
		if e != nil {
			return e
		}
		device, e := connector.New(platform.Profile(), config)
		if e != nil {
			return e
		}
		defer func() {
			if closeErr := device.Close(); closeErr != nil {
				err = errors.Join(err, sessionCloseError{closeErr})
			}
		}()
		if e = device.Connect(ctx); e != nil {
			return sessionError{e}
		}
		operationErr, cleanupErr := device.WithBorrowedOperation(ctx, func(ctx context.Context, op *connector.Operation) error {
			return fn(ctx, Session{Operation: op, Device: device})
		})
		if operationErr != nil {
			err = sessionError{operationErr}
		}
		if cleanupErr != nil {
			err = errors.Join(err, sessionCloseError{cleanupErr})
		}
		return err
	}
}
