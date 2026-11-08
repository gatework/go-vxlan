package apply

import (
	"context"
	"errors"
	"sync"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/change"
)

// Session is the capability the executor consumes. ReadConfiguration returns
// complete, checked configuration evidence or an error.
type Session interface {
	ReadConfiguration(context.Context) (vxlan.Record, error)
	Write(context.Context, string) error
}

// Opener lends exactly one session and context for the complete operation. Its
// returned error includes independent cleanup failures, even after verification.
type Opener func(context.Context, func(context.Context, Session) error) error

// Journal consumes each state synchronously without retaining or mutating it.
// An error after a visible rename implements PublicationCommitted() bool.
// FinalizeExecution preserves an independent durable checkpoint and invalidates
// unconfirmed success when the final publication or its recovery fails.
type Journal interface {
	WriteExecution(context.Context, vxlan.Record) error
	FinalizeExecution(context.Context, vxlan.Record) error
}

type Result struct {
	State             vxlan.Record
	ReportUnconfirmed bool
	Interrupted       bool
}

type runError struct{ cause error }

func (*runError) Error() string      { return "vxlan: execution failed" }
func (e *runError) Unwrap() error    { return e.cause }
func (e *runError) GoString() string { return e.Error() }

// Run accepts only a bound ExecutionPlan. It never reconnects, replays a
// command, saves configuration or automatically executes rollback commands.
func Run(ctx context.Context, plan *change.ExecutionPlan, open Opener, journal Journal) (Result, error) {
	if !plan.Valid() || open == nil || journal == nil {
		return Result{}, &runError{change.ErrExecutionPlan}
	}
	state := vxlan.Record{"status": "confirmed", "device": plan.Device(), "plan_sha256": plan.PlanSHA256(), "plan_item": plan.ItemID(), "expected_config_sha256": plan.ExpectedConfigSHA256(), "commands": plan.Commands(), "steps": []vxlan.Record{}}
	started, verified := false, false
	fail := func(cause error, finalization bool) (Result, error) {
		state["status"] = "failed"
		if started {
			state["status"] = "uncertain"
		}
		state["error"] = "execution_failed"
		if finalization {
			state["error"] = "execution_finalization_unconfirmed"
		}
		interrupted := ctx.Err() != nil || errors.Is(cause, context.Canceled)
		if interrupted {
			state["error"] = "interrupted"
		}
		publicationErr := journal.WriteExecution(context.WithoutCancel(ctx), state)
		return Result{State: state, ReportUnconfirmed: publicationErr != nil || finalization, Interrupted: interrupted}, &runError{errors.Join(cause, ctx.Err(), publicationErr)}
	}
	if err := ctx.Err(); err != nil {
		return fail(err, false)
	}
	if err := journal.WriteExecution(ctx, state); err != nil {
		return fail(err, false)
	}
	operation := func(operationCtx context.Context, session Session) error {
		if operationCtx == nil || session == nil {
			return change.ErrExecutionPlan
		}
		checkContext := func() error { return errors.Join(ctx.Err(), operationCtx.Err()) }
		if err := checkContext(); err != nil {
			return err
		}
		before, err := session.ReadConfiguration(operationCtx)
		if err != nil {
			return err
		}
		before, err = vxlan.ProjectRecord(before)
		if err != nil {
			return err
		}
		if err = plan.CheckBefore(before); err != nil {
			return err
		}
		for i, command := range plan.Commands() {
			if err = checkContext(); err != nil {
				return err
			}
			state["status"], state["pending_command"] = "executing", i
			if err = journal.WriteExecution(operationCtx, state); err != nil {
				var publication interface{ PublicationCommitted() bool }
				if errors.As(err, &publication) && publication.PublicationCommitted() {
					started = true
				}
				return err
			}
			started = true
			if err = checkContext(); err != nil {
				return err
			}
			if err = session.Write(operationCtx, command); err != nil {
				return err
			}
			state["steps"] = append(state["steps"].([]vxlan.Record), vxlan.Record{"index": i, "status": "acknowledged"})
			delete(state, "pending_command")
			if err = journal.WriteExecution(context.WithoutCancel(operationCtx), state); err != nil {
				return err
			}
			if err = checkContext(); err != nil {
				return err
			}
		}
		after, err := session.ReadConfiguration(operationCtx)
		if err != nil {
			return err
		}
		digest, err := plan.CheckAfter(before, after)
		if err != nil {
			return err
		}
		state["observed_config_sha256"] = digest
		verified = true
		return checkContext()
	}
	if err := ownedOpen(ctx, open, operation); err != nil {
		return fail(err, false)
	}
	if !verified {
		return fail(change.ErrExecutionPlan, false)
	}
	if err := ctx.Err(); err != nil {
		return fail(err, false)
	}
	state["status"] = "configuration_verified"
	if err := journal.FinalizeExecution(ctx, state); err != nil {
		return fail(err, true)
	}
	if err := ctx.Err(); err != nil {
		return fail(err, true)
	}
	return Result{State: state}, nil
}

// A faulty injected opener cannot replay the operation, erase its callback
// failure, or let an admitted asynchronous callback outlive final publication.
func ownedOpen(ctx context.Context, open Opener, run func(context.Context, Session) error) error {
	var mu sync.Mutex
	active, admitted := true, false
	done := make(chan struct{})
	var callbackErr, protocolErr error
	openErr := open(ctx, func(operationCtx context.Context, session Session) error {
		mu.Lock()
		if !active || admitted {
			protocolErr = change.ErrExecutionPlan
			mu.Unlock()
			return change.ErrExecutionPlan
		}
		admitted = true
		mu.Unlock()
		err := change.ErrExecutionPlan
		defer func() { mu.Lock(); callbackErr = err; close(done); mu.Unlock() }()
		err = run(operationCtx, session)
		return err
	})
	mu.Lock()
	active = false
	started := admitted
	mu.Unlock()
	if !started {
		return errors.Join(openErr, change.ErrExecutionPlan)
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	return errors.Join(openErr, callbackErr, protocolErr, ctx.Err())
}
