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
	ReadConfiguration(ctx context.Context) (vxlan.Record, error)
	Write(ctx context.Context, command string) error
}

// Opener lends exactly one session and context for the complete operation. Its
// returned error includes independent cleanup failures, even after verification.
type Opener func(context.Context, func(context.Context, Session) error) error

// Journal receives an owned state projection for each synchronous publication.
// An error after a visible rename implements PublicationCommitted() bool.
// FinalizeExecution preserves an independent durable checkpoint and invalidates
// unconfirmed success when the final publication or its recovery fails.
type Journal interface {
	WriteExecution(ctx context.Context, execution vxlan.Record) error
	FinalizeExecution(ctx context.Context, execution vxlan.Record) error
}

// Result retains execution state and independent publication or cancellation outcomes.
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
	state := executionState{plan: plan, commands: plan.Commands(), status: executionConfirmed}
	fail := func(cause error, finalization bool) (Result, error) {
		state.status = executionFailed
		if state.started {
			state.status = executionUncertain
		}
		state.errorCode = "execution_failed"
		if finalization {
			state.errorCode = "execution_finalization_unconfirmed"
		}
		interrupted := ctx.Err() != nil || errors.Is(cause, context.Canceled)
		if interrupted {
			state.errorCode = "interrupted"
		}
		publicationErr := journal.WriteExecution(context.WithoutCancel(ctx), state.record())
		return Result{State: state.record(), ReportUnconfirmed: publicationErr != nil || finalization, Interrupted: interrupted}, &runError{errors.Join(cause, ctx.Err(), publicationErr)}
	}
	if err := ctx.Err(); err != nil {
		return fail(err, false)
	}
	if err := journal.WriteExecution(ctx, state.record()); err != nil {
		return fail(err, false)
	}
	operation := func(operationCtx context.Context, session Session) error {
		return state.execute(ctx, operationCtx, session, journal)
	}
	if err := ownedOpen(ctx, open, operation); err != nil {
		return fail(err, false)
	}
	if !state.verified {
		return fail(change.ErrExecutionPlan, false)
	}
	if err := ctx.Err(); err != nil {
		return fail(err, false)
	}
	state.status = executionVerified
	if err := journal.FinalizeExecution(ctx, state.record()); err != nil {
		return fail(err, true)
	}
	if err := ctx.Err(); err != nil {
		return fail(err, true)
	}
	return Result{State: state.record()}, nil
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

func (s *executionState) execute(ctx, operationCtx context.Context, session Session, journal Journal) error {
	plan := s.plan
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
	for i, command := range s.commands {
		if err = checkContext(); err != nil {
			return err
		}
		s.status, s.pendingCommand = executionRunning, new(i)
		if err = journal.WriteExecution(operationCtx, s.record()); err != nil {
			var publication interface{ PublicationCommitted() bool }
			if errors.As(err, &publication) && publication.PublicationCommitted() {
				s.started = true
			}
			return err
		}
		s.started = true
		if err = checkContext(); err != nil {
			return err
		}
		if err = session.Write(operationCtx, command); err != nil {
			return err
		}
		s.acknowledged = append(s.acknowledged, i)
		s.pendingCommand = nil
		if err = journal.WriteExecution(context.WithoutCancel(operationCtx), s.record()); err != nil {
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
	s.observedConfigSHA256 = digest
	s.verified = true
	return checkContext()
}
