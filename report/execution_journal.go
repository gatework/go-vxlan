package report

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

func (r *Report) WriteExecution(ctx context.Context, state vxlan.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.PublishJSON(ctx, "execution.json", state)
}

// FinalizeExecution keeps an independent, durable uncertain checkpoint until
// both success publication and checkpoint removal are confirmed. If storage
// stops accepting recovery and unlink, the checkpoint takes precedence over a
// visible execution.json; callers must also require a successful Run result.
func (r *Report) FinalizeExecution(ctx context.Context, state vxlan.Record) error {
	checkpoint := record.MergeLayers(state, vxlan.Record{"status": "uncertain", "error": "execution_finalization_unconfirmed"})
	if err := r.PublishJSON(context.WithoutCancel(ctx), "execution-checkpoint.json", checkpoint); err != nil {
		return err
	}
	recoverExecution := func(cause error) error {
		recoveryErr := r.PublishJSON(context.WithoutCancel(ctx), "execution.json", checkpoint)
		var removalErr error
		if recoveryErr != nil {
			removalErr = r.remove(filepath.Join(r.Directory, "execution.json"))
			if removalErr == nil {
				removalErr = r.SyncDirectory(r.Directory)
			}
		}
		return errors.Join(cause, recoveryErr, removalErr)
	}
	if err := r.WriteExecution(ctx, state); err != nil {
		return recoverExecution(err)
	}
	if err := ctx.Err(); err != nil {
		return recoverExecution(err)
	}
	if err := r.remove(filepath.Join(r.Directory, "execution-checkpoint.json")); err != nil {
		return recoverExecution(err)
	}
	if err := r.SyncDirectory(r.Directory); err != nil {
		checkpointErr := r.PublishJSON(context.WithoutCancel(ctx), "execution-checkpoint.json", checkpoint)
		return recoverExecution(errors.Join(err, checkpointErr))
	}
	if err := ctx.Err(); err != nil {
		checkpointErr := r.PublishJSON(context.WithoutCancel(ctx), "execution-checkpoint.json", checkpoint)
		return recoverExecution(errors.Join(err, checkpointErr))
	}
	return nil
}

func (r *Report) remove(path string) error {
	if r.removeFile != nil {
		return r.removeFile(path)
	}
	return os.Remove(path)
}
