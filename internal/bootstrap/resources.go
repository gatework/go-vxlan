package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	ErrResourceParallel = errors.New("parallel must be between 0 and 500")
	ErrResourceLimit    = errors.New("insufficient local file descriptor limit")
)

// resourceLimitError contains only the capacity requested by the batch.
type resourceLimitError struct {
	parallel int
	required uint64
}

func (e *resourceLimitError) Error() string {
	return fmt.Sprintf("%d concurrent devices require at least %d file descriptors", e.parallel, e.required)
}

func (e *resourceLimitError) Unwrap() error { return ErrResourceLimit }

// Concurrent batches share the process limit, so updates must be serialized.
var resourceLimitMu sync.Mutex

// prepareResources reserves 128 base descriptors and 16 per active device,
// matching the existing Ruby/connector policy. It raises only the soft limit,
// within the existing hard limit. Callers pass min(parallel, selected devices).
func PrepareResources(ctx context.Context, parallel int) error {
	if parallel < 0 || parallel > 500 {
		return ErrResourceParallel
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if parallel == 0 {
		return nil
	}
	resourceLimitMu.Lock()
	defer resourceLimitMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	required := uint64(128 + 16*parallel)
	failure := &resourceLimitError{parallel: parallel, required: required}
	var limit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &limit) != nil {
		return failure
	}
	if limit.Cur >= required {
		return nil
	}
	if limit.Max < required {
		return failure
	}
	limit.Cur = required
	if unix.Setrlimit(unix.RLIMIT_NOFILE, &limit) != nil {
		return failure
	}
	return nil
}
