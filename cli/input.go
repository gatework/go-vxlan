package cli

import (
	"bufio"
	"context"
	"io"
)

// A cancelled CLI returns immediately without closing caller-owned input.
// For injected readers the caller must unblock its reader when disposing the App.
func inputContext[T any](ctx context.Context, read func() (T, error)) (T, error) {
	var zero T
	if e := ctx.Err(); e != nil {
		return zero, e
	}
	type result struct {
		value T
		err   error
	}
	done := make(chan result, 1)
	go func() { v, e := read(); done <- result{v, e} }()
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case r := <-done:
		return r.value, r.err
	}
}
func readLineContext(ctx context.Context, r io.Reader) (string, error) {
	return inputContext(ctx, func() (string, error) { return bufio.NewReader(r).ReadString('\n') })
}
func readContext(ctx context.Context, r io.Reader) ([]byte, error) {
	return inputContext(ctx, func() ([]byte, error) { return io.ReadAll(r) })
}
