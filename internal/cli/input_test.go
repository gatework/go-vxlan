package cli

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestCancelledInputReturnsWithoutWaitingForNewline(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := readLineContext(ctx, r); done <- e }()
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation blocked")
	}
}
func TestParseCancelledStdin(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := App{Input: r, Output: io.Discard, Error: io.Discard}
	if code := a.Run(ctx, []string{"parse", "--model", "N9K"}); code != 130 {
		t.Fatal(code)
	}
}
