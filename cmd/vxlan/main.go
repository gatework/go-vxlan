package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/gatework/go-vxlan/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := cli.App{}
	code := a.Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
