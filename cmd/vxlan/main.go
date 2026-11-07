package main

import (
	"context"
	"github.com/gatework/go-vxlan/cli"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := cli.App{}
	code := a.Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
