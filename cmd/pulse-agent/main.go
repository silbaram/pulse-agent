// Command pulse-agent runs the Pulse Agent standalone service and local
// administrative CLI.
package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"pulse-agent/internal/command"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signalContext(context.Background())
	defer stop()

	return command.Execute(ctx, args, stdout, stderr)
}

func signalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}
