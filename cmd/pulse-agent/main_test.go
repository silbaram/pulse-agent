package main

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestSignalContext_CancelsForTerminationSignals(t *testing.T) {
	tests := []struct {
		name   string
		signal os.Signal
	}{
		{name: "interrupt", signal: os.Interrupt},
		{name: "terminate", signal: syscall.SIGTERM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, stop := signalContext(context.Background())
			t.Cleanup(stop)

			process, err := os.FindProcess(os.Getpid())
			if err != nil {
				t.Fatalf("find current process: %v", err)
			}
			if err := process.Signal(tt.signal); err != nil {
				t.Fatalf("send %v: %v", tt.signal, err)
			}

			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatalf("context was not canceled after %v", tt.signal)
			}
		})
	}
}
