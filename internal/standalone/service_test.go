package standalone

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
)

func TestService_RunStopsAdmissionAndDrainsAcceptedWork(t *testing.T) {
	service := newService(time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	runResult := make(chan error, 1)

	go func() {
		runResult <- service.Run(ctx)
	}()

	complete := waitForAcceptedWork(t, service)
	cancel()
	waitForAdmissionToStop(t, service)

	if _, accepted := service.BeginWork(); accepted {
		t.Fatal("BeginWork() accepted work after cancellation")
	}

	complete()
	complete()

	select {
	case err := <-runResult:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not finish after accepted work drained")
	}
}

func TestService_RunBoundsGracefulShutdown(t *testing.T) {
	service := newService(20 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	runResult := make(chan error, 1)

	go func() {
		runResult <- service.Run(ctx)
	}()

	complete := waitForAcceptedWork(t, service)
	t.Cleanup(complete)
	cancel()

	select {
	case err := <-runResult:
		if !errors.Is(err, ErrShutdownTimeout) {
			t.Fatalf("Run() error = %v, want %v", err, ErrShutdownTimeout)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() exceeded the bounded shutdown deadline")
	}
}

func TestService_RunRejectsSecondStart(t *testing.T) {
	service := newService(time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := service.Run(ctx); err != nil {
		t.Fatalf("first Run() error = %v, want nil", err)
	}
	if err := service.Run(ctx); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Run() error = %v, want %v", err, ErrAlreadyStarted)
	}
}

func waitForAcceptedWork(t *testing.T, service *Service) func() {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if complete, accepted := service.BeginWork(); accepted {
			return complete
		}
		runtime.Gosched()
	}
	t.Fatal("service did not start accepting work")
	return nil
}

func waitForAdmissionToStop(t *testing.T, service *Service) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if !service.Accepting() {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("service did not stop accepting work")
}
