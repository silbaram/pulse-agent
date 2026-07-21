// Package standalone owns the standalone process lifecycle.
package standalone

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"pulse-agent/internal/adminipc"
	"pulse-agent/internal/config"
	"pulse-agent/internal/runbook"
	"pulse-agent/internal/store"
	"pulse-agent/internal/target"
)

const (
	defaultShutdownTimeout  = 10 * time.Second
	defaultStoreLockTimeout = time.Second
	stateFileName           = "state.db"
)

var (
	// ErrAlreadyStarted indicates that a Service was run more than once.
	ErrAlreadyStarted = errors.New("standalone service already started")
	// ErrShutdownTimeout indicates that accepted work did not drain in time.
	ErrShutdownTimeout = errors.New("standalone shutdown timed out")
)

// Service coordinates admission and bounded graceful shutdown for standalone
// work. A Service can be run only once.
type Service struct {
	shutdownTimeout time.Duration

	mu        sync.Mutex
	started   bool
	accepting bool
	active    int
	drained   chan struct{}
}

// New returns a Service with the default graceful shutdown timeout.
func New() *Service {
	return newService(defaultShutdownTimeout)
}

func newService(shutdownTimeout time.Duration) *Service {
	return &Service{
		shutdownTimeout: shutdownTimeout,
		drained:         make(chan struct{}),
	}
}

// Run accepts work until ctx is canceled, then rejects new work and waits for
// accepted work to finish within the shutdown timeout.
func (s *Service) Run(ctx context.Context) error {
	if err := s.start(); err != nil {
		return err
	}

	<-ctx.Done()
	return s.drain()
}

// RunWithConfig opens daemon-owned local state, serves protected
// administrative IPC, and drains any admitted standalone work at shutdown.
func (s *Service) RunWithConfig(ctx context.Context, runtimeConfig config.Config) (runErr error) {
	if err := runtimeConfig.Validate(); err != nil {
		return err
	}
	state, err := store.Open(store.Options{
		Path:        filepath.Join(runtimeConfig.DataDirectory, stateFileName),
		LockTimeout: defaultStoreLockTimeout,
	})
	if err != nil {
		return fmt.Errorf("open daemon-owned state: %w", err)
	}
	defer func() {
		if closeErr := state.Close(); runErr == nil && closeErr != nil {
			runErr = fmt.Errorf("close daemon-owned state: %w", closeErr)
		}
	}()
	allowedTargets := make([]target.AllowedTarget, len(runtimeConfig.AllowedTargets))
	for index, configured := range runtimeConfig.AllowedTargets {
		allowedTargets[index] = target.AllowedTarget{
			TargetID:    configured.TargetID,
			AdapterType: configured.AdapterType,
		}
	}
	registry, err := target.NewRegistry(target.Options{
		State:            state,
		AllowedTargets:   allowedTargets,
		MaxTargets:       runtimeConfig.Limits.MaxTargets,
		MaxEvidenceBytes: runtimeConfig.Limits.Retention.MaxBytes,
		Clock:            time.Now,
		NewAuditEventID:  target.NewAuditEventID,
	})
	if err != nil {
		return fmt.Errorf("create target registry: %w", err)
	}
	runbooks, err := runbook.NewRegistry(runbook.Options{
		State:           state,
		Clock:           time.Now,
		NewAuditEventID: runbook.NewAuditEventID,
	})
	if err != nil {
		return fmt.Errorf("create runbook registry: %w", err)
	}

	server, err := adminipc.NewServer(adminipc.Options{
		SocketPath:  runtimeConfig.Admin.SocketPath,
		AllowedUIDs: runtimeConfig.Admin.AllowedUIDs,
		AllowedGIDs: runtimeConfig.Admin.AllowedGIDs,
		State:       state,
		Targets:     registry,
		Runbooks:    runbooks,
		Clock:       adminipc.SystemClock,
		NewAuditID:  adminipc.NewAuditID,
	})
	if err != nil {
		return fmt.Errorf("create administrative IPC server: %w", err)
	}
	if err := s.start(); err != nil {
		return err
	}

	serveErr := server.Serve(ctx)
	drainErr := s.drain()
	if serveErr != nil {
		return serveErr
	}
	return drainErr
}

func (s *Service) drain() error {
	drained := s.stopAccepting()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()

	select {
	case <-drained:
		return nil
	case <-shutdownCtx.Done():
		return ErrShutdownTimeout
	}
}

// BeginWork admits one unit of work while the service is accepting. The
// returned completion function is safe to call more than once.
func (s *Service) BeginWork() (complete func(), accepted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.accepting {
		return nil, false
	}

	s.active++
	var once sync.Once
	return func() {
		once.Do(s.completeWork)
	}, true
}

// Accepting reports whether the service currently accepts new work.
func (s *Service) Accepting() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.accepting
}

func (s *Service) start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return ErrAlreadyStarted
	}

	s.started = true
	s.accepting = true
	return nil
}

func (s *Service) stopAccepting() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.accepting = false
	if s.active == 0 {
		close(s.drained)
	}
	return s.drained
}

func (s *Service) completeWork() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.active--
	if !s.accepting && s.active == 0 {
		close(s.drained)
	}
}
