// Package docker provides the bounded Docker Engine adapter used by Pulse Agent.
package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/evidence"
	"pulse-agent/internal/telemetry"
)

const (
	// AdapterType identifies the Docker Engine adapter.
	AdapterType         = "docker"
	composeServiceLabel = "com.docker.compose.service"
)

var (
	// ErrInvalidOptions indicates a missing dependency or unsafe adapter bound.
	ErrInvalidOptions = errors.New("invalid docker adapter options")
	// ErrInvalidTarget indicates a target is outside the Docker adapter boundary.
	ErrInvalidTarget = errors.New("invalid docker target")
	// ErrAmbiguousTarget indicates a selector did not resolve to exactly one container.
	ErrAmbiguousTarget = errors.New("ambiguous docker target")
	// ErrPrecondition indicates a target is not safe to restart in its current state.
	ErrPrecondition = errors.New("docker action precondition failed")
	// ErrUnsafeAction indicates an action is not one of the two allowed typed restarts.
	ErrUnsafeAction = errors.New("unsafe docker action")
	// ErrUnavailable indicates Docker Engine could not complete a bounded request.
	ErrUnavailable = errors.New("docker engine unavailable")
	// ErrTimeout indicates a bounded Docker Engine request exceeded its deadline.
	ErrTimeout = errors.New("docker request timed out")
)

// Container is the bounded Docker state used by the adapter.
type Container struct {
	ID      string
	Running bool
	Health  string
	Labels  map[string]string
}

// Client is the least-privilege Docker Engine SDK surface used by Adapter.
// It deliberately has no exec, remove, scale, compose-down, or raw-command API.
type Client interface {
	NegotiateAPIVersion(context.Context) error
	Inspect(context.Context, string) (Container, error)
	ListByLabel(context.Context, string, string) ([]Container, error)
	Logs(context.Context, string) (io.ReadCloser, error)
	Restart(context.Context, string, time.Duration) error
}

// Clock supplies deterministic evidence timestamps.
type Clock interface {
	Now() time.Time
}

// Options configures a bounded Docker Engine adapter.
type Options struct {
	Client      Client
	Evidence    *evidence.Collector
	Clock       Clock
	MaxLogBytes int
	Timeout     time.Duration
	// Telemetry records bounded Docker action outcomes without exporting target IDs or errors.
	Telemetry *telemetry.Recorder
}

// Snapshot is a bounded view of one Docker container's state and health.
type Snapshot struct {
	TargetID string
	Running  bool
	Healthy  bool
}

// Adapter observes and restarts only registered Docker targets.
type Adapter struct {
	client      Client
	evidence    *evidence.Collector
	clock       Clock
	maxLogBytes int
	timeout     time.Duration
	telemetry   *telemetry.Recorder

	mu         sync.Mutex
	negotiated bool
}

// NewAdapter validates dependencies and creates a bounded Docker adapter.
func NewAdapter(options Options) (*Adapter, error) {
	if options.Client == nil || options.Evidence == nil || options.Clock == nil || options.MaxLogBytes < 1 || options.Timeout < time.Millisecond {
		return nil, ErrInvalidOptions
	}
	return &Adapter{client: options.Client, evidence: options.Evidence, clock: options.Clock, maxLogBytes: options.MaxLogBytes, timeout: options.Timeout, telemetry: options.Telemetry}, nil
}

// Discover resolves a target to exactly one Docker container and returns its bounded state.
func (a *Adapter) Discover(ctx context.Context, target contract.ServiceTarget) (Snapshot, error) {
	container, err := a.resolve(ctx, target)
	if err != nil {
		return Snapshot{}, err
	}
	return snapshot(target.TargetID, container), nil
}

// Observe implements observer.Probe for Docker availability rules.
func (a *Adapter) Observe(ctx context.Context, target contract.ServiceTarget, rule contract.ProbeRule) (map[string]float64, error) {
	if rule.SignalType != "availability" {
		return nil, ErrInvalidTarget
	}
	state, err := a.Discover(ctx, target)
	if err != nil {
		return nil, err
	}
	availability := 0.0
	if state.Healthy {
		availability = 1
	}
	return map[string]float64{"availability": availability}, nil
}

// CollectEvidence reads bounded Docker logs and passes them through the shared redactor.
func (a *Adapter) CollectEvidence(ctx context.Context, target contract.ServiceTarget) (evidence.Result, error) {
	container, err := a.resolve(ctx, target)
	if err != nil {
		return evidence.Result{}, err
	}
	requestCtx, cancel := a.requestContext(ctx)
	defer cancel()
	stream, err := a.client.Logs(requestCtx, container.ID)
	if err != nil {
		return evidence.Result{}, a.mapError(requestCtx, err)
	}
	defer stream.Close()
	contents, readErr := io.ReadAll(io.LimitReader(stream, int64(a.logLimit(target))))
	if readErr != nil {
		return evidence.Result{}, a.mapError(requestCtx, readErr)
	}
	now := a.clock.Now()
	if now.IsZero() {
		return evidence.Result{}, ErrInvalidOptions
	}
	records := make([]evidence.Record, 0)
	for _, line := range strings.Split(string(contents), "\n") {
		if line != "" {
			records = append(records, evidence.Record{At: now, Fields: map[string]string{"message": line}})
		}
	}
	result, err := a.evidence.Collect("docker", target.EvidencePolicy.RedactionProfile, now, now, records)
	if err != nil {
		return evidence.Result{}, err
	}
	return result, nil
}

// ValidateAction checks an exact target selector and safe restart preconditions.
// A running unhealthy container is eligible: health is the recovery trigger,
// while post-restart health belongs to the stabilization verifier.
func (a *Adapter) ValidateAction(ctx context.Context, target contract.ServiceTarget, action contract.TypedAction) (err error) {
	startedAt := time.Now()
	defer func() { a.recordAction(ctx, telemetry.OperationValidate, startedAt, err) }()
	_, err = a.validatedContainer(ctx, target, action)
	return err
}

func (a *Adapter) validatedContainer(ctx context.Context, target contract.ServiceTarget, action contract.TypedAction) (Container, error) {
	if err := validAction(target, action); err != nil {
		return Container{}, err
	}
	container, err := a.resolve(ctx, target)
	if err != nil {
		return Container{}, err
	}
	if !container.Running {
		return Container{}, ErrPrecondition
	}
	return container, nil
}

// Execute validates then performs only the approved SDK restart operation.
func (a *Adapter) Execute(ctx context.Context, target contract.ServiceTarget, action contract.TypedAction) (err error) {
	startedAt := time.Now()
	defer func() { a.recordAction(ctx, telemetry.OperationExecute, startedAt, err) }()
	container, err := a.validatedContainer(ctx, target, action)
	if err != nil {
		return err
	}
	requestCtx, cancel := a.requestContext(ctx)
	defer cancel()
	if err := a.client.Restart(requestCtx, container.ID, action.StopTimeout.Value()); err != nil {
		return a.mapError(requestCtx, err)
	}
	return nil
}

func (a *Adapter) recordAction(ctx context.Context, operation telemetry.Operation, startedAt time.Time, actionErr error) {
	if a == nil || a.telemetry == nil {
		return
	}
	result, reason := telemetry.ResultSuccess, telemetry.ReasonAccepted
	if actionErr != nil {
		switch {
		case errors.Is(actionErr, ErrInvalidTarget), errors.Is(actionErr, ErrAmbiguousTarget), errors.Is(actionErr, ErrPrecondition), errors.Is(actionErr, ErrUnsafeAction):
			result, reason = telemetry.ResultRejected, telemetry.ReasonInvalid
		case errors.Is(actionErr, ErrTimeout), errors.Is(actionErr, context.DeadlineExceeded):
			result, reason = telemetry.ResultUnavailable, telemetry.ReasonTimeout
		case errors.Is(actionErr, context.Canceled):
			result, reason = telemetry.ResultUnavailable, telemetry.ReasonUnavailable
		default:
			result, reason = telemetry.ResultUnavailable, telemetry.ReasonUnavailable
		}
	}
	event, err := telemetry.NewEventWithDimensions(telemetry.ComponentDocker, operation, result, reason, time.Since(startedAt), telemetry.Dimensions{Target: telemetry.TargetDocker})
	if err == nil {
		a.telemetry.RecordBestEffort(ctx, event)
	}
}

// Verify confirms bounded Docker state after a recovery action.
func (a *Adapter) Verify(ctx context.Context, target contract.ServiceTarget) (Snapshot, error) {
	return a.Discover(ctx, target)
}

func (a *Adapter) resolve(ctx context.Context, target contract.ServiceTarget) (Container, error) {
	kind, value, ok := selector(target)
	if !ok {
		return Container{}, ErrInvalidTarget
	}
	requestCtx, cancel := a.requestContext(ctx)
	defer cancel()
	if err := a.negotiate(requestCtx); err != nil {
		return Container{}, err
	}
	if kind == "container" {
		container, err := a.client.Inspect(requestCtx, value)
		if err != nil {
			return Container{}, a.mapError(requestCtx, err)
		}
		if container.ID == "" {
			return Container{}, ErrAmbiguousTarget
		}
		return container, nil
	}
	containers, err := a.client.ListByLabel(requestCtx, composeServiceLabel, value)
	if err != nil {
		return Container{}, a.mapError(requestCtx, err)
	}
	if len(containers) != 1 || containers[0].ID == "" || containers[0].Labels[composeServiceLabel] != value {
		return Container{}, ErrAmbiguousTarget
	}
	return containers[0], nil
}

func (a *Adapter) negotiate(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.negotiated {
		return nil
	}
	if err := a.client.NegotiateAPIVersion(ctx); err != nil {
		return a.mapError(ctx, err)
	}
	a.negotiated = true
	return nil
}

func (a *Adapter) requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, a.timeout)
}

func (a *Adapter) mapError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrTimeout, context.DeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return context.Canceled
	}
	return fmt.Errorf("%w", ErrUnavailable)
}

func (a *Adapter) logLimit(target contract.ServiceTarget) int {
	if target.EvidencePolicy.MaxBytes > 0 && target.EvidencePolicy.MaxBytes < a.maxLogBytes {
		return target.EvidencePolicy.MaxBytes
	}
	return a.maxLogBytes
}

func selector(target contract.ServiceTarget) (string, string, bool) {
	if target.SchemaVersion != contract.SchemaVersionV1 || target.AdapterType != AdapterType || !target.Enabled {
		return "", "", false
	}
	kind, value, found := strings.Cut(target.Selector, ":")
	if !found || !validSelectorValue(value) || (kind != "container" && kind != "compose_service") {
		return "", "", false
	}
	return kind, value, true
}

func validSelectorValue(value string) bool {
	if value == "" || len(value) > 96 || strings.Contains(value, "..") {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || (index > 0 && (character == '.' || character == '_' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

func validAction(target contract.ServiceTarget, action contract.TypedAction) error {
	kind, _, ok := selector(target)
	if !ok || action.TargetSelector != target.Selector || action.StopTimeout.Value() < 0 || action.Cooldown.Value() < 0 {
		return ErrUnsafeAction
	}
	if (kind == "container" && action.ActionType != contract.ActionDockerContainerRestart) || (kind == "compose_service" && action.ActionType != contract.ActionDockerComposeServiceRestart) {
		return ErrUnsafeAction
	}
	return nil
}

func snapshot(targetID string, container Container) Snapshot {
	return Snapshot{TargetID: targetID, Running: container.Running, Healthy: container.Running && container.Health != "unhealthy"}
}
