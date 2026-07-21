// Package observer evaluates direct probe results into deterministic health observations.
package observer

import (
	"context"
	"errors"
	"math"
	"sort"
	"sync"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/target"
	"pulse-agent/internal/telemetry"
)

const (
	maxValues  = 16
	maxValue   = 1_000_000.0
	maxSamples = 256
)

var (
	// ErrInvalidOptions indicates incomplete scheduler dependencies.
	ErrInvalidOptions = errors.New("invalid observer options")
	// ErrProbeFailed indicates a probe could not produce a usable sample.
	ErrProbeFailed = errors.New("probe failed")
)

// Clock supplies deterministic scheduler time.
type Clock interface {
	Now() time.Time
}

// Probe reads one direct target signal without exposing Docker implementation details.
type Probe interface {
	Observe(context.Context, contract.ServiceTarget, contract.ProbeRule) (map[string]float64, error)
}

// TargetSource provides immutable target snapshots for one scheduler cycle.
type TargetSource interface {
	Snapshot() target.Snapshot
}

// Options configures a synchronous, caller-owned scheduler.
type Options struct {
	// Targets supplies one immutable registry snapshot per cycle.
	Targets TargetSource
	// Probe performs one direct, cancellable signal read.
	Probe Probe
	// Clock supplies deterministic cycle timestamps.
	Clock Clock
	// NewObservationID creates immutable observation IDs.
	NewObservationID func() (string, error)
	// Telemetry records bounded scheduler measurements when configured.
	Telemetry *telemetry.Recorder
}

// Scheduler evaluates due rules using exactly one target snapshot per cycle.
// Its methods are safe for concurrent callers; a rule already running is skipped.
type Scheduler struct {
	targets   TargetSource
	probe     Probe
	clock     Clock
	newID     func() (string, error)
	telemetry *telemetry.Recorder

	mu       sync.Mutex
	lastRun  map[string]time.Time
	running  map[string]bool
	states   map[string]*ruleState
	sequence uint64
}

type ruleState struct {
	failures   int
	recoveries int
	samples    []sample
}

type sample struct {
	observedAt time.Time
	failed     bool
}

// NewScheduler creates a scheduler with injected time, probe, and ID sources.
func NewScheduler(options Options) (*Scheduler, error) {
	if options.Targets == nil || options.Probe == nil || options.Clock == nil || options.NewObservationID == nil {
		return nil, ErrInvalidOptions
	}
	return &Scheduler{targets: options.Targets, probe: options.Probe, clock: options.Clock, newID: options.NewObservationID, telemetry: options.Telemetry, lastRun: make(map[string]time.Time), running: make(map[string]bool), states: make(map[string]*ruleState)}, nil
}

// RunCycle evaluates every due rule from one immutable target snapshot. A
// cancelled context stops before starting the next probe.
func (s *Scheduler) RunCycle(ctx context.Context) ([]contract.HealthObservation, error) {
	if ctx == nil {
		return nil, ErrInvalidOptions
	}
	snapshot := s.targets.Snapshot()
	now := s.clock.Now()
	if now.IsZero() {
		return nil, ErrInvalidOptions
	}
	observations := make([]contract.HealthObservation, 0)
	for _, candidate := range snapshot.Targets {
		if !candidate.Enabled {
			continue
		}
		for _, rule := range candidate.ProbeRules {
			if err := ctx.Err(); err != nil {
				return observations, err
			}
			if !s.startDue(candidate.TargetID, rule, now) {
				continue
			}
			observation, err := s.observe(ctx, candidate, rule, snapshot.Version, now)
			s.finish(candidate.TargetID, rule.RuleID, now)
			if err != nil {
				return observations, err
			}
			observations = append(observations, observation)
		}
	}
	return observations, nil
}

func (s *Scheduler) startDue(targetID string, rule contract.ProbeRule, now time.Time) bool {
	key := targetID + "/" + rule.RuleID
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running[key] {
		return false
	}
	if previous := s.lastRun[key]; !previous.IsZero() && now.Sub(previous) < rule.Interval.Value() {
		return false
	}
	s.running[key] = true
	return true
}

func (s *Scheduler) finish(targetID, ruleID string, now time.Time) {
	key := targetID + "/" + ruleID
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.running, key)
	s.lastRun[key] = now
}

func (s *Scheduler) observe(ctx context.Context, candidate contract.ServiceTarget, rule contract.ProbeRule, snapshotVersion uint64, now time.Time) (contract.HealthObservation, error) {
	probeCtx, cancel := context.WithTimeout(ctx, rule.Timeout.Value())
	defer cancel()
	startedAt := time.Now()
	values, err := s.probe.Observe(probeCtx, candidate, rule)
	probeDuration := time.Since(startedAt)
	if err != nil {
		if ctx.Err() != nil {
			s.recordProbe(ctx, candidate, rule, telemetry.ResultUnavailable, telemetry.ReasonTimeout, probeDuration)
			return contract.HealthObservation{}, ctx.Err()
		}
		s.recordProbe(ctx, candidate, rule, telemetry.ResultUnavailable, telemetry.ReasonUnavailable, probeDuration)
		return contract.HealthObservation{}, ErrProbeFailed
	}
	bounded := boundedValues(values)
	failed, ok := failedSample(rule, bounded)
	if !ok {
		s.recordProbe(ctx, candidate, rule, telemetry.ResultRejected, telemetry.ReasonInvalid, probeDuration)
		return contract.HealthObservation{}, ErrProbeFailed
	}
	state := s.evaluate(candidate.TargetID, rule, now, failed)
	id, err := s.newID()
	if err != nil {
		s.recordProbe(ctx, candidate, rule, telemetry.ResultFailure, telemetry.ReasonInternal, probeDuration)
		return contract.HealthObservation{}, err
	}
	s.mu.Lock()
	s.sequence++
	sequence := s.sequence
	s.mu.Unlock()
	observation := contract.HealthObservation{SchemaVersion: contract.SchemaVersionV1, ObservationID: id, TargetID: candidate.TargetID, RuleID: rule.RuleID, TargetSnapshotVersion: snapshotVersion, ObservedAt: now, NormalizedState: state, BoundedValues: bounded, EvidenceRefs: []string{}, Sequence: sequence}
	if s.telemetry != nil {
		result, reason := telemetry.ResultSuccess, telemetry.ReasonNone
		if state == contract.StateUnhealthy {
			result, reason = telemetry.ResultRejected, telemetry.ReasonInvalid
		}
		s.recordProbe(ctx, candidate, rule, result, reason, probeDuration)
	}
	return observation, nil
}

func (s *Scheduler) recordProbe(ctx context.Context, candidate contract.ServiceTarget, rule contract.ProbeRule, result telemetry.Result, reason telemetry.Reason, duration time.Duration) {
	if s.telemetry == nil {
		return
	}
	dimensions := telemetry.Dimensions{}
	if targetKind, ok := telemetry.TargetForAdapter(candidate.AdapterType); ok {
		dimensions.Target = targetKind
	}
	if ruleKind, ok := telemetry.RuleForSignal(rule.SignalType); ok {
		dimensions.Rule = ruleKind
	}
	event, err := telemetry.NewEventWithDimensions(telemetry.ComponentObserver, telemetry.OperationRead, result, reason, duration, dimensions)
	if err == nil {
		s.telemetry.RecordBestEffort(ctx, event)
	}
}

func (s *Scheduler) evaluate(targetID string, rule contract.ProbeRule, now time.Time, failed bool) contract.NormalizedState {
	key := targetID + "/" + rule.RuleID
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.states[key]
	if state == nil {
		state = &ruleState{}
		s.states[key] = state
	}
	if len(state.samples) > 0 && now.Sub(state.samples[len(state.samples)-1].observedAt) > rule.SLOWindow.Value() {
		state.failures = 0
		state.recoveries = 0
	}
	state.samples = append(state.samples, sample{observedAt: now, failed: failed})
	cutoff := now.Add(-rule.SLOWindow.Value())
	first := 0
	for first < len(state.samples) && state.samples[first].observedAt.Before(cutoff) {
		first++
	}
	state.samples = append([]sample(nil), state.samples[first:]...)
	if len(state.samples) > maxSamples {
		state.samples = state.samples[len(state.samples)-maxSamples:]
	}
	if failed {
		state.failures++
		state.recoveries = 0
	} else {
		state.recoveries++
		state.failures = 0
	}
	if state.failures >= rule.ConsecutiveFailures {
		return contract.StateUnhealthy
	}
	if state.recoveries >= rule.RecoverySamples {
		return contract.StateHealthy
	}
	return contract.StateUnknown
}

func failedSample(rule contract.ProbeRule, values map[string]float64) (bool, bool) {
	value, found := values[rule.SignalType]
	if !found {
		return false, false
	}
	if rule.SignalType == "availability" {
		return value < rule.Threshold, true
	}
	return value > rule.Threshold, true
}

func boundedValues(values map[string]float64) map[string]float64 {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	bounded := make(map[string]float64, min(len(keys), maxValues))
	for _, key := range keys {
		if len(bounded) == maxValues {
			break
		}
		value := values[key]
		if math.IsNaN(value) || math.IsInf(value, 0) {
			continue
		}
		if value > maxValue {
			value = maxValue
		}
		if value < -maxValue {
			value = -maxValue
		}
		bounded[key] = value
	}
	return bounded
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
