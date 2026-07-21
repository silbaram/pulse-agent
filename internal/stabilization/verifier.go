// Package stabilization verifies recovery separately from a Docker command result.
package stabilization

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/docker"
	"pulse-agent/internal/policy"
	"pulse-agent/internal/store"
)

const (
	maxRecoverySamples      = 256
	maxStabilizationDocSize = 64 * 1024
	stabilizationKeyPrefix  = "stabilization/"
)

var (
	// ErrInvalidOptions indicates that a verifier dependency is missing.
	ErrInvalidOptions = errors.New("invalid stabilization verifier options")
	// ErrInvalidRequest indicates that a command cannot be stabilized safely.
	ErrInvalidRequest = errors.New("invalid stabilization request")
	// ErrCorruptResult indicates an invalid persisted stabilization result.
	ErrCorruptResult = errors.New("corrupt stabilization result")
)

// Clock supplies deterministic stabilization timestamps.
type Clock interface {
	// Now returns the current verifier time.
	Now() time.Time
}

// Probe returns one bounded, deterministic health sample for a registered target.
// A probe must not execute recovery actions.
type Probe interface {
	// Observe reads one current health sample.
	Observe(context.Context, contract.ServiceTarget) (Sample, error)
}

// CommandFinalizer records the terminal outcome after stabilization. It is
// intentionally separate from Probe so observing health cannot change Docker state.
type CommandFinalizer interface {
	// CompleteStabilization records one terminal verification result.
	CompleteStabilization(commandID string, succeeded bool) (contract.RecoveryCommand, error)
}

// RetryStateSource reloads current authorization facts before a retry is
// scheduled. The verifier never executes a retry itself; callers must create a
// new recovery command through the normal coordinator path.
type RetryStateSource interface {
	// LoadRetryState returns the current target and deterministic policy inputs.
	LoadRetryState(context.Context, contract.RecoveryCommand) (RetryState, error)
}

// RetryState is the daemon-owned policy view used for one retry recheck.
type RetryState struct {
	// Target is the current registered target.
	Target contract.ServiceTarget
	// PolicySnapshot is the current registered-runbook snapshot.
	PolicySnapshot policy.Snapshot
	// PolicyInput contains current digest, preconditions, cooldown, and attempts.
	PolicyInput policy.Input
}

// Sample is one bounded health and metric reading. Metrics use the registered
// probe signal type as a key and must not contain NaN or infinite values.
type Sample struct {
	Healthy bool
	Metrics map[string]float64
}

// Outcome identifies the durable verification result for one recovery attempt.
type Outcome string

const (
	// OutcomePending identifies an attempt that still needs samples or time.
	OutcomePending Outcome = "pending"
	// OutcomeSucceeded identifies a command that passed all stabilization checks.
	OutcomeSucceeded Outcome = "succeeded"
	// OutcomeRetryScheduled identifies a failed attempt with one policy-authorized retry.
	OutcomeRetryScheduled Outcome = "retry_scheduled"
	// OutcomeFailed identifies a terminal stabilization failure.
	OutcomeFailed Outcome = "failed"
)

// FailureReason identifies why stabilization, rather than command execution,
// did not complete successfully.
type FailureReason string

const (
	// FailureNone identifies a pending or successful verification.
	FailureNone FailureReason = ""
	// FailureUnhealthy identifies a target that remains unhealthy after recovery.
	FailureUnhealthy FailureReason = "unhealthy"
	// FailureFlapping identifies a healthy sequence interrupted before completion.
	FailureFlapping FailureReason = "flapping"
	// FailureTimeout identifies an elapsed stabilization window or probe deadline.
	FailureTimeout FailureReason = "timeout"
	// FailureMetricRegression identifies a registered SLI threshold regression.
	FailureMetricRegression FailureReason = "metric_regression"
	// FailureDockerUnavailable identifies an unavailable Docker Engine during verification.
	FailureDockerUnavailable FailureReason = "docker_unavailable"
	// FailureProbe identifies an unclassified probe failure.
	FailureProbe FailureReason = "probe_failed"
)

// Options configures a verifier with daemon-owned persistence and policy seams.
type Options struct {
	// State persists stabilization observations separately from the command journal.
	State *store.Store
	// Probe supplies bounded post-recovery health samples.
	Probe Probe
	// Clock supplies deterministic verification time.
	Clock Clock
	// Finalizer moves a recovery command from stabilizing to its terminal state.
	Finalizer CommandFinalizer
	// RetryState reloads current policy facts before recording a retry schedule.
	RetryState RetryStateSource
}

// Verifier accumulates bounded post-recovery samples. Its zero value is invalid.
type Verifier struct {
	state      *store.Store
	probe      Probe
	clock      Clock
	finalizer  CommandFinalizer
	retryState RetryStateSource
}

// Request identifies one stabilization attempt. Attempt is zero based and is
// independent from a command's immutable identity; a retry must use a new
// command after this verifier records the prior attempt as failed.
type Request struct {
	// Command is a recovery command whose Docker action has already returned successfully.
	Command contract.RecoveryCommand
	// Target is the target observed by the verifier.
	Target contract.ServiceTarget
	// Policy defines required samples and the stabilization window.
	Policy contract.StabilizationPolicy
	// RetryPolicy bounds total recovery attempts, including this attempt.
	RetryPolicy contract.RetryPolicy
	// Attempt is the zero-based attempt being stabilized.
	Attempt int
}

// Result reports a durable stabilization result separate from command execution.
type Result struct {
	// CommandID identifies the command whose execution is being verified.
	CommandID string
	// ExecutionSucceeded records that the Docker action reached stabilization;
	// it remains true even when the separate stabilization result fails.
	ExecutionSucceeded bool
	// Attempt identifies the zero-based recovery attempt.
	Attempt int
	// StartedAt is the first verifier timestamp for this attempt.
	StartedAt time.Time
	// HealthySamples is the current consecutive healthy sample count.
	HealthySamples int
	// Outcome identifies pending, success, retry, or terminal failure.
	Outcome Outcome
	// FailureReason identifies the stabilization-only failure, when present.
	FailureReason FailureReason
	// RetryReason is the policy result used when a retry was considered.
	RetryReason policy.ReasonCode
	// NextAttempt is the zero-based retry number, or -1 when none is scheduled.
	NextAttempt int
}

type resultRecord struct {
	SchemaVersion      string            `json:"schema_version"`
	CommandID          string            `json:"command_id"`
	ExecutionSucceeded bool              `json:"execution_succeeded"`
	Attempt            int               `json:"attempt"`
	StartedAt          time.Time         `json:"started_at"`
	HealthySamples     int               `json:"healthy_samples"`
	Outcome            Outcome           `json:"outcome"`
	FailureReason      FailureReason     `json:"failure_reason,omitempty"`
	RetryReason        policy.ReasonCode `json:"retry_reason,omitempty"`
	NextAttempt        int               `json:"next_attempt"`
}

// New constructs a verifier after validating its required dependencies.
func New(options Options) (*Verifier, error) {
	if options.State == nil || options.Probe == nil || options.Clock == nil || options.Finalizer == nil || options.RetryState == nil {
		return nil, ErrInvalidOptions
	}
	return &Verifier{state: options.State, probe: options.Probe, clock: options.Clock, finalizer: options.Finalizer, retryState: options.RetryState}, nil
}

// Verify records one stabilization sample. Callers control the scheduling cadence;
// this method never sleeps or executes Docker operations. A command completes only
// after the required consecutive samples and the full stabilization window pass.
func (v *Verifier) Verify(ctx context.Context, request Request) (Result, error) {
	if v == nil || ctx == nil || validateRequest(request) != nil {
		return Result{}, ErrInvalidRequest
	}
	now, err := v.now()
	if err != nil {
		return Result{}, err
	}
	record, found, err := v.load(request.Command.CommandID, request.Attempt)
	if err != nil {
		return Result{}, err
	}
	if found && record.Outcome != OutcomePending {
		return record.result(), nil
	}
	if !found {
		record = resultRecord{
			SchemaVersion:      contract.SchemaVersionV1,
			CommandID:          request.Command.CommandID,
			ExecutionSucceeded: true,
			Attempt:            request.Attempt,
			StartedAt:          now,
			Outcome:            OutcomePending,
			NextAttempt:        -1,
		}
	}
	deadline := record.StartedAt.Add(request.Policy.Window.Value())
	if now.After(deadline) {
		return v.fail(ctx, request, record, now, FailureTimeout)
	}

	sample, probeErr := v.probe.Observe(ctx, request.Target)
	if probeErr != nil {
		return v.fail(ctx, request, record, now, probeFailureReason(probeErr))
	}
	if !validSample(sample) {
		return v.fail(ctx, request, record, now, FailureProbe)
	}
	if !sample.Healthy {
		reason := FailureUnhealthy
		if record.HealthySamples > 0 {
			reason = FailureFlapping
		}
		return v.fail(ctx, request, record, now, reason)
	}
	if !metricsMeetRules(sample.Metrics, request.Target.ProbeRules) {
		return v.fail(ctx, request, record, now, FailureMetricRegression)
	}

	record.HealthySamples++
	if record.HealthySamples >= request.Policy.RecoverySamples && !now.Before(deadline) {
		record.Outcome = OutcomeSucceeded
		if err := v.complete(record.CommandID, true); err != nil {
			return Result{}, err
		}
		if err := v.persist(record); err != nil {
			return Result{}, err
		}
		return record.result(), nil
	}
	if err := v.persist(record); err != nil {
		return Result{}, err
	}
	return record.result(), nil
}

func (v *Verifier) fail(ctx context.Context, request Request, record resultRecord, now time.Time, reason FailureReason) (Result, error) {
	record.FailureReason = reason
	record.HealthySamples = 0
	record.NextAttempt = -1
	if request.Attempt+1 < request.RetryPolicy.MaxAttempts {
		decision, err := v.retryDecision(ctx, request, now)
		if err != nil {
			record.Outcome = OutcomeFailed
			record.RetryReason = policy.ReasonInvalidPolicy
			if finalizeErr := v.complete(record.CommandID, false); finalizeErr != nil {
				return Result{}, finalizeErr
			}
			if persistErr := v.persist(record); persistErr != nil {
				return Result{}, persistErr
			}
			return record.result(), fmt.Errorf("recheck stabilization retry: %w", err)
		}
		record.RetryReason = decision.ReasonCode
		if decision.Verdict == policy.VerdictAllow {
			record.Outcome = OutcomeRetryScheduled
			record.NextAttempt = request.Attempt + 1
		} else {
			record.Outcome = OutcomeFailed
		}
	} else {
		record.Outcome = OutcomeFailed
		record.RetryReason = policy.ReasonRetryExhausted
	}
	if err := v.complete(record.CommandID, false); err != nil {
		return Result{}, err
	}
	if err := v.persist(record); err != nil {
		return Result{}, err
	}
	return record.result(), nil
}

func (v *Verifier) complete(commandID string, succeeded bool) error {
	if _, err := v.finalizer.CompleteStabilization(commandID, succeeded); err != nil {
		if succeeded {
			return fmt.Errorf("complete successful stabilization: %w", err)
		}
		return fmt.Errorf("complete failed stabilization: %w", err)
	}
	return nil
}

func (v *Verifier) retryDecision(ctx context.Context, request Request, now time.Time) (policy.Decision, error) {
	state, err := v.retryState.LoadRetryState(ctx, request.Command)
	if err != nil {
		return policy.Decision{}, fmt.Errorf("load retry state: %w", err)
	}
	input := state.PolicyInput
	if input.RunbookID != request.Command.RunbookID || input.TargetID != request.Command.TargetID || input.ActionIndex != request.Command.ActionIndex || !sameTarget(state.Target, request.Target) {
		return policy.Decision{Verdict: policy.VerdictDeny, ReasonCode: policy.ReasonInvalidPolicy}, nil
	}
	input.CommandID = request.Command.CommandID
	input.RunbookDigest = request.Command.RunbookDigest
	input.Now = now
	input.AttemptCount = max(input.AttemptCount, request.Attempt+1)
	return policy.Evaluate(state.PolicySnapshot, input), nil
}

func (v *Verifier) now() (time.Time, error) {
	if v.clock == nil {
		return time.Time{}, ErrInvalidOptions
	}
	now := v.clock.Now().UTC()
	if now.IsZero() {
		return time.Time{}, ErrInvalidOptions
	}
	return now, nil
}

func (v *Verifier) load(commandID string, attempt int) (resultRecord, bool, error) {
	var (
		record resultRecord
		found  bool
	)
	err := v.state.View(func(transaction *store.Tx) error {
		document, exists, err := transaction.Get(store.BucketStabilizationResults, resultKey(commandID, attempt))
		if err != nil || !exists {
			found = exists
			return err
		}
		decoded, err := contract.Decode(document, contract.DecodeOptions[resultRecord]{
			MaxBytes:      maxStabilizationDocSize,
			SchemaVersion: contract.SchemaVersionV1,
			Validate:      validateRecord,
		})
		if err != nil {
			return ErrCorruptResult
		}
		record, found = decoded, true
		return nil
	})
	if err != nil {
		return resultRecord{}, false, fmt.Errorf("load stabilization result: %w", err)
	}
	if found && (record.CommandID != commandID || record.Attempt != attempt) {
		return resultRecord{}, false, ErrCorruptResult
	}
	return record, found, nil
}

func (v *Verifier) persist(record resultRecord) error {
	if err := validateRecord(record); err != nil {
		return ErrCorruptResult
	}
	document, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode stabilization result: %w", err)
	}
	if err := v.state.Update(func(transaction *store.Tx) error {
		return transaction.Put(store.BucketStabilizationResults, resultKey(record.CommandID, record.Attempt), document)
	}); err != nil {
		return fmt.Errorf("persist stabilization result: %w", err)
	}
	return nil
}

func (r resultRecord) result() Result {
	return Result{
		CommandID:          r.CommandID,
		ExecutionSucceeded: r.ExecutionSucceeded,
		Attempt:            r.Attempt,
		StartedAt:          r.StartedAt,
		HealthySamples:     r.HealthySamples,
		Outcome:            r.Outcome,
		FailureReason:      r.FailureReason,
		RetryReason:        r.RetryReason,
		NextAttempt:        r.NextAttempt,
	}
}

func validateRequest(request Request) error {
	if request.Command.Validate() != nil || request.Command.State != contract.RecoveryStabilizing || request.Target.SchemaVersion != contract.SchemaVersionV1 || !request.Target.Enabled || request.Target.TargetID != request.Command.TargetID || request.Policy.RecoverySamples < 1 || request.Policy.RecoverySamples > maxRecoverySamples || request.Policy.Window.Value() <= 0 || request.RetryPolicy.MaxAttempts < 1 || request.Attempt < 0 || request.Attempt >= request.RetryPolicy.MaxAttempts {
		return ErrInvalidRequest
	}
	return nil
}

func validateRecord(record resultRecord) error {
	if record.SchemaVersion != contract.SchemaVersionV1 || record.CommandID == "" || !record.ExecutionSucceeded || record.Attempt < 0 || record.StartedAt.IsZero() || record.HealthySamples < 0 || record.HealthySamples > maxRecoverySamples || record.NextAttempt < -1 {
		return ErrCorruptResult
	}
	switch record.Outcome {
	case OutcomePending:
		if record.FailureReason != FailureNone || record.RetryReason != "" || record.NextAttempt != -1 {
			return ErrCorruptResult
		}
	case OutcomeSucceeded:
		if record.FailureReason != FailureNone || record.RetryReason != "" || record.NextAttempt != -1 {
			return ErrCorruptResult
		}
	case OutcomeRetryScheduled:
		if !validFailureReason(record.FailureReason) || record.FailureReason == FailureNone || record.RetryReason != policy.ReasonAllowed || record.NextAttempt != record.Attempt+1 {
			return ErrCorruptResult
		}
	case OutcomeFailed:
		if !validFailureReason(record.FailureReason) || record.FailureReason == FailureNone || record.NextAttempt != -1 {
			return ErrCorruptResult
		}
	default:
		return ErrCorruptResult
	}
	return nil
}

func validSample(sample Sample) bool {
	for _, value := range sample.Metrics {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return false
		}
	}
	return true
}

func metricsMeetRules(metrics map[string]float64, rules []contract.ProbeRule) bool {
	for _, rule := range rules {
		value, found := metrics[rule.SignalType]
		if !found {
			return false
		}
		if rule.SignalType == "availability" {
			if value < rule.Threshold {
				return false
			}
			continue
		}
		if value > rule.Threshold {
			return false
		}
	}
	return true
}

func probeFailureReason(err error) FailureReason {
	if errors.Is(err, docker.ErrUnavailable) {
		return FailureDockerUnavailable
	}
	if errors.Is(err, docker.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
		return FailureTimeout
	}
	return FailureProbe
}

func validFailureReason(reason FailureReason) bool {
	switch reason {
	case FailureNone, FailureUnhealthy, FailureFlapping, FailureTimeout, FailureMetricRegression, FailureDockerUnavailable, FailureProbe:
		return true
	default:
		return false
	}
}

func sameTarget(left, right contract.ServiceTarget) bool {
	return left.SchemaVersion == right.SchemaVersion && left.TargetID == right.TargetID && left.AdapterType == right.AdapterType && left.Selector == right.Selector && left.Enabled == right.Enabled
}

func resultKey(commandID string, attempt int) string {
	sum := sha256.Sum256([]byte(commandID + "\x00" + strconv.Itoa(attempt)))
	return stabilizationKeyPrefix + hex.EncodeToString(sum[:])
}
