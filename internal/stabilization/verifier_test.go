package stabilization

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/docker"
	"pulse-agent/internal/policy"
	"pulse-agent/internal/store"
	"pulse-agent/internal/telemetry"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestVerifier_SucceedsOnlyAfterSamplesAndWindow(t *testing.T) {
	now := testNow()
	clock := &fakeClock{times: []time.Time{now, now.Add(30 * time.Second), now.Add(time.Minute)}}
	probe := &fakeProbe{samples: []Sample{
		{Healthy: true, Metrics: map[string]float64{"availability": 1}},
		{Healthy: true, Metrics: map[string]float64{"availability": 1}},
		{Healthy: true, Metrics: map[string]float64{"availability": 1}},
	}}
	finalizer := &fakeFinalizer{}
	verifier := newVerifier(t, clock, probe, finalizer, &fakeRetryState{state: retryState(now)})
	request := testRequest(now, 0)

	for index, want := range []Outcome{OutcomePending, OutcomePending, OutcomeSucceeded} {
		result, err := verifier.Verify(context.Background(), request)
		if err != nil {
			t.Fatalf("Verify() call %d error = %v", index, err)
		}
		if result.Outcome != want {
			t.Fatalf("Verify() call %d outcome = %q, want %q", index, result.Outcome, want)
		}
	}
	if finalizer.calls != 1 || !finalizer.succeeded {
		t.Fatalf("finalizer = calls=%d succeeded=%t, want one successful completion", finalizer.calls, finalizer.succeeded)
	}
	if probe.calls != 3 {
		t.Fatalf("Probe.Observe() calls = %d, want 3", probe.calls)
	}

	result, err := verifier.Verify(context.Background(), request)
	if err != nil || result.Outcome != OutcomeSucceeded || probe.calls != 3 || finalizer.calls != 1 {
		t.Fatalf("idempotent Verify() = %#v, %v, probe=%d finalizer=%d, want persisted success without another probe", result, err, probe.calls, finalizer.calls)
	}
}

func TestVerifier_EmitsBoundedStabilizationTelemetry(t *testing.T) {
	now := testNow()
	spanExporter := tracetest.NewInMemoryExporter()
	recorder, err := telemetry.New(telemetry.Options{SpanExporter: spanExporter})
	if err != nil {
		t.Fatalf("telemetry.New() error = %v", err)
	}
	t.Cleanup(func() { _ = recorder.Shutdown(context.Background()) })
	verifier := newVerifier(t, &fakeClock{times: []time.Time{now}}, &fakeProbe{samples: []Sample{{Healthy: true, Metrics: map[string]float64{"availability": 1}}}}, &fakeFinalizer{}, &fakeRetryState{state: retryState(now)})
	verifier.telemetry = recorder
	request := testRequest(now, 0)
	request.Command.CommandID = "command-raw-secret"
	request.Command.IncidentID = "incident-raw-secret"
	request.Target.TargetID = request.Command.TargetID
	result, err := verifier.Verify(context.Background(), request)
	if err != nil || result.Outcome != OutcomePending {
		t.Fatalf("Verify() = %#v, %v, want pending sample", result, err)
	}
	if err := recorder.ForceFlush(context.Background()); err != nil {
		t.Fatalf("telemetry flush error = %v", err)
	}
	spans := spanExporter.GetSpans()
	if len(spans) != 1 || spans[0].Name != "pulse.agent.stabilization.verify" {
		t.Fatalf("telemetry spans = %#v, want stabilization verify span", spans)
	}
	attributes := make(map[string]string, len(spans[0].Attributes))
	for _, value := range spans[0].Attributes {
		attributes[string(value.Key)] = value.Value.AsString()
	}
	if attributes[telemetry.AttributeTarget] != string(telemetry.TargetDocker) || attributes[telemetry.AttributeResult] != string(telemetry.ResultSuccess) {
		t.Fatalf("telemetry attributes = %#v, want bounded stabilization contract", attributes)
	}
	for _, value := range attributes {
		if value == "command-raw-secret" || value == "incident-raw-secret" || value == "target-web" {
			t.Fatalf("telemetry leaked stabilization identifier: %#v", attributes)
		}
	}
}

func TestVerifier_RecordsDistinctStabilizationFailureReasons(t *testing.T) {
	now := testNow()
	tests := []struct {
		name          string
		probe         *fakeProbe
		wantReason    FailureReason
		wantProbeCall int
	}{
		{
			name:          "unhealthy",
			probe:         &fakeProbe{samples: []Sample{{Healthy: false, Metrics: map[string]float64{"availability": 0}}}},
			wantReason:    FailureUnhealthy,
			wantProbeCall: 1,
		},
		{
			name:          "probe timeout",
			probe:         &fakeProbe{errs: []error{context.DeadlineExceeded}},
			wantReason:    FailureTimeout,
			wantProbeCall: 1,
		},
		{
			name:          "metric regression",
			probe:         &fakeProbe{samples: []Sample{{Healthy: true, Metrics: map[string]float64{"availability": 0.5}}}},
			wantReason:    FailureMetricRegression,
			wantProbeCall: 1,
		},
		{
			name:          "docker unavailable",
			probe:         &fakeProbe{errs: []error{docker.ErrUnavailable}},
			wantReason:    FailureDockerUnavailable,
			wantProbeCall: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			finalizer := &fakeFinalizer{}
			verifier := newVerifier(t, &fakeClock{times: []time.Time{now}}, test.probe, finalizer, &fakeRetryState{state: retryState(now)})
			request := testRequest(now, 0)
			request.RetryPolicy.MaxAttempts = 1

			result, err := verifier.Verify(context.Background(), request)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.Outcome != OutcomeFailed || result.FailureReason != test.wantReason || result.RetryReason != policy.ReasonRetryExhausted {
				t.Fatalf("Verify() = %#v, want failed/%q/retry_exhausted", result, test.wantReason)
			}
			if test.probe.calls != test.wantProbeCall || finalizer.calls != 1 || finalizer.succeeded {
				t.Fatalf("calls = probe=%d finalizer=%d succeeded=%t, want %d/1/false", test.probe.calls, finalizer.calls, finalizer.succeeded, test.wantProbeCall)
			}
		})
	}
}

func TestVerifier_TimeoutAfterStabilizationWindow(t *testing.T) {
	now := testNow()
	probe := &fakeProbe{samples: []Sample{{Healthy: true, Metrics: map[string]float64{"availability": 1}}}}
	finalizer := &fakeFinalizer{}
	verifier := newVerifier(t, &fakeClock{times: []time.Time{now, now.Add(time.Minute + time.Nanosecond)}}, probe, finalizer, &fakeRetryState{state: retryState(now)})
	request := testRequest(now, 0)
	request.RetryPolicy.MaxAttempts = 1

	if result, err := verifier.Verify(context.Background(), request); err != nil || result.Outcome != OutcomePending {
		t.Fatalf("first Verify() = %#v, %v, want pending", result, err)
	}
	result, err := verifier.Verify(context.Background(), request)
	if err != nil {
		t.Fatalf("window Verify() error = %v", err)
	}
	if result.Outcome != OutcomeFailed || result.FailureReason != FailureTimeout || result.RetryReason != policy.ReasonRetryExhausted {
		t.Fatalf("window Verify() = %#v, want timeout terminal failure", result)
	}
	if probe.calls != 1 || finalizer.calls != 1 || finalizer.succeeded {
		t.Fatalf("window timeout calls = probe=%d finalizer=%d succeeded=%t, want 1/1/false", probe.calls, finalizer.calls, finalizer.succeeded)
	}
}

func TestVerifier_FlashingHealthSchedulesOnlyAuthorizedRetry(t *testing.T) {
	now := testNow()
	probe := &fakeProbe{samples: []Sample{
		{Healthy: true, Metrics: map[string]float64{"availability": 1}},
		{Healthy: false, Metrics: map[string]float64{"availability": 0}},
	}}
	retry := &fakeRetryState{state: retryState(now.Add(30 * time.Second))}
	finalizer := &fakeFinalizer{}
	verifier := newVerifier(t, &fakeClock{times: []time.Time{now, now.Add(30 * time.Second)}}, probe, finalizer, retry)
	request := testRequest(now, 0)

	if result, err := verifier.Verify(context.Background(), request); err != nil || result.Outcome != OutcomePending {
		t.Fatalf("first Verify() = %#v, %v, want pending healthy sample", result, err)
	}
	result, err := verifier.Verify(context.Background(), request)
	if err != nil {
		t.Fatalf("second Verify() error = %v", err)
	}
	if result.Outcome != OutcomeRetryScheduled || result.FailureReason != FailureFlapping || result.RetryReason != policy.ReasonAllowed || result.NextAttempt != 1 {
		t.Fatalf("second Verify() = %#v, want authorized flapping retry", result)
	}
	if retry.loads != 1 || finalizer.calls != 1 || finalizer.succeeded {
		t.Fatalf("retry/finalizer calls = %d/%d/%t, want 1/1/false", retry.loads, finalizer.calls, finalizer.succeeded)
	}
}

func TestVerifier_RetryRechecksCurrentPolicyAndExhaustsBudget(t *testing.T) {
	now := testNow()
	tests := []struct {
		name       string
		mutate     func(*RetryState)
		wantReason policy.ReasonCode
	}{
		{
			name:       "digest changed",
			mutate:     func(state *RetryState) { state.PolicySnapshot.Runbooks[0].Runbook.Digest = "replacement-digest" },
			wantReason: policy.ReasonForgedDigest,
		},
		{
			name:       "target changed",
			mutate:     func(state *RetryState) { state.Target.Selector = "container:replacement" },
			wantReason: policy.ReasonInvalidPolicy,
		},
		{
			name:       "precondition failed",
			mutate:     func(state *RetryState) { state.PolicyInput.Preconditions["docker_healthy"] = false },
			wantReason: policy.ReasonPreconditionFailed,
		},
		{
			name:       "cooldown active",
			mutate:     func(state *RetryState) { state.PolicyInput.LastAttemptAt = now },
			wantReason: policy.ReasonCooldownActive,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := retryState(now)
			test.mutate(&state)
			retry := &fakeRetryState{state: state}
			verifier := newVerifier(t, &fakeClock{times: []time.Time{now}}, &fakeProbe{samples: []Sample{{Healthy: false, Metrics: map[string]float64{"availability": 0}}}}, &fakeFinalizer{}, retry)

			result, err := verifier.Verify(context.Background(), testRequest(now, 0))
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.Outcome != OutcomeFailed || result.RetryReason != test.wantReason || retry.loads != 1 {
				t.Fatalf("Verify() = %#v, retry loads=%d, want failed/%q with recheck", result, retry.loads, test.wantReason)
			}
		})
	}

	request := testRequest(now, 1)
	request.RetryPolicy.MaxAttempts = 2
	verifier := newVerifier(t, &fakeClock{times: []time.Time{now}}, &fakeProbe{samples: []Sample{{Healthy: false, Metrics: map[string]float64{"availability": 0}}}}, &fakeFinalizer{}, &fakeRetryState{state: retryState(now)})
	result, err := verifier.Verify(context.Background(), request)
	if err != nil {
		t.Fatalf("Verify() retry-exhausted error = %v", err)
	}
	if result.Outcome != OutcomeFailed || result.RetryReason != policy.ReasonRetryExhausted {
		t.Fatalf("Verify() retry-exhausted = %#v, want terminal retry_exhausted", result)
	}
}

func TestVerifier_ManualRecoveryCanStabilizeWithoutExecutingDocker(t *testing.T) {
	now := testNow()
	probe := &fakeProbe{samples: []Sample{
		{Healthy: true, Metrics: map[string]float64{"availability": 1}},
		{Healthy: true, Metrics: map[string]float64{"availability": 1}},
	}}
	finalizer := &fakeFinalizer{}
	verifier := newVerifier(t, &fakeClock{times: []time.Time{now, now.Add(time.Minute)}}, probe, finalizer, &fakeRetryState{state: retryState(now)})
	request := testRequest(now, 0)

	if result, err := verifier.Verify(context.Background(), request); err != nil || result.Outcome != OutcomePending {
		t.Fatalf("initial Verify() = %#v, %v, want pending", result, err)
	}
	result, err := verifier.Verify(context.Background(), request)
	if err != nil || result.Outcome != OutcomeSucceeded {
		t.Fatalf("manual-recovery Verify() = %#v, %v, want succeeded", result, err)
	}
	if probe.calls != 2 || finalizer.calls != 1 || !finalizer.succeeded {
		t.Fatalf("manual-recovery calls = probe=%d finalizer=%d succeeded=%t, want 2/1/true", probe.calls, finalizer.calls, finalizer.succeeded)
	}
}

type fakeClock struct {
	times []time.Time
	index int
}

func (c *fakeClock) Now() time.Time {
	if c.index >= len(c.times) {
		return c.times[len(c.times)-1]
	}
	now := c.times[c.index]
	c.index++
	return now
}

type fakeProbe struct {
	samples []Sample
	errs    []error
	calls   int
}

func (p *fakeProbe) Observe(_ context.Context, _ contract.ServiceTarget) (Sample, error) {
	index := p.calls
	p.calls++
	if index < len(p.errs) && p.errs[index] != nil {
		return Sample{}, p.errs[index]
	}
	if index < len(p.samples) {
		return p.samples[index], nil
	}
	return Sample{}, errors.New("unexpected probe call")
}

type fakeFinalizer struct {
	calls     int
	succeeded bool
	err       error
}

func (f *fakeFinalizer) CompleteStabilization(commandID string, succeeded bool) (contract.RecoveryCommand, error) {
	f.calls++
	f.succeeded = succeeded
	if f.err != nil {
		return contract.RecoveryCommand{}, f.err
	}
	return contract.RecoveryCommand{CommandID: commandID}, nil
}

type fakeRetryState struct {
	state RetryState
	err   error
	loads int
}

func (s *fakeRetryState) LoadRetryState(_ context.Context, _ contract.RecoveryCommand) (RetryState, error) {
	s.loads++
	if s.err != nil {
		return RetryState{}, s.err
	}
	return s.state, nil
}

func newVerifier(t *testing.T, clock Clock, probe Probe, finalizer CommandFinalizer, retry RetryStateSource) *Verifier {
	t.Helper()
	state, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db"), LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := state.Close(); closeErr != nil {
			t.Errorf("state.Close() error = %v", closeErr)
		}
	})
	verifier, err := New(Options{State: state, Clock: clock, Probe: probe, Finalizer: finalizer, RetryState: retry})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return verifier
}

func testRequest(now time.Time, attempt int) Request {
	return Request{
		Command: contract.RecoveryCommand{
			SchemaVersion:  contract.SchemaVersionV1,
			CommandID:      "command-" + strconv.Itoa(attempt),
			IncidentID:     "incident-1",
			RunbookID:      "restart-web",
			RunbookDigest:  "digest-web",
			TargetID:       "target-web",
			ActionIndex:    0,
			RiskTier:       contract.RiskLow,
			IssuedAt:       now.Add(-time.Minute),
			ExpiresAt:      now.Add(time.Hour),
			IdempotencyKey: "delivery-" + strconv.Itoa(attempt),
			State:          contract.RecoveryStabilizing,
		},
		Target: contract.ServiceTarget{
			SchemaVersion: contract.SchemaVersionV1,
			TargetID:      "target-web",
			AdapterType:   docker.AdapterType,
			Selector:      "container:web",
			ProbeRules: []contract.ProbeRule{{
				RuleID:     "availability",
				SignalType: "availability",
				Threshold:  0.9,
			}},
			Enabled: true,
		},
		Policy:      contract.StabilizationPolicy{RecoverySamples: 2, Window: contract.NewDuration(time.Minute)},
		RetryPolicy: contract.RetryPolicy{MaxAttempts: 2},
		Attempt:     attempt,
	}
}

func retryState(now time.Time) RetryState {
	return RetryState{
		Target: testRequest(now, 0).Target,
		PolicySnapshot: policy.Snapshot{Runbooks: []policy.RegisteredRunbook{{
			Runbook: contract.Runbook{
				SchemaVersion: contract.SchemaVersionV1,
				RunbookID:     "restart-web",
				Digest:        "digest-web",
				AdapterType:   docker.AdapterType,
				TypedActions: []contract.TypedAction{{
					ActionType:     contract.ActionDockerContainerRestart,
					TargetSelector: "container:web",
					StopTimeout:    contract.NewDuration(time.Second),
					Cooldown:       contract.NewDuration(time.Minute),
				}},
				RiskTier:            contract.RiskLow,
				AutoExecute:         true,
				Preconditions:       []string{"docker_healthy"},
				RetryPolicy:         contract.RetryPolicy{MaxAttempts: 2},
				StabilizationPolicy: contract.StabilizationPolicy{RecoverySamples: 2, Window: contract.NewDuration(time.Minute)},
			},
			TargetID: "target-web",
		}}, AuthorizedApprovers: []string{"operator-1"}},
		PolicyInput: policy.Input{
			RunbookID:     "restart-web",
			RunbookDigest: "digest-web",
			TargetID:      "target-web",
			ActionIndex:   0,
			Preconditions: map[string]bool{"docker_healthy": true},
			Now:           now,
		},
	}
}

func testNow() time.Time { return time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC) }
