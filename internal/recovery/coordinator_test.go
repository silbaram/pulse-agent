package recovery

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/docker"
	"pulse-agent/internal/policy"
	"pulse-agent/internal/store"
	"pulse-agent/internal/telemetry"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestCoordinator_SubmitPersistsPendingBeforeAdapterExecution(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{snapshot: docker.Snapshot{TargetID: "target-web", Running: true, Healthy: true}}
	clock := &sequenceClock{times: []time.Time{now, now}}
	coordinator := newCoordinator(t, state, adapter, clock)
	request := testRequest(now)
	pendingObserved := false
	adapter.onValidate = func() {
		stored := readRecord(t, state, contract.RecoveryCommand{
			IncidentID:    request.IncidentID,
			RunbookID:     request.PolicyInput.RunbookID,
			RunbookDigest: request.PolicyInput.RunbookDigest,
			TargetID:      request.Target.TargetID,
			ActionIndex:   request.PolicyInput.ActionIndex,
		})
		if stored.Phase != phasePending || stored.Command.State != contract.RecoveryPending {
			t.Fatalf("journal before ValidateAction() = phase=%q state=%q, want pending", stored.Phase, stored.Command.State)
		}
		if stored.Command.IncidentID != request.IncidentID || stored.Command.RunbookDigest != request.PolicyInput.RunbookDigest || stored.Command.TargetID != request.Target.TargetID || stored.Command.ActionIndex != request.PolicyInput.ActionIndex || stored.Command.ExpiresAt != request.ExpiresAt || stored.Command.IdempotencyKey != request.IdempotencyKey || stored.Command.CommandID == "" {
			t.Fatalf("pending journal command = %#v, want durable command fields", stored.Command)
		}
		pendingObserved = true
	}

	result, err := coordinator.Submit(context.Background(), request)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if result.Outcome != OutcomeStabilizing || result.Command.State != contract.RecoveryStabilizing || !pendingObserved {
		t.Fatalf("Submit() = %#v, pendingObserved=%t, want pending-first execution awaiting stabilization", result, pendingObserved)
	}
	if adapter.validateCalls != 1 || adapter.executeCalls != 1 {
		t.Fatalf("adapter calls = validate=%d execute=%d, want 1 each", adapter.validateCalls, adapter.executeCalls)
	}
	stored := readRecord(t, state, result.Command)
	if stored.Phase != phaseStabilizing || stored.Command.State != contract.RecoveryStabilizing {
		t.Fatalf("stored command = phase=%q state=%q, want stabilizing/stabilizing", stored.Phase, stored.Command.State)
	}
}

func TestCoordinator_EmitsBoundedPolicyAndReconciliationTelemetry(t *testing.T) {
	now := testNow()
	spanExporter := tracetest.NewInMemoryExporter()
	recorder, err := telemetry.New(telemetry.Options{SpanExporter: spanExporter})
	if err != nil {
		t.Fatalf("telemetry.New() error = %v", err)
	}
	t.Cleanup(func() { _ = recorder.Shutdown(context.Background()) })
	state := openState(t)
	adapter := &fakeAdapter{snapshot: docker.Snapshot{TargetID: "target-web", Running: true, Healthy: true}}
	request := testRequest(now)
	request.IncidentID = "incident-raw-secret"
	request.PolicyInput.RunbookDigest = "digest-raw-secret"
	request.PolicySnapshot.Runbooks[0].Runbook.Digest = request.PolicyInput.RunbookDigest
	coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now, now, now}}, &fakeStateSource{state: executionState(request)})
	coordinator.telemetry = recorder
	if _, err := coordinator.Submit(context.Background(), request); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if _, err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if err := recorder.ForceFlush(context.Background()); err != nil {
		t.Fatalf("telemetry flush error = %v", err)
	}
	seen := make(map[string]map[string]string)
	for _, span := range spanExporter.GetSpans() {
		attributes := make(map[string]string, len(span.Attributes))
		for _, value := range span.Attributes {
			attributes[string(value.Key)] = value.Value.AsString()
		}
		seen[span.Name] = attributes
		for _, value := range attributes {
			if value == "incident-raw-secret" || value == "digest-raw-secret" || value == "command-1" {
				t.Fatalf("telemetry leaked recovery identifier: %s %#v", span.Name, attributes)
			}
		}
	}
	for _, name := range []string{"pulse.agent.policy.decide", "pulse.agent.recovery.execute", "pulse.agent.recovery.reconcile"} {
		if _, found := seen[name]; !found {
			t.Fatalf("telemetry spans = %#v, want %q", seen, name)
		}
	}
	if seen["pulse.agent.policy.decide"][telemetry.AttributeReason] != string(telemetry.ReasonAllowed) {
		t.Fatalf("policy telemetry = %#v, want bounded allowed reason", seen["pulse.agent.policy.decide"])
	}
}

func TestCoordinator_SubmitReloadsAuthoritativeFactsAfterAdapterValidation(t *testing.T) {
	now := testNow()
	tests := []struct {
		name       string
		mutate     func(*fakeStateSource)
		wantReason policy.ReasonCode
	}{
		{
			name: "forged digest",
			mutate: func(source *fakeStateSource) {
				source.state.PolicySnapshot.Runbooks[0].Runbook.Digest = "changed-digest"
			},
			wantReason: policy.ReasonForgedDigest,
		},
		{
			name: "target registration changed",
			mutate: func(source *fakeStateSource) {
				source.state.PolicySnapshot.Runbooks[0].TargetID = "other-target"
			},
			wantReason: policy.ReasonTargetMismatch,
		},
		{
			name: "target selector changed",
			mutate: func(source *fakeStateSource) {
				source.state.Target.Selector = "container:replacement"
			},
			wantReason: policy.ReasonInvalidPolicy,
		},
		{
			name: "precondition no longer holds",
			mutate: func(source *fakeStateSource) {
				source.state.PolicyInput.Preconditions["docker_healthy"] = false
			},
			wantReason: policy.ReasonPreconditionFailed,
		},
		{
			name: "cooldown became active",
			mutate: func(source *fakeStateSource) {
				source.state.PolicyInput.LastAttemptAt = now
			},
			wantReason: policy.ReasonCooldownActive,
		},
		{
			name: "retry budget exhausted",
			mutate: func(source *fakeStateSource) {
				source.state.PolicyInput.AttemptCount = 2
			},
			wantReason: policy.ReasonRetryExhausted,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := openState(t)
			adapter := &fakeAdapter{snapshot: docker.Snapshot{TargetID: "target-web", Running: true, Healthy: true}}
			request := testRequest(now)
			source := &fakeStateSource{state: executionState(testRequest(now))}
			adapter.onValidate = func() { test.mutate(source) }
			coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now, now, now}}, source)

			result, err := coordinator.Submit(context.Background(), request)
			if err != nil {
				t.Fatalf("Submit() error = %v", err)
			}
			if result.Outcome != OutcomeDenied || result.Decision.ReasonCode != test.wantReason {
				t.Fatalf("Submit() = %#v, want denied/%q", result, test.wantReason)
			}
			if adapter.validateCalls != 1 || adapter.executeCalls != 0 {
				t.Fatalf("adapter calls = validate=%d execute=%d, want final revalidation to stop execution", adapter.validateCalls, adapter.executeCalls)
			}
			if source.loads != 2 {
				t.Fatalf("StateSource.Load() calls = %d, want 2", source.loads)
			}
			stored := readRecord(t, state, result.Command)
			if stored.Phase != phaseCompleted || stored.Command.State != contract.RecoveryDenied {
				t.Fatalf("stored command = phase=%q state=%q, want completed/denied", stored.Phase, stored.Command.State)
			}
		})
	}
}

func TestCoordinator_SubmitRejectsCurrentReplicaCountBeforeExecute(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{validateErr: docker.ErrAmbiguousTarget}
	coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now, now}})

	result, err := coordinator.Submit(context.Background(), testRequest(now))
	if !errors.Is(err, docker.ErrAmbiguousTarget) {
		t.Fatalf("Submit() error = %v, want current-replica validation error", err)
	}
	if result.Outcome != OutcomeDenied || adapter.executeCalls != 0 {
		t.Fatalf("Submit() = %#v, execute calls=%d, want denied with no execution", result, adapter.executeCalls)
	}
	if adapter.validateCalls != 1 {
		t.Fatalf("ValidateAction() calls = %d, want 1", adapter.validateCalls)
	}
	stored := readRecord(t, state, result.Command)
	if stored.Command.State != contract.RecoveryDenied {
		t.Fatalf("stored state = %q, want denied", stored.Command.State)
	}
}

func TestCoordinator_SubmitExpiresImmediatelyBeforeExecute(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{}
	request := testRequest(now)
	request.ExpiresAt = now.Add(time.Minute)
	coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now, request.ExpiresAt}})

	result, err := coordinator.Submit(context.Background(), request)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if result.Outcome != OutcomeExpired || adapter.validateCalls != 0 || adapter.executeCalls != 0 {
		t.Fatalf("Submit() = %#v, calls=%d/%d, want expired before adapter execution", result, adapter.validateCalls, adapter.executeCalls)
	}
	stored := readRecord(t, state, result.Command)
	if stored.Command.State != contract.RecoveryExpired {
		t.Fatalf("stored state = %q, want expired", stored.Command.State)
	}
}

func TestCoordinator_SubmitExpiresDuringAdapterValidation(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{}
	request := testRequest(now)
	request.ExpiresAt = now.Add(time.Minute)
	source := &fakeStateSource{state: executionState(testRequest(now))}
	coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now, now, request.ExpiresAt}}, source)

	result, err := coordinator.Submit(context.Background(), request)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if result.Outcome != OutcomeExpired || adapter.validateCalls != 1 || adapter.executeCalls != 0 {
		t.Fatalf("Submit() = %#v, calls=%d/%d, want expiry after validation with no execution", result, adapter.validateCalls, adapter.executeCalls)
	}
	if source.loads != 2 {
		t.Fatalf("StateSource.Load() calls = %d, want 2", source.loads)
	}
	stored := readRecord(t, state, result.Command)
	if stored.Command.State != contract.RecoveryExpired {
		t.Fatalf("stored state = %q, want expired", stored.Command.State)
	}
}

func TestCoordinator_SubmitFailsClosedWhenCurrentStateCannotLoad(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{}
	source := &fakeStateSource{err: errors.New("state unavailable")}
	coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now}}, source)

	result, err := coordinator.Submit(context.Background(), testRequest(now))
	if err == nil || result.Outcome != OutcomeDenied || result.Decision.ReasonCode != policy.ReasonInvalidPolicy {
		t.Fatalf("Submit() = %#v, %v, want denied invalid policy with state-load error", result, err)
	}
	if adapter.validateCalls != 0 || adapter.executeCalls != 0 {
		t.Fatalf("adapter calls = validate=%d execute=%d, want no adapter interaction", adapter.validateCalls, adapter.executeCalls)
	}
	stored := readRecord(t, state, result.Command)
	if stored.Command.State != contract.RecoveryDenied {
		t.Fatalf("stored state = %q, want denied", stored.Command.State)
	}
}

func TestCoordinator_DuplicateDeliveriesProduceAtMostOneEffect(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{snapshot: docker.Snapshot{TargetID: "target-web", Running: true, Healthy: true}}
	coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now, now, now}})
	firstRequest := testRequest(now)

	first, err := coordinator.Submit(context.Background(), firstRequest)
	if err != nil || first.Outcome != OutcomeStabilizing {
		t.Fatalf("first Submit() = %#v, %v, want stabilizing", first, err)
	}
	secondRequest := firstRequest
	secondRequest.IdempotencyKey = "delivery-retry-2"
	second, err := coordinator.Submit(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("second Submit() error = %v", err)
	}
	if !second.Duplicate || second.Outcome != OutcomeStabilizing || second.Command.CommandID != first.Command.CommandID {
		t.Fatalf("second Submit() = %#v, want duplicate of %#v", second, first.Command)
	}
	if adapter.executeCalls != 1 {
		t.Fatalf("Execute() calls = %d, want exactly one effect", adapter.executeCalls)
	}
}

func TestCoordinator_CompleteStabilizationRequiresSeparateVerification(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{}
	coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now, now, now}})

	result, err := coordinator.Submit(context.Background(), testRequest(now))
	if err != nil || result.Command.State != contract.RecoveryStabilizing {
		t.Fatalf("Submit() = %#v, %v, want stabilizing command", result, err)
	}
	completed, err := coordinator.CompleteStabilization(result.Command.CommandID, true)
	if err != nil {
		t.Fatalf("CompleteStabilization() error = %v", err)
	}
	if completed.State != contract.RecoverySucceeded {
		t.Fatalf("CompleteStabilization() state = %q, want succeeded", completed.State)
	}
	if repeated, err := coordinator.CompleteStabilization(result.Command.CommandID, true); err != nil || repeated.State != contract.RecoverySucceeded {
		t.Fatalf("idempotent CompleteStabilization() = %#v, %v, want succeeded", repeated, err)
	}
	if _, err := coordinator.CompleteStabilization(result.Command.CommandID, false); !errors.Is(err, errCommandNotExecutable) {
		t.Fatalf("opposite CompleteStabilization() error = %v, want errCommandNotExecutable", err)
	}
}

func TestCoordinator_ExecuteErrorStaysUncertainWithoutReplay(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{executeErr: errors.New("SDK outcome unknown")}
	coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now, now, now}})
	request := testRequest(now)

	result, err := coordinator.Submit(context.Background(), request)
	if err == nil {
		t.Fatal("Submit() error = nil, want adapter error")
	}
	if result.Outcome != OutcomeVerifyAndNotify || result.Command.State != contract.RecoveryExecuting {
		t.Fatalf("Submit() = %#v, want uncertain executing command", result)
	}
	stored := readRecord(t, state, result.Command)
	if stored.Phase != phaseVerifyAndNotify || stored.Reconciliation == nil || stored.Reconciliation.Verified {
		t.Fatalf("stored record = %#v, want unverified verify_and_notify", stored)
	}
	retry, retryErr := coordinator.Submit(context.Background(), request)
	if retryErr != nil {
		t.Fatalf("retry Submit() error = %v", retryErr)
	}
	if !retry.Duplicate || retry.Outcome != OutcomeVerifyAndNotify || adapter.executeCalls != 1 {
		t.Fatalf("retry Submit() = %#v, execute calls=%d, want no replay", retry, adapter.executeCalls)
	}
}

func TestCoordinator_SubmitPersistsApprovalWaitWithoutExecution(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{}
	coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now}})
	request := testRequest(now)
	request.PolicySnapshot.Runbooks[0].Runbook.RiskTier = contract.RiskHigh
	request.PolicySnapshot.Runbooks[0].Runbook.AutoExecute = false

	result, err := coordinator.Submit(context.Background(), request)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if result.Outcome != OutcomeAwaitApproval || result.Command.State != contract.RecoveryPending || adapter.executeCalls != 0 {
		t.Fatalf("Submit() = %#v, execute calls=%d, want durable approval wait", result, adapter.executeCalls)
	}
	stored := readRecord(t, state, result.Command)
	if stored.Phase != phaseAwaitingApproval {
		t.Fatalf("stored phase = %q, want awaiting approval", stored.Phase)
	}
	results, err := coordinator.Reconcile(context.Background())
	if err != nil || len(results) != 0 {
		t.Fatalf("Reconcile() = %#v, %v, want approval wait unchanged", results, err)
	}
}

func TestCoordinator_LifecyclePublisherQueuesRecoveryStartedBeforeDockerExecute(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{snapshot: docker.Snapshot{TargetID: "target-web", Running: true, Healthy: true}}
	publisher := &fakeLifecyclePublisher{}
	coordinator := newCoordinatorWithPublisher(t, state, adapter, &sequenceClock{times: []time.Time{now, now, now}}, publisher)
	journalObserved := false
	publisher.onRecoveryStarted = func(command contract.RecoveryCommand) {
		stored := readRecord(t, state, command)
		if stored.Command.CommandID != command.CommandID || stored.Phase != phasePending {
			t.Fatalf("journal at recovery.started = %#v, want durable pending command", stored)
		}
		journalObserved = true
	}
	adapter.onExecute = func() {
		if !journalObserved || !publisher.hasCall("recovery.started") {
			t.Fatal("Docker Execute() ran before durable recovery.started publication")
		}
	}

	request := testRequest(now)
	request.PolicyInput.AnalysisAvailable = true
	result, err := coordinator.Submit(context.Background(), request)
	if err != nil || result.Outcome != OutcomeStabilizing || adapter.executeCalls != 1 || !journalObserved {
		t.Fatalf("Submit() = %#v, %v, execute=%d, journal=%t", result, err, adapter.executeCalls, journalObserved)
	}
}

func TestCoordinator_LifecyclePublisherFailurePreventsDockerExecute(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{}
	publisher := &fakeLifecyclePublisher{err: errors.New("queue unavailable")}
	coordinator := newCoordinatorWithPublisher(t, state, adapter, &sequenceClock{times: []time.Time{now, now, now}}, publisher)

	request := testRequest(now)
	request.PolicyInput.AnalysisAvailable = true
	result, err := coordinator.Submit(context.Background(), request)
	if err == nil || result.Command.CommandID == "" || adapter.executeCalls != 0 {
		t.Fatalf("Submit() = %#v, %v, execute=%d, want queue failure before Docker", result, err, adapter.executeCalls)
	}
	stored := readRecord(t, state, result.Command)
	if stored.Phase != phasePending || stored.Command.State != contract.RecoveryPending {
		t.Fatalf("journal after queue failure = %#v, want pending command", stored)
	}
}

func TestCoordinator_LifecyclePublisherKeepsApprovalWaitNonExecutable(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{}
	publisher := &fakeLifecyclePublisher{}
	coordinator := newCoordinatorWithPublisher(t, state, adapter, &sequenceClock{times: []time.Time{now}}, publisher)
	request := testRequest(now)
	request.PolicyInput.AnalysisAvailable = true
	request.PolicySnapshot.Runbooks[0].Runbook.RiskTier = contract.RiskHigh
	request.PolicySnapshot.Runbooks[0].Runbook.AutoExecute = false

	result, err := coordinator.Submit(context.Background(), request)
	if err != nil || result.Outcome != OutcomeAwaitApproval || !publisher.hasCall("approval.requested") || adapter.executeCalls != 0 {
		t.Fatalf("Submit() = %#v, %v, calls=%#v, execute=%d", result, err, publisher.calls, adapter.executeCalls)
	}
}

func TestCoordinator_LifecyclePublisherOrdersUnavailableAnalysisBeforeRecovery(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{}
	publisher := &fakeLifecyclePublisher{}
	coordinator := newCoordinatorWithPublisher(t, state, adapter, &sequenceClock{times: []time.Time{now, now, now}}, publisher)

	result, err := coordinator.Submit(context.Background(), testRequest(now))
	if err != nil || result.Outcome != OutcomeStabilizing || len(publisher.calls) != 2 || publisher.calls[0] != "analysis.unavailable" || publisher.calls[1] != "recovery.started" {
		t.Fatalf("Submit() = %#v, %v, calls=%#v, want ordered analysis and recovery events", result, err, publisher.calls)
	}
}

func TestCoordinator_LifecyclePublisherRecordsPolicyDenialWithoutDockerExecute(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{}
	publisher := &fakeLifecyclePublisher{}
	coordinator := newCoordinatorWithPublisher(t, state, adapter, &sequenceClock{times: []time.Time{now}}, publisher)
	request := testRequest(now)
	request.PolicyInput.AnalysisAvailable = true
	request.PolicyInput.Preconditions["docker_healthy"] = false

	result, err := coordinator.Submit(context.Background(), request)
	if err != nil || result.Outcome != OutcomeDenied || !publisher.hasCall("policy.denied") || adapter.executeCalls != 0 {
		t.Fatalf("Submit() = %#v, %v, calls=%#v, execute=%d", result, err, publisher.calls, adapter.executeCalls)
	}
}

func TestCoordinator_ReconcileProcessStopsWithoutRepeatingEffect(t *testing.T) {
	now := testNow()
	tests := []struct {
		name             string
		simulateStop     func(t *testing.T, coordinator *Coordinator, adapter *fakeAdapter, record journalRecord)
		wantExecuteCalls int
		wantState        contract.RecoveryCommandState
	}{
		{
			name:             "immediately after pending write",
			simulateStop:     func(_ *testing.T, _ *Coordinator, _ *fakeAdapter, _ journalRecord) {},
			wantExecuteCalls: 0,
			wantState:        contract.RecoveryPending,
		},
		{
			name: "after execution state before SDK call",
			simulateStop: func(t *testing.T, coordinator *Coordinator, _ *fakeAdapter, record journalRecord) {
				t.Helper()
				if _, err := coordinator.approve(recordKey(record.Command)); err != nil {
					t.Fatalf("approve() error = %v", err)
				}
				if _, err := coordinator.startExecution(recordKey(record.Command)); err != nil {
					t.Fatalf("startExecution() error = %v", err)
				}
			},
			wantExecuteCalls: 0,
			wantState:        contract.RecoveryExecuting,
		},
		{
			name: "after SDK accepted before durable result",
			simulateStop: func(t *testing.T, coordinator *Coordinator, adapter *fakeAdapter, record journalRecord) {
				t.Helper()
				if _, err := coordinator.approve(recordKey(record.Command)); err != nil {
					t.Fatalf("approve() error = %v", err)
				}
				executing, err := coordinator.startExecution(recordKey(record.Command))
				if err != nil {
					t.Fatalf("startExecution() error = %v", err)
				}
				if err := adapter.Execute(context.Background(), executing.Target, executing.Action); err != nil {
					t.Fatalf("fake Execute() error = %v", err)
				}
			},
			wantExecuteCalls: 1,
			wantState:        contract.RecoveryExecuting,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := openState(t)
			adapter := &fakeAdapter{snapshot: docker.Snapshot{TargetID: "target-web", Running: true, Healthy: true}}
			coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now}})
			request := testRequest(now)
			record, duplicate, decision, err := coordinator.prepare(context.Background(), request, now)
			if err != nil || duplicate || decision.Verdict != policy.VerdictAllow {
				t.Fatalf("prepare() = record=%#v duplicate=%t decision=%#v err=%v, want new allow", record, duplicate, decision, err)
			}
			test.simulateStop(t, coordinator, adapter, record)

			restarted := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now.Add(time.Minute)}})
			results, err := restarted.Reconcile(context.Background())
			if err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}
			if len(results) != 1 || results[0].Outcome != OutcomeVerifyAndNotify || !results[0].Verified {
				t.Fatalf("Reconcile() = %#v, want one verified verify_and_notify result", results)
			}
			if adapter.executeCalls != test.wantExecuteCalls {
				t.Fatalf("Execute() calls after reconciliation = %d, want %d", adapter.executeCalls, test.wantExecuteCalls)
			}
			stored := readRecord(t, state, record.Command)
			if stored.Phase != phaseVerifyAndNotify || stored.Command.State != test.wantState || stored.Reconciliation == nil || !stored.Reconciliation.Verified {
				t.Fatalf("reconciled record = %#v, want verify_and_notify without state replay", stored)
			}
		})
	}
}

func TestCoordinator_ReconcileVerificationFailureStaysFailClosed(t *testing.T) {
	now := testNow()
	state := openState(t)
	adapter := &fakeAdapter{verifyErr: errors.New("docker unavailable")}
	coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now}})
	record, duplicate, decision, err := coordinator.prepare(context.Background(), testRequest(now), now)
	if err != nil || duplicate || decision.Verdict != policy.VerdictAllow {
		t.Fatalf("prepare() = record=%#v duplicate=%t decision=%#v err=%v, want new allow", record, duplicate, decision, err)
	}

	results, err := coordinator.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if len(results) != 1 || results[0].Verified || adapter.executeCalls != 0 {
		t.Fatalf("Reconcile() = %#v, execute calls=%d, want unverified fail-closed result", results, adapter.executeCalls)
	}
	stored := readRecord(t, state, record.Command)
	if stored.Phase != phaseVerifyAndNotify || stored.Reconciliation == nil || stored.Reconciliation.Verified {
		t.Fatalf("stored record = %#v, want durable unverified verify_and_notify", stored)
	}
}

type fakeAdapter struct {
	validateErr   error
	executeErr    error
	verifyErr     error
	snapshot      docker.Snapshot
	onValidate    func()
	onExecute     func()
	validateCalls int
	executeCalls  int
	verifyCalls   int
}

func (a *fakeAdapter) ValidateAction(_ context.Context, _ contract.ServiceTarget, _ contract.TypedAction) error {
	a.validateCalls++
	if a.onValidate != nil {
		a.onValidate()
	}
	return a.validateErr
}

func (a *fakeAdapter) Execute(_ context.Context, _ contract.ServiceTarget, _ contract.TypedAction) error {
	a.executeCalls++
	if a.onExecute != nil {
		a.onExecute()
	}
	return a.executeErr
}

type fakeLifecyclePublisher struct {
	err               error
	calls             []string
	onRecoveryStarted func(contract.RecoveryCommand)
}

func (p *fakeLifecyclePublisher) PublishAnalysisUnavailable(_ context.Context, _ string, _ string, _ string) error {
	p.calls = append(p.calls, "analysis.unavailable")
	return p.err
}

func (p *fakeLifecyclePublisher) PublishPolicyDenied(_ context.Context, _ string, _ string, _ string) error {
	p.calls = append(p.calls, "policy.denied")
	return p.err
}

func (p *fakeLifecyclePublisher) PublishApprovalRequested(_ context.Context, _ contract.RecoveryCommand) error {
	p.calls = append(p.calls, "approval.requested")
	return p.err
}

func (p *fakeLifecyclePublisher) PublishRecoveryStarted(_ context.Context, command contract.RecoveryCommand) error {
	p.calls = append(p.calls, "recovery.started")
	if p.onRecoveryStarted != nil {
		p.onRecoveryStarted(command)
	}
	return p.err
}

func (p *fakeLifecyclePublisher) hasCall(want string) bool {
	for _, call := range p.calls {
		if call == want {
			return true
		}
	}
	return false
}

func (a *fakeAdapter) Verify(_ context.Context, _ contract.ServiceTarget) (docker.Snapshot, error) {
	a.verifyCalls++
	if a.verifyErr != nil {
		return docker.Snapshot{}, a.verifyErr
	}
	return a.snapshot, nil
}

type fakeStateSource struct {
	state ExecutionState
	err   error
	loads int
}

func (s *fakeStateSource) Load(_ context.Context, _ contract.RecoveryCommand) (ExecutionState, error) {
	s.loads++
	if s.err != nil {
		return ExecutionState{}, s.err
	}
	return s.state, nil
}

type sequenceClock struct {
	times []time.Time
	index int
}

func (c *sequenceClock) Now() time.Time {
	if len(c.times) == 0 {
		return time.Time{}
	}
	if c.index >= len(c.times) {
		return c.times[len(c.times)-1]
	}
	now := c.times[c.index]
	c.index++
	return now
}

func newCoordinator(t *testing.T, state *store.Store, adapter Adapter, clock Clock, sources ...StateSource) *Coordinator {
	t.Helper()
	source := StateSource(&fakeStateSource{state: executionState(testRequest(testNow()))})
	if len(sources) == 1 {
		source = sources[0]
	}
	if len(sources) > 1 {
		t.Fatalf("newCoordinator() received %d state sources, want at most 1", len(sources))
	}
	nextID := 0
	coordinator, err := New(Options{
		State:       state,
		Adapter:     adapter,
		StateSource: source,
		Clock:       clock,
		NewCommandID: func() (string, error) {
			nextID++
			return fmt.Sprintf("command-%d", nextID), nil
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return coordinator
}

func newCoordinatorWithPublisher(t *testing.T, state *store.Store, adapter Adapter, clock Clock, publisher LifecyclePublisher) *Coordinator {
	t.Helper()
	nextID := 0
	coordinator, err := New(Options{
		State:       state,
		Adapter:     adapter,
		StateSource: &fakeStateSource{state: executionState(testRequest(testNow()))},
		Clock:       clock,
		NewCommandID: func() (string, error) {
			nextID++
			return fmt.Sprintf("command-%d", nextID), nil
		},
		LifecyclePublisher: publisher,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return coordinator
}

func openState(t *testing.T) *store.Store {
	t.Helper()
	state, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db"), LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Errorf("Store.Close() error = %v", err)
		}
	})
	return state
}

func readRecord(t *testing.T, state *store.Store, command contract.RecoveryCommand) journalRecord {
	t.Helper()
	var record journalRecord
	err := state.View(func(tx *store.Tx) error {
		var (
			found bool
			err   error
		)
		record, found, err = loadRecord(tx, recordKey(command))
		if err != nil {
			return err
		}
		if !found {
			return ErrCorruptJournal
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read recovery record error = %v", err)
	}
	return record
}

func testRequest(now time.Time) Request {
	target := contract.ServiceTarget{
		SchemaVersion: contract.SchemaVersionV1,
		TargetID:      "target-web",
		AdapterType:   docker.AdapterType,
		Selector:      "container:web",
		Enabled:       true,
	}
	runbook := contract.Runbook{
		SchemaVersion: contract.SchemaVersionV1,
		RunbookID:     "restart-web",
		Digest:        "digest-web",
		AdapterType:   docker.AdapterType,
		TypedActions: []contract.TypedAction{{
			ActionType:     contract.ActionDockerContainerRestart,
			TargetSelector: target.Selector,
			StopTimeout:    contract.NewDuration(time.Second),
			Cooldown:       contract.NewDuration(time.Minute),
		}},
		RiskTier:      contract.RiskLow,
		AutoExecute:   true,
		Preconditions: []string{"docker_healthy"},
		RetryPolicy:   contract.RetryPolicy{MaxAttempts: 2},
		StabilizationPolicy: contract.StabilizationPolicy{
			RecoverySamples: 2,
			Window:          contract.NewDuration(time.Minute),
		},
	}
	return Request{
		IncidentID: "incident-1",
		Target:     target,
		PolicySnapshot: policy.Snapshot{
			Runbooks:            []policy.RegisteredRunbook{{Runbook: runbook, TargetID: target.TargetID}},
			AuthorizedApprovers: []string{"operator-1"},
		},
		PolicyInput: policy.Input{
			RunbookID:     runbook.RunbookID,
			RunbookDigest: runbook.Digest,
			TargetID:      target.TargetID,
			ActionIndex:   0,
			Preconditions: map[string]bool{"docker_healthy": true},
			AttemptCount:  0,
		},
		ExpiresAt:      now.Add(5 * time.Minute),
		IdempotencyKey: "delivery-1",
	}
}

func executionState(request Request) ExecutionState {
	return ExecutionState{
		Target:         request.Target,
		PolicySnapshot: request.PolicySnapshot,
		PolicyInput:    request.PolicyInput,
	}
}

func testNow() time.Time {
	return time.Date(2026, 7, 21, 9, 0, 0, 0, time.UTC)
}
