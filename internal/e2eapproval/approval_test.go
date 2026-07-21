// Package e2eapproval verifies the approved recovery path across its durable boundaries.
package e2eapproval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/adk/v2/model"
	"google.golang.org/genai"

	"pulse-agent/internal/adminipc"
	"pulse-agent/internal/analysis"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/delivery"
	"pulse-agent/internal/docker"
	"pulse-agent/internal/lifecycle"
	"pulse-agent/internal/llm"
	"pulse-agent/internal/policy"
	"pulse-agent/internal/recovery"
	"pulse-agent/internal/report"
	"pulse-agent/internal/stabilization"
	"pulse-agent/internal/store"
	"pulse-agent/internal/webhook"
)

const (
	testTimeout         = 3 * time.Second
	testWebhookSecret   = "whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
	maxWebhookBodyBytes = 64 * 1024
)

// TestApprovalFlow_E2EGrantExecutesOneCommandAndPublishesTerminalReport verifies the approved high-risk recovery path.
func TestApprovalFlow_E2EGrantExecutesOneCommandAndPublishesTerminalReport(t *testing.T) {
	flow := newApprovalFlow(t)
	ctx := testContext(t)
	analysisResult := flow.analyze(ctx, t, "incident-1")
	request := flow.request("incident-1", "delivery-1", analysisResult)

	first, err := flow.coordinator.Submit(ctx, request)
	if err != nil || first.Outcome != recovery.OutcomeAwaitApproval {
		t.Fatalf("Submit() = %#v, %v, want awaiting approval", first, err)
	}
	if flow.adapter.executeCalls != 0 || !flow.hasQueuedLifecycle(t, first.Command, contract.LifecycleApprovalRequested, "approval_required") {
		t.Fatalf("approval wait execute calls=%d, want durable approval request before Docker", flow.adapter.executeCalls)
	}

	otherAnalysis := flow.analyze(ctx, t, "incident-2")
	otherRequest := flow.request("incident-2", "delivery-2", otherAnalysis)
	second, err := flow.coordinator.Submit(ctx, otherRequest)
	if err != nil || second.Outcome != recovery.OutcomeAwaitApproval {
		t.Fatalf("Submit(other) = %#v, %v, want separate approval wait", second, err)
	}

	approval, err := flow.client.DecideApproval(ctx, flow.socketPath, "operator_requested", first.Command.CommandID, contract.ApprovalGranted, flow.clock.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("DecideApproval(grant) error = %v", err)
	}
	if approval.CommandID != first.Command.CommandID || approval.Decision != contract.ApprovalGranted {
		t.Fatalf("grant result = %#v, want first command grant", approval)
	}
	if _, err := flow.client.DecideApproval(ctx, flow.socketPath, "operator_requested", first.Command.CommandID, contract.ApprovalGranted, flow.clock.Now().Add(time.Minute)); !errors.Is(err, adminipc.ErrRequestRejected) {
		t.Fatalf("duplicate grant error = %v, want %v", err, adminipc.ErrRequestRejected)
	}

	resumed, err := flow.coordinator.Resume(ctx, first.Command.CommandID)
	if err != nil || resumed.Outcome != recovery.OutcomeStabilizing || flow.adapter.executeCalls != 1 {
		t.Fatalf("Resume(granted) = %#v, %v, execute calls=%d; want one stabilizing execution", resumed, err, flow.adapter.executeCalls)
	}
	if !flow.hasQueuedLifecycle(t, resumed.Command, contract.LifecycleRecoveryStarted, "recovery_started") {
		t.Fatal("recovery.started was not durably queued before Docker execution")
	}
	if waiting, err := flow.coordinator.Resume(ctx, second.Command.CommandID); err != nil || waiting.Outcome != recovery.OutcomeAwaitApproval || flow.adapter.executeCalls != 1 {
		t.Fatalf("Resume(other) = %#v, %v, execute calls=%d; want foreign approval to remain non-executable", waiting, err, flow.adapter.executeCalls)
	}

	if result, err := flow.verifier.Verify(ctx, flow.stabilizationRequest(resumed.Command)); err != nil || result.Outcome != stabilization.OutcomePending {
		t.Fatalf("Verify(first) = %#v, %v, want pending first sample", result, err)
	}
	flow.clock.Advance(time.Minute)
	if result, err := flow.verifier.Verify(ctx, flow.stabilizationRequest(resumed.Command)); err != nil || result.Outcome != stabilization.OutcomeSucceeded {
		t.Fatalf("Verify(second) = %#v, %v, want successful stabilization", result, err)
	}

	terminal, err := flow.report.PublishTerminal(ctx, report.Input{
		IncidentID:                    resumed.Command.IncidentID,
		TerminalState:                 contract.IncidentClosed,
		IdempotencyKey:                request.IdempotencyKey,
		OccurredAt:                    flow.clock.Now(),
		Analysis:                      &analysisResult,
		EvidenceRefs:                  []string{"evidence-1"},
		Actions:                       []contract.ReportAction{{CommandID: resumed.Command.CommandID, ActionType: contract.ActionDockerContainerRestart, Result: "succeeded"}},
		ApprovalIDs:                   []string{approval.ApprovalID},
		VerificationResult:            "stabilized",
		PreventionRecommendations:     []string{"Review target health thresholds."},
		PostmortemDraft:               "Recovery completed after local approval and stabilization.",
		RunbookImprovementSuggestions: []string{"Keep the approval requirement for this action."},
	})
	if err != nil || terminal.Report.DeliveryStatus != contract.DeliveryPending || terminal.ReportQueueItem.State != contract.DeliveryPending || terminal.LifecycleQueueItem.State != contract.DeliveryPending {
		t.Fatalf("PublishTerminal() = %#v, %v, want durable pending terminal report", terminal, err)
	}

	deliveries, err := flow.dispatcher.DeliverDue(ctx)
	if err != nil {
		t.Fatalf("DeliverDue() error = %v", err)
	}
	if len(deliveries) != 5 || flow.receiver.count() != 5 || flow.receiver.failure() != nil {
		t.Fatalf("DeliverDue()=%d receiver=%d receiver error=%v, want five authenticated lifecycle/report deliveries", len(deliveries), flow.receiver.count(), flow.receiver.failure())
	}
	for _, result := range deliveries {
		if !result.Sent || result.Item.State != contract.DeliveryDelivered {
			t.Errorf("delivery result = %#v, want delivered", result)
		}
	}
}

// TestApprovalFlow_E2EDenyExpireAndRevokeNeverExecuteDocker verifies non-grant paths fail before Docker execution.
func TestApprovalFlow_E2EDenyExpireAndRevokeNeverExecuteDocker(t *testing.T) {
	tests := []struct {
		name       string
		exercise   func(context.Context, *approvalFlow, contract.RecoveryCommand) (string, error)
		wantReason string
		wantAudit  bool
	}{
		{
			name: "deny",
			exercise: func(ctx context.Context, flow *approvalFlow, command contract.RecoveryCommand) (string, error) {
				_, err := flow.client.DecideApproval(ctx, flow.socketPath, "operator_denied", command.CommandID, contract.ApprovalDenied, flow.clock.Now().Add(time.Minute))
				return "approval_denied", err
			},
			wantReason: "operator_denied",
			wantAudit:  true,
		},
		{
			name: "expire",
			exercise: func(ctx context.Context, flow *approvalFlow, command contract.RecoveryCommand) (string, error) {
				flow.clock.Set(command.ExpiresAt)
				_, err := flow.client.DecideApproval(ctx, flow.socketPath, "operator_requested", command.CommandID, contract.ApprovalGranted, command.ExpiresAt)
				return "approval_expired", err
			},
			wantReason: "command_expired",
			wantAudit:  true,
		},
		{
			name: "revoke",
			exercise: func(ctx context.Context, flow *approvalFlow, command contract.RecoveryCommand) (string, error) {
				if _, err := flow.client.DecideApproval(ctx, flow.socketPath, "operator_requested", command.CommandID, contract.ApprovalGranted, flow.clock.Now().Add(time.Minute)); err != nil {
					return "", err
				}
				flow.source.SetAuthorizedApprovers([]string{"uid:other/gid:other"})
				result, err := flow.coordinator.Resume(ctx, command.CommandID)
				if err != nil {
					return "", err
				}
				if result.Outcome != recovery.OutcomeDenied || result.Decision.ReasonCode != policy.ReasonApprovalRevoked {
					return "", fmt.Errorf("resume outcome=%q reason=%q", result.Outcome, result.Decision.ReasonCode)
				}
				return "approval_revoked", nil
			},
			wantReason: "approval_revoked",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flow := newApprovalFlow(t)
			ctx := testContext(t)
			analysisResult := flow.analyze(ctx, t, "incident-1")
			request := flow.request("incident-1", "delivery-1", analysisResult)
			waiting, err := flow.coordinator.Submit(ctx, request)
			if err != nil || waiting.Outcome != recovery.OutcomeAwaitApproval {
				t.Fatalf("Submit() = %#v, %v, want approval wait", waiting, err)
			}

			verification, exerciseErr := test.exercise(ctx, flow, waiting.Command)
			if test.name == "expire" {
				if !errors.Is(exerciseErr, adminipc.ErrRequestRejected) {
					t.Fatalf("expired decision error = %v, want %v", exerciseErr, adminipc.ErrRequestRejected)
				}
			} else if exerciseErr != nil {
				t.Fatalf("%s exercise error = %v", test.name, exerciseErr)
			}
			if flow.adapter.executeCalls != 0 {
				t.Fatalf("%s execute calls=%d, want no Docker execution", test.name, flow.adapter.executeCalls)
			}
			if test.wantAudit && !flow.hasAuditReason(t, test.wantReason) {
				t.Fatalf("%s audit reason %q was not recorded", test.name, test.wantReason)
			}

			terminal, err := flow.report.PublishTerminal(ctx, report.Input{
				IncidentID:                    waiting.Command.IncidentID,
				TerminalState:                 contract.IncidentFailed,
				IdempotencyKey:                request.IdempotencyKey,
				OccurredAt:                    flow.clock.Now(),
				AnalysisUnavailable:           true,
				VerificationResult:            verification,
				PreventionRecommendations:     []string{"Require a new local approval before another attempt."},
				PostmortemDraft:               "Recovery remained blocked before Docker execution.",
				RunbookImprovementSuggestions: []string{"Review the approval policy and expiry window."},
			})
			if err != nil || terminal.Report.VerificationResult != verification || terminal.ReportQueueItem.State != contract.DeliveryPending || terminal.LifecycleQueueItem.State != contract.DeliveryPending {
				t.Fatalf("PublishTerminal() = %#v, %v, want failed terminal report", terminal, err)
			}
			if !flow.hasTerminalLifecycle(t, waiting.Command.IncidentID) {
				t.Fatal("failed approval flow did not persist a terminal lifecycle event")
			}
		})
	}
}

// TestApprovalFlow_E2EReplayWebhookCannotAuthorizeCommand verifies a stale webhook cannot grant local approval.
func TestApprovalFlow_E2EReplayWebhookCannotAuthorizeCommand(t *testing.T) {
	flow := newApprovalFlow(t)
	ctx := testContext(t)
	analysisResult := flow.analyze(ctx, t, "incident-1")
	waiting, err := flow.coordinator.Submit(ctx, flow.request("incident-1", "delivery-1", analysisResult))
	if err != nil || waiting.Outcome != recovery.OutcomeAwaitApproval {
		t.Fatalf("Submit() = %#v, %v, want approval wait", waiting, err)
	}

	body := []byte(`{"status":"stale"}`)
	headers, err := flow.receiver.keyring.Sign("replayed-webhook", flow.clock.Now().Add(-webhook.DefaultTolerance-time.Second), body)
	if err != nil {
		t.Fatalf("Sign(stale webhook) error = %v", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, flow.receiver.server.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	request.Header.Set(webhook.HeaderID, headers.ID)
	request.Header.Set(webhook.HeaderTimestamp, headers.Timestamp)
	request.Header.Set(webhook.HeaderSignature, headers.Signature)
	response, err := flow.receiver.server.Client().Do(request)
	if err != nil {
		t.Fatalf("send stale webhook error = %v", err)
	}
	if closeErr := response.Body.Close(); closeErr != nil {
		t.Errorf("close stale webhook response: %v", closeErr)
	}
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("stale webhook status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}

	resumed, err := flow.coordinator.Resume(ctx, waiting.Command.CommandID)
	if err != nil || resumed.Outcome != recovery.OutcomeAwaitApproval || flow.adapter.executeCalls != 0 {
		t.Fatalf("Resume(after replay) = %#v, %v, execute calls=%d; want approval wait without Docker", resumed, err, flow.adapter.executeCalls)
	}
}

type approvalFlow struct {
	state       *store.Store
	clock       *flowClock
	source      *flowStateSource
	adapter     *flowAdapter
	coordinator *recovery.Coordinator
	verifier    *stabilization.Verifier
	report      *report.Publisher
	dispatcher  *delivery.Dispatcher
	receiver    *webhookReceiver
	client      *adminipc.Client
	socketPath  string
}

func newApprovalFlow(t *testing.T) *approvalFlow {
	t.Helper()
	clock := &flowClock{now: time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)}
	state, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db"), LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Errorf("close state: %v", err)
		}
	})

	keyring, err := webhook.NewKeyring(testWebhookSecret)
	if err != nil {
		t.Fatalf("create webhook keyring: %v", err)
	}
	receiver := newWebhookReceiver(t, keyring, clock)
	lifecycleSource, err := lifecycle.NewSource(state)
	if err != nil {
		t.Fatalf("create lifecycle source: %v", err)
	}
	reportSource, err := report.NewSource(state)
	if err != nil {
		t.Fatalf("create report source: %v", err)
	}
	nextID := newIDGenerator()
	dispatcher, err := delivery.New(delivery.Options{
		State:           state,
		Client:          receiver.server.Client(),
		Payloads:        delivery.PayloadSources{contract.DeliveryPayloadLifecycleEvent: lifecycleSource, contract.DeliveryPayloadIncidentReport: reportSource},
		Keyring:         keyring,
		Clock:           clock,
		NewDeliveryID:   nextID("delivery"),
		NewWebhookID:    nextID("webhook"),
		NewAuditEventID: nextID("delivery-audit"),
		Destinations:    map[string]string{"operations": receiver.server.URL},
		MaxQueueItems:   16,
		MaxAttempts:     2,
		InitialBackoff:  time.Second,
		MaxBackoff:      time.Second,
		RequestTimeout:  time.Second,
		MaxPayloadBytes: maxWebhookBodyBytes,
	})
	if err != nil {
		t.Fatalf("create delivery dispatcher: %v", err)
	}
	lifecyclePublisher, err := lifecycle.New(lifecycle.Options{State: state, Queue: dispatcher, DestinationRef: "operations", Clock: lifecycle.ClockFunc(clock.Now), DeliveryTTL: time.Hour})
	if err != nil {
		t.Fatalf("create lifecycle publisher: %v", err)
	}
	reportPublisher, err := report.New(report.Options{State: state, Queue: dispatcher, Lifecycle: lifecyclePublisher, DestinationRef: "operations", Clock: report.ClockFunc(clock.Now), DeliveryTTL: time.Hour})
	if err != nil {
		t.Fatalf("create report publisher: %v", err)
	}

	target, snapshot, input := recoveryPolicy(clock.Now())
	source := &flowStateSource{target: target, snapshot: snapshot, input: input}
	approvals, err := recovery.NewApprovalManager(recovery.ApprovalOptions{State: state, Clock: recovery.ClockFunc(clock.Now), NewApprovalID: nextID("approval"), NewAuditEventID: nextID("approval-audit")})
	if err != nil {
		t.Fatalf("create approval manager: %v", err)
	}
	adapter := &flowAdapter{}
	coordinator, err := recovery.New(recovery.Options{
		State:              state,
		Adapter:            adapter,
		StateSource:        recovery.ApprovalStateSource{Source: source, Approvals: approvals},
		Clock:              recovery.ClockFunc(clock.Now),
		NewCommandID:       nextID("command"),
		LifecyclePublisher: lifecyclePublisher,
	})
	if err != nil {
		t.Fatalf("create recovery coordinator: %v", err)
	}
	verifier, err := stabilization.New(stabilization.Options{State: state, Probe: stabilizationProbe{}, Clock: clock, Finalizer: coordinator, RetryState: source})
	if err != nil {
		t.Fatalf("create stabilization verifier: %v", err)
	}

	socketPath, stopServer := startApprovalServer(t, state, approvals, nextID("admin-audit"))
	client, err := adminipc.NewClient(adminipc.ClientOptions{RequestTimeout: time.Second, Clock: time.Now, NewRequestID: nextID("request")})
	if err != nil {
		stopServer()
		t.Fatalf("create administrative client: %v", err)
	}
	return &approvalFlow{state: state, clock: clock, source: source, adapter: adapter, coordinator: coordinator, verifier: verifier, report: reportPublisher, dispatcher: dispatcher, receiver: receiver, client: client, socketPath: socketPath}
}

func (f *approvalFlow) analyze(ctx context.Context, t *testing.T, incidentID string) contract.AnalysisResult {
	t.Helper()
	content := "registered health sample failed"
	now := f.clock.Now()
	analysisDocument, err := json.Marshal(contract.AnalysisResult{
		SchemaVersion: contract.SchemaVersionV1,
		IncidentID:    incidentID,
		Hypotheses: []contract.Hypothesis{{
			Summary:      "Health probe failure requires approved recovery.",
			EvidenceRefs: []string{"evidence-1"},
		}},
		EvidenceRefs:               []string{"evidence-1"},
		ConfidenceLabels:           []contract.ConfidenceLabel{contract.ConfidenceHigh},
		NotificationRecommendation: contract.NotificationNotify,
		CandidateRunbookIDs:        []string{"restart-web"},
	})
	if err != nil {
		t.Fatalf("marshal fake analysis: %v", err)
	}
	model, err := llm.NewFake("approval-e2e", []llm.FakeEvent{{
		Response: &model.LLMResponse{Content: genai.NewContentFromText(string(analysisDocument), "model")},
	}})
	if err != nil {
		t.Fatalf("create fake model: %v", err)
	}
	graph, err := analysis.NewGraph(analysis.Options{Model: model, Timeout: time.Second, MaxAttempts: 1, MaxEvidenceBytes: 1024})
	if err != nil {
		t.Fatalf("create analysis graph: %v", err)
	}
	input := analysis.Input{
		IncidentID: incidentID,
		Evidence: []analysis.Evidence{{
			Reference: contract.EvidenceRef{
				SchemaVersion:    contract.SchemaVersionV1,
				EvidenceID:       "evidence-1",
				SourceType:       "docker",
				CollectorID:      "local",
				Start:            now,
				End:              now,
				RedactionProfile: "strict",
				Digest:           "evidence-digest",
				ByteCount:        len(content),
				RetentionUntil:   now.Add(time.Hour),
			},
			Content: content,
		}},
		Runbooks: []analysis.RunbookDescription{{
			RunbookID:   "restart-web",
			Description: "Restart the registered web container.",
		}},
	}
	outcome := graph.Analyze(ctx, input)
	if outcome.Status != analysis.StatusComplete {
		t.Fatalf("Analyze() = %#v, want complete fake-model result", outcome)
	}
	return outcome.Result
}

func (f *approvalFlow) request(incidentID, idempotencyKey string, result contract.AnalysisResult) recovery.Request {
	input := f.source.input
	input.AnalysisAvailable = true
	input.AnalysisCandidateIDs = append([]string(nil), result.CandidateRunbookIDs...)
	input.AnalysisConfidence = append([]contract.ConfidenceLabel(nil), result.ConfidenceLabels...)
	input.NotificationSuggestion = result.NotificationRecommendation
	f.source.input = input
	return recovery.Request{IncidentID: incidentID, Target: f.source.target, PolicySnapshot: f.source.snapshot, PolicyInput: input, ExpiresAt: f.clock.Now().Add(5 * time.Minute), IdempotencyKey: idempotencyKey}
}

func (f *approvalFlow) stabilizationRequest(command contract.RecoveryCommand) stabilization.Request {
	return stabilization.Request{Command: command, Target: f.source.target, Policy: contract.StabilizationPolicy{RecoverySamples: 2, Window: contract.NewDuration(time.Minute)}, RetryPolicy: contract.RetryPolicy{MaxAttempts: 1}}
}

func (f *approvalFlow) hasQueuedLifecycle(t *testing.T, command contract.RecoveryCommand, eventType contract.LifecycleEventType, reason string) bool {
	t.Helper()
	eventID := lifecycle.StableEventID(eventType, command.IncidentID, command.CommandID)
	found := false
	if err := f.state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketLifecycleEvents, func(_ string, document []byte) error {
			var event contract.LifecycleEvent
			if err := json.Unmarshal(document, &event); err != nil {
				return err
			}
			if event.EventID == eventID && event.EventType == eventType && event.ReasonCode == reason {
				found = true
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("scan lifecycle events: %v", err)
	}
	return found && f.hasDelivery(t, contract.DeliveryPayloadLifecycleEvent, eventID)
}

func (f *approvalFlow) hasTerminalLifecycle(t *testing.T, incidentID string) bool {
	t.Helper()
	found := false
	if err := f.state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketLifecycleEvents, func(_ string, document []byte) error {
			var event contract.LifecycleEvent
			if err := json.Unmarshal(document, &event); err != nil {
				return err
			}
			if event.IncidentID == incidentID && event.EventType == contract.LifecycleIncidentFailed && event.ReasonCode == "terminal_failed" {
				found = true
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("scan terminal lifecycle events: %v", err)
	}
	return found
}

func (f *approvalFlow) hasDelivery(t *testing.T, payloadType contract.DeliveryPayloadType, payloadRef string) bool {
	t.Helper()
	found := false
	if err := f.state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketDeliveryQueue, func(_ string, document []byte) error {
			var item contract.DeliveryQueueItem
			if err := json.Unmarshal(document, &item); err != nil {
				return err
			}
			if item.PayloadType == payloadType && item.PayloadRef == payloadRef {
				found = true
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("scan delivery queue: %v", err)
	}
	return found
}

func (f *approvalFlow) hasAuditReason(t *testing.T, reason string) bool {
	t.Helper()
	found := false
	if err := f.state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketAudit, func(_ string, document []byte) error {
			var event contract.AuditEvent
			if err := json.Unmarshal(document, &event); err != nil {
				return err
			}
			if event.ReasonCode == reason {
				found = true
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("scan audit events: %v", err)
	}
	return found
}

func recoveryPolicy(now time.Time) (contract.ServiceTarget, policy.Snapshot, policy.Input) {
	target := contract.ServiceTarget{
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
	}
	runbook := contract.Runbook{
		SchemaVersion: contract.SchemaVersionV1,
		RunbookID:     "restart-web",
		Digest:        "digest-restart-web",
		AdapterType:   docker.AdapterType,
		TypedActions: []contract.TypedAction{{
			ActionType:     contract.ActionDockerContainerRestart,
			TargetSelector: target.Selector,
			StopTimeout:    contract.NewDuration(time.Second),
		}},
		RiskTier:       contract.RiskHigh,
		ApprovalPolicy: contract.ApprovalPolicy{Required: true},
		Preconditions:  []string{"docker_healthy"},
		RetryPolicy:    contract.RetryPolicy{MaxAttempts: 1},
		StabilizationPolicy: contract.StabilizationPolicy{
			RecoverySamples: 2,
			Window:          contract.NewDuration(time.Minute),
		},
	}
	snapshot := policy.Snapshot{
		Runbooks: []policy.RegisteredRunbook{{
			Runbook:          runbook,
			TargetID:         target.TargetID,
			AnalysisRequired: true,
		}},
		AuthorizedApprovers: []string{"uid:1000/gid:1000"},
	}
	input := policy.Input{
		RunbookID:     runbook.RunbookID,
		RunbookDigest: runbook.Digest,
		TargetID:      target.TargetID,
		ActionIndex:   0,
		Preconditions: map[string]bool{
			"docker_healthy": true,
		},
		Now: now,
	}
	return target, snapshot, input
}

type flowClock struct{ now time.Time }

// Now returns the deterministic test time.
func (c *flowClock) Now() time.Time {
	return c.now
}

// Advance moves the deterministic test time forward.
func (c *flowClock) Advance(value time.Duration) {
	c.now = c.now.Add(value)
}

// Set replaces the deterministic test time.
func (c *flowClock) Set(value time.Time) {
	c.now = value
}

type flowStateSource struct {
	target   contract.ServiceTarget
	snapshot policy.Snapshot
	input    policy.Input
}

// Load returns a copy of the current test execution facts.
func (s *flowStateSource) Load(_ context.Context, _ contract.RecoveryCommand) (recovery.ExecutionState, error) {
	return s.executionState(), nil
}

// LoadRetryState returns a copy of the current test retry facts.
func (s *flowStateSource) LoadRetryState(_ context.Context, _ contract.RecoveryCommand) (stabilization.RetryState, error) {
	state := s.executionState()
	return stabilization.RetryState{
		Target:         state.Target,
		PolicySnapshot: state.PolicySnapshot,
		PolicyInput:    state.PolicyInput,
	}, nil
}

// SetAuthorizedApprovers replaces the authorized identities for a revalidation test.
func (s *flowStateSource) SetAuthorizedApprovers(identities []string) {
	s.snapshot.AuthorizedApprovers = append([]string(nil), identities...)
}

func (s *flowStateSource) executionState() recovery.ExecutionState {
	target := s.target
	target.ProbeRules = append([]contract.ProbeRule(nil), s.target.ProbeRules...)

	snapshot := s.snapshot
	snapshot.Runbooks = append([]policy.RegisteredRunbook(nil), s.snapshot.Runbooks...)
	snapshot.AuthorizedApprovers = append([]string(nil), s.snapshot.AuthorizedApprovers...)

	input := s.input
	input.AnalysisCandidateIDs = append([]string(nil), s.input.AnalysisCandidateIDs...)
	input.AnalysisConfidence = append([]contract.ConfidenceLabel(nil), s.input.AnalysisConfidence...)
	input.Preconditions = make(map[string]bool, len(s.input.Preconditions))
	for key, value := range s.input.Preconditions {
		input.Preconditions[key] = value
	}

	return recovery.ExecutionState{Target: target, PolicySnapshot: snapshot, PolicyInput: input}
}

type flowAdapter struct {
	validateCalls int
	executeCalls  int
}

// ValidateAction records the pre-execution validation request.
func (a *flowAdapter) ValidateAction(context.Context, contract.ServiceTarget, contract.TypedAction) error {
	a.validateCalls++
	return nil
}

// Execute records one bounded Docker action without external I/O.
func (a *flowAdapter) Execute(context.Context, contract.ServiceTarget, contract.TypedAction) error {
	a.executeCalls++
	return nil
}

// Verify returns a healthy deterministic Docker snapshot.
func (a *flowAdapter) Verify(context.Context, contract.ServiceTarget) (docker.Snapshot, error) {
	return docker.Snapshot{TargetID: "target-web", Running: true, Healthy: true}, nil
}

type stabilizationProbe struct{}

// Observe returns a healthy deterministic stabilization sample.
func (stabilizationProbe) Observe(context.Context, contract.ServiceTarget) (stabilization.Sample, error) {
	return stabilization.Sample{Healthy: true, Metrics: map[string]float64{"availability": 1}}, nil
}

type webhookReceiver struct {
	server  *httptest.Server
	keyring *webhook.Keyring
	clock   *flowClock

	mu     sync.Mutex
	bodies [][]byte
	err    error
}

func newWebhookReceiver(t *testing.T, keyring *webhook.Keyring, clock *flowClock) *webhookReceiver {
	t.Helper()
	receiver := &webhookReceiver{keyring: keyring, clock: clock}
	receiver.server = httptest.NewTLSServer(http.HandlerFunc(receiver.handle))
	t.Cleanup(receiver.server.Close)
	return receiver
}

func (r *webhookReceiver) handle(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(io.LimitReader(request.Body, maxWebhookBodyBytes+1))
	closeErr := request.Body.Close()
	if err == nil && closeErr != nil {
		err = closeErr
	}
	if err == nil && len(body) > maxWebhookBodyBytes {
		err = errors.New("webhook payload exceeds limit")
	}
	if err == nil {
		err = r.keyring.Verify(webhook.Headers{ID: request.Header.Get(webhook.HeaderID), Timestamp: request.Header.Get(webhook.HeaderTimestamp), Signature: request.Header.Get(webhook.HeaderSignature)}, body, r.clock.Now())
	}
	r.mu.Lock()
	if err != nil && r.err == nil {
		r.err = err
	}
	if err == nil {
		r.bodies = append(r.bodies, append([]byte(nil), body...))
	}
	r.mu.Unlock()
	if err == nil {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	writer.WriteHeader(http.StatusBadRequest)
}

func (r *webhookReceiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

func (r *webhookReceiver) failure() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func startApprovalServer(t *testing.T, state *store.Store, approvals *recovery.ApprovalManager, newAuditID func() (string, error)) (string, func()) {
	t.Helper()
	directory, err := os.MkdirTemp("/private/tmp", "pulse-agent-approval-")
	if err != nil {
		t.Fatalf("create socket directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove socket directory: %v", err)
		}
	})
	socketPath := filepath.Join(directory, "admin.sock")
	actor := adminipc.Actor{UID: 1000, GID: 1000}
	server, err := adminipc.NewServer(adminipc.Options{
		SocketPath:      socketPath,
		AllowedUIDs:     []uint32{actor.UID},
		AllowedGIDs:     []uint32{actor.GID},
		State:           state,
		Approvals:       approvals,
		RequestTimeout:  time.Second,
		PeerCredentials: func(*net.UnixConn) (adminipc.Actor, error) { return actor, nil },
		Clock:           time.Now,
		NewAuditID:      newAuditID,
	})
	if err != nil {
		t.Fatalf("create approval server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var serveErr error
	go func() {
		defer close(done)
		serveErr = server.Serve(ctx)
	}()
	waitForSocket(t, socketPath, done, func() error { return serveErr })
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
				if serveErr != nil {
					t.Errorf("approval server stopped with error: %v", serveErr)
				}
			case <-time.After(testTimeout):
				t.Error("approval server did not stop before timeout")
			}
		})
	}
	t.Cleanup(stop)
	return socketPath, stop
}

func waitForSocket(t *testing.T, socketPath string, done <-chan struct{}, runErr func() error) {
	t.Helper()
	timeout := time.NewTimer(testTimeout)
	defer timeout.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := os.Lstat(socketPath)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		select {
		case <-done:
			t.Fatalf("approval server stopped before socket %q became available: %v", socketPath, runErr())
		case <-timeout.C:
			t.Fatalf("approval socket %q did not become available: %v", socketPath, err)
		case <-ticker.C:
		}
	}
}

func newIDGenerator() func(string) func() (string, error) {
	var mu sync.Mutex
	sequence := 0
	return func(prefix string) func() (string, error) {
		return func() (string, error) {
			mu.Lock()
			defer mu.Unlock()
			sequence++
			return fmt.Sprintf("%s-%d", prefix, sequence), nil
		}
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}
