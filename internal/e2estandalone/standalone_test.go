// Package e2estandalone verifies the direct-observation standalone recovery flow.
package e2estandalone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/adk/v2/model"
	"google.golang.org/genai"

	"pulse-agent/internal/analysis"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/correlator"
	"pulse-agent/internal/delivery"
	"pulse-agent/internal/docker"
	"pulse-agent/internal/evidence"
	"pulse-agent/internal/lifecycle"
	"pulse-agent/internal/llm"
	"pulse-agent/internal/observer"
	"pulse-agent/internal/policy"
	"pulse-agent/internal/recovery"
	"pulse-agent/internal/report"
	"pulse-agent/internal/stabilization"
	"pulse-agent/internal/store"
	"pulse-agent/internal/target"
	"pulse-agent/internal/webhook"
)

const (
	testTimeout       = 3 * time.Second
	probeInterval     = 20 * time.Second
	stabilizeWindow   = 20 * time.Second
	maxWebhookBytes   = 64 * 1024
	testWebhookSecret = "whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
)

// TestStandaloneFlow_E2EDirectObservationRecoversAndReports verifies the full low-risk direct-observation path.
func TestStandaloneFlow_E2EDirectObservationRecoversAndReports(t *testing.T) {
	flow := newStandaloneFlow(t)
	ctx := testContext(t)
	faultStartedAt := flow.clock.Now()

	first := flow.observeOnce(t, ctx)
	if first.NormalizedState != contract.StateUnknown {
		t.Fatalf("first observation state = %q, want %q before consecutive failures", first.NormalizedState, contract.StateUnknown)
	}

	flow.clock.Advance(probeInterval)
	candidateObservation := flow.observeOnce(t, ctx)
	if candidateObservation.NormalizedState != contract.StateUnhealthy {
		t.Fatalf("candidate observation state = %q, want %q", candidateObservation.NormalizedState, contract.StateUnhealthy)
	}
	candidate, err := flow.correlator.Ingest(correlator.Signal{Source: "observer", Severity: contract.SeverityWarning, Observation: candidateObservation})
	if err != nil || candidate.Phase != correlator.PhaseCandidate {
		t.Fatalf("Ingest(candidate) = %#v, %v, want candidate", candidate, err)
	}
	if detectionDelay := candidateObservation.ObservedAt.Sub(faultStartedAt); detectionDelay > 2*probeInterval || detectionDelay > time.Minute {
		t.Fatalf("candidate detection delay = %s, want at most two intervals and one minute", detectionDelay)
	}

	flow.clock.Advance(probeInterval)
	confirmedObservation := flow.observeOnce(t, ctx)
	confirmed, err := flow.correlator.Ingest(correlator.Signal{Source: "observer", Severity: contract.SeverityWarning, Observation: confirmedObservation})
	if err != nil || confirmed.Phase != correlator.PhaseConfirmed || confirmed.Incident.State != contract.IncidentAnalyzing {
		t.Fatalf("Ingest(confirmation) = %#v, %v, want confirmed analyzing incident", confirmed, err)
	}
	confirmedEvent, err := flow.lifecycle.Publish(ctx, lifecycle.Input{
		EventID:    lifecycle.StableEventID(contract.LifecycleIncidentConfirmed, confirmed.Incident.IncidentID, "direct-observation"),
		EventType:  contract.LifecycleIncidentConfirmed,
		IncidentID: confirmed.Incident.IncidentID,
		ReasonCode: "consecutive_probe_failure",
		OccurredAt: flow.clock.Now(),
	})
	if err != nil || confirmedEvent.QueueItem.State != contract.DeliveryPending {
		t.Fatalf("Publish(incident.confirmed) = %#v, %v, want durable pending notification", confirmedEvent, err)
	}

	evidenceResult, err := flow.adapter.CollectEvidence(ctx, flow.target)
	if err != nil {
		t.Fatalf("CollectEvidence() error = %v", err)
	}
	if strings.Contains(evidenceResult.Content, "fixture-api-key-not-secret") || strings.Contains(evidenceResult.Content, "fixture.user@example.invalid") {
		t.Fatalf("CollectEvidence() leaked fixture secret or customer data: %q", evidenceResult.Content)
	}
	analysisResult := flow.analyze(ctx, t, confirmed.Incident.IncidentID, evidenceResult)
	request := flow.recoveryRequest(confirmed.Incident.IncidentID, "direct-recovery-1", analysisResult)

	recovered, err := flow.coordinator.Submit(ctx, request)
	if err != nil || recovered.Outcome != recovery.OutcomeStabilizing || flow.dockerClient.restartCalls != 1 {
		t.Fatalf("Submit() = %#v, %v, restarts=%d, want one stabilizing restart", recovered, err, flow.dockerClient.restartCalls)
	}
	if !flow.hasLifecycle(t, recovered.Command.IncidentID, contract.LifecycleRecoveryStarted, recovered.Command.CommandID, "recovery_started") {
		t.Fatal("recovery.started was not durably queued before Docker restart")
	}

	duplicate, err := flow.coordinator.Submit(ctx, request)
	if err != nil || !duplicate.Duplicate || duplicate.Command.CommandID != recovered.Command.CommandID || flow.dockerClient.restartCalls != 1 {
		t.Fatalf("Submit(duplicate) = %#v, %v, restarts=%d, want one idempotent Docker effect", duplicate, err, flow.dockerClient.restartCalls)
	}

	if verification, err := flow.verifier.Verify(ctx, flow.stabilizationRequest(recovered.Command)); err != nil || verification.Outcome != stabilization.OutcomePending {
		t.Fatalf("Verify(first) = %#v, %v, want pending stabilization", verification, err)
	}
	flow.clock.Advance(stabilizeWindow)
	if verification, err := flow.verifier.Verify(ctx, flow.stabilizationRequest(recovered.Command)); err != nil || verification.Outcome != stabilization.OutcomeSucceeded {
		t.Fatalf("Verify(second) = %#v, %v, want successful stabilization", verification, err)
	}

	terminal, err := flow.report.PublishTerminal(ctx, report.Input{
		IncidentID:                    recovered.Command.IncidentID,
		TerminalState:                 contract.IncidentClosed,
		IdempotencyKey:                request.IdempotencyKey,
		OccurredAt:                    flow.clock.Now(),
		Analysis:                      &analysisResult,
		EvidenceRefs:                  []string{evidenceResult.Reference.EvidenceID},
		Actions:                       []contract.ReportAction{{CommandID: recovered.Command.CommandID, ActionType: contract.ActionDockerContainerRestart, Result: "succeeded"}},
		VerificationResult:            "stabilized",
		PreventionRecommendations:     []string{"Review direct-probe thresholds after recovery."},
		PostmortemDraft:               "Direct Docker recovery stabilized the registered target.",
		RunbookImprovementSuggestions: []string{"Keep the registered low-risk restart action bounded."},
	})
	if err != nil || terminal.ReportQueueItem.State != contract.DeliveryPending || terminal.LifecycleQueueItem.State != contract.DeliveryPending {
		t.Fatalf("PublishTerminal() = %#v, %v, want durable pending terminal report and lifecycle event", terminal, err)
	}

	deliveries, err := flow.dispatcher.DeliverDue(ctx)
	if err != nil {
		t.Fatalf("DeliverDue() error = %v", err)
	}
	if len(deliveries) != 4 || flow.receiver.count() != 4 || flow.receiver.failure() != nil {
		t.Fatalf("DeliverDue()=%d receiver=%d receiver error=%v, want four authenticated lifecycle/report deliveries", len(deliveries), flow.receiver.count(), flow.receiver.failure())
	}
	for _, delivery := range deliveries {
		if !delivery.Sent || delivery.Item.State != contract.DeliveryDelivered {
			t.Errorf("delivery = %#v, want delivered", delivery)
		}
	}
}

// TestStandaloneFlow_E2EDaemonUnavailableQueuesNotificationWithoutRestart verifies direct observation fails closed when Docker is unavailable.
func TestStandaloneFlow_E2EDaemonUnavailableQueuesNotificationWithoutRestart(t *testing.T) {
	flow := newStandaloneFlow(t)
	ctx := testContext(t)
	flow.dockerClient.inspectErr = errors.New("docker daemon unavailable")

	observations, err := flow.scheduler.RunCycle(ctx)
	if !errors.Is(err, observer.ErrProbeFailed) || len(observations) != 0 {
		t.Fatalf("RunCycle() observations=%#v error=%v, want %v without observation", observations, err, observer.ErrProbeFailed)
	}
	queued, err := flow.lifecycle.Publish(ctx, lifecycle.Input{
		EventID:    lifecycle.StableEventID(contract.LifecycleIncidentFailed, "incident-daemon", "docker-unavailable"),
		EventType:  contract.LifecycleIncidentFailed,
		IncidentID: "incident-daemon",
		ReasonCode: "docker_unavailable",
		OccurredAt: flow.clock.Now(),
	})
	if err != nil || queued.QueueItem.State != contract.DeliveryPending {
		t.Fatalf("Publish(docker unavailable) = %#v, %v, want pending notification", queued, err)
	}
	if flow.dockerClient.restartCalls != 0 || !flow.hasDelivery(t, contract.DeliveryPayloadLifecycleEvent, queued.Event.EventID, contract.DeliveryPending) {
		t.Fatalf("daemon-unavailable restarts=%d pending=%t, want no Docker restart and durable notification", flow.dockerClient.restartCalls, flow.hasDelivery(t, contract.DeliveryPayloadLifecycleEvent, queued.Event.EventID, contract.DeliveryPending))
	}
}

type standaloneFlow struct {
	state        *store.Store
	clock        *flowClock
	target       contract.ServiceTarget
	dockerClient *fixtureDockerClient
	adapter      *docker.Adapter
	scheduler    *observer.Scheduler
	correlator   *correlator.Correlator
	coordinator  *recovery.Coordinator
	verifier     *stabilization.Verifier
	lifecycle    *lifecycle.Publisher
	report       *report.Publisher
	dispatcher   *delivery.Dispatcher
	receiver     *webhookReceiver
	source       *executionStateSource
}

func newStandaloneFlow(t *testing.T) *standaloneFlow {
	t.Helper()
	clock := &flowClock{now: time.Date(2026, time.July, 22, 0, 0, 0, 0, time.UTC)}
	state, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db"), LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Errorf("close state: %v", err)
		}
	})

	ids := newIDGenerator()
	targetValue, snapshot, input := standalonePolicy(clock.Now())
	registry, err := target.NewRegistry(target.Options{
		State:            state,
		AllowedTargets:   []target.AllowedTarget{{TargetID: targetValue.TargetID, AdapterType: docker.AdapterType}},
		MaxTargets:       1,
		MaxEvidenceBytes: int64(targetValue.EvidencePolicy.MaxBytes),
		Clock:            clock.Now,
		NewAuditEventID:  ids("target-audit"),
	})
	if err != nil {
		t.Fatalf("create target registry: %v", err)
	}
	if _, err := registry.Register(target.Registration{Target: targetValue, ActorIdentity: "operator-1", RequestID: "register-target", ReasonCode: "onboarding"}); err != nil {
		t.Fatalf("register target: %v", err)
	}

	collector, err := evidence.NewCollector(evidence.Options{
		AllowedFields: []string{"message"},
		MaxLines:      8,
		MaxBytes:      int(targetValue.EvidencePolicy.MaxBytes),
		Retention:     time.Hour,
		Clock:         clock.Now,
		NewEvidenceID: ids("evidence"),
	})
	if err != nil {
		t.Fatalf("create evidence collector: %v", err)
	}
	dockerClient := &fixtureDockerClient{
		containers: map[string]docker.Container{
			"web": {ID: "container-web", Running: true, Health: "unhealthy"},
		},
		logs: "WARN api_key=fixture-api-key-not-secret customer_email=fixture.user@example.invalid\nINFO container health failed",
	}
	adapter, err := docker.NewAdapter(docker.Options{Client: dockerClient, Evidence: collector, Clock: clock, MaxLogBytes: int(targetValue.EvidencePolicy.MaxBytes), Timeout: time.Second})
	if err != nil {
		t.Fatalf("create docker adapter: %v", err)
	}
	scheduler, err := observer.NewScheduler(observer.Options{Targets: registry, Probe: adapter, Clock: clock, NewObservationID: ids("observation")})
	if err != nil {
		t.Fatalf("create observer scheduler: %v", err)
	}
	incidentCorrelator, err := correlator.New(correlator.Options{State: state, NewIncidentID: ids("incident"), DedupeWindow: time.Minute})
	if err != nil {
		t.Fatalf("create correlator: %v", err)
	}

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
	dispatcher, err := delivery.New(delivery.Options{
		State:           state,
		Client:          receiver.server.Client(),
		Payloads:        delivery.PayloadSources{contract.DeliveryPayloadLifecycleEvent: lifecycleSource, contract.DeliveryPayloadIncidentReport: reportSource},
		Keyring:         keyring,
		Clock:           clock,
		NewDeliveryID:   ids("delivery"),
		NewWebhookID:    ids("webhook"),
		NewAuditEventID: ids("delivery-audit"),
		Destinations:    map[string]string{"operations": receiver.server.URL},
		MaxQueueItems:   16,
		MaxAttempts:     2,
		InitialBackoff:  time.Second,
		MaxBackoff:      time.Second,
		RequestTimeout:  time.Second,
		MaxPayloadBytes: maxWebhookBytes,
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

	source := &executionStateSource{target: targetValue, snapshot: snapshot, input: input}
	coordinator, err := recovery.New(recovery.Options{
		State:              state,
		Adapter:            adapter,
		StateSource:        source,
		Clock:              recovery.ClockFunc(clock.Now),
		NewCommandID:       ids("command"),
		LifecyclePublisher: lifecyclePublisher,
	})
	if err != nil {
		t.Fatalf("create recovery coordinator: %v", err)
	}
	verifier, err := stabilization.New(stabilization.Options{State: state, Probe: adapterProbe{adapter: adapter}, Clock: clock, Finalizer: coordinator, RetryState: source})
	if err != nil {
		t.Fatalf("create stabilization verifier: %v", err)
	}

	return &standaloneFlow{
		state:        state,
		clock:        clock,
		target:       targetValue,
		dockerClient: dockerClient,
		adapter:      adapter,
		scheduler:    scheduler,
		correlator:   incidentCorrelator,
		coordinator:  coordinator,
		verifier:     verifier,
		lifecycle:    lifecyclePublisher,
		report:       reportPublisher,
		dispatcher:   dispatcher,
		receiver:     receiver,
		source:       source,
	}
}

func (f *standaloneFlow) observeOnce(t *testing.T, ctx context.Context) contract.HealthObservation {
	t.Helper()
	observations, err := f.scheduler.RunCycle(ctx)
	if err != nil || len(observations) != 1 {
		t.Fatalf("RunCycle() observations=%#v error=%v, want one observation", observations, err)
	}
	return observations[0]
}

func (f *standaloneFlow) analyze(ctx context.Context, t *testing.T, incidentID string, evidenceResult evidence.Result) contract.AnalysisResult {
	t.Helper()
	analysisDocument, err := json.Marshal(contract.AnalysisResult{
		SchemaVersion: contract.SchemaVersionV1,
		IncidentID:    incidentID,
		Hypotheses: []contract.Hypothesis{{
			Summary:      "The direct availability probe found an unhealthy registered container.",
			EvidenceRefs: []string{evidenceResult.Reference.EvidenceID},
		}},
		EvidenceRefs:               []string{evidenceResult.Reference.EvidenceID},
		ConfidenceLabels:           []contract.ConfidenceLabel{contract.ConfidenceHigh},
		NotificationRecommendation: contract.NotificationNotify,
		CandidateRunbookIDs:        []string{"restart-web"},
	})
	if err != nil {
		t.Fatalf("marshal fake analysis: %v", err)
	}
	fakeModel, err := llm.NewFake("standalone-e2e", []llm.FakeEvent{{
		Response: &model.LLMResponse{Content: genai.NewContentFromText(string(analysisDocument), "model")},
	}})
	if err != nil {
		t.Fatalf("create fake model: %v", err)
	}
	graph, err := analysis.NewGraph(analysis.Options{Model: fakeModel, Timeout: time.Second, MaxAttempts: 1, MaxEvidenceBytes: maxWebhookBytes})
	if err != nil {
		t.Fatalf("create analysis graph: %v", err)
	}
	outcome := graph.Analyze(ctx, analysis.Input{
		IncidentID: incidentID,
		Evidence: []analysis.Evidence{{
			Reference: evidenceResult.Reference,
			Content:   evidenceResult.Content,
		}},
		Runbooks: []analysis.RunbookDescription{{
			RunbookID:   "restart-web",
			Description: "Restart the one registered web container.",
		}},
	})
	if outcome.Status != analysis.StatusComplete {
		t.Fatalf("Analyze() = %#v, want complete structured fake-model result", outcome)
	}
	return outcome.Result
}

func (f *standaloneFlow) recoveryRequest(incidentID, idempotencyKey string, analysisResult contract.AnalysisResult) recovery.Request {
	input := f.source.input
	input.AnalysisAvailable = true
	input.AnalysisCandidateIDs = append([]string(nil), analysisResult.CandidateRunbookIDs...)
	input.AnalysisConfidence = append([]contract.ConfidenceLabel(nil), analysisResult.ConfidenceLabels...)
	input.NotificationSuggestion = analysisResult.NotificationRecommendation
	f.source.input = input
	return recovery.Request{
		IncidentID:     incidentID,
		Target:         f.source.target,
		PolicySnapshot: f.source.snapshot,
		PolicyInput:    input,
		ExpiresAt:      f.clock.Now().Add(5 * time.Minute),
		IdempotencyKey: idempotencyKey,
	}
}

func (f *standaloneFlow) stabilizationRequest(command contract.RecoveryCommand) stabilization.Request {
	return stabilization.Request{
		Command: command,
		Target:  f.target,
		Policy: contract.StabilizationPolicy{
			RecoverySamples: 2,
			Window:          contract.NewDuration(stabilizeWindow),
		},
		RetryPolicy: contract.RetryPolicy{MaxAttempts: 1},
	}
}

func (f *standaloneFlow) hasLifecycle(t *testing.T, incidentID string, eventType contract.LifecycleEventType, idempotencyKey, reason string) bool {
	t.Helper()
	eventID := lifecycle.StableEventID(eventType, incidentID, idempotencyKey)
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
	return found && f.hasDelivery(t, contract.DeliveryPayloadLifecycleEvent, eventID, contract.DeliveryPending)
}

func (f *standaloneFlow) hasDelivery(t *testing.T, payloadType contract.DeliveryPayloadType, payloadRef string, state contract.DeliveryState) bool {
	t.Helper()
	found := false
	if err := f.state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketDeliveryQueue, func(_ string, document []byte) error {
			var item contract.DeliveryQueueItem
			if err := json.Unmarshal(document, &item); err != nil {
				return err
			}
			if item.PayloadType == payloadType && item.PayloadRef == payloadRef && item.State == state {
				found = true
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("scan delivery queue: %v", err)
	}
	return found
}

func standalonePolicy(now time.Time) (contract.ServiceTarget, policy.Snapshot, policy.Input) {
	targetValue := contract.ServiceTarget{
		SchemaVersion: contract.SchemaVersionV1,
		TargetID:      "web",
		AdapterType:   docker.AdapterType,
		Selector:      "container:web",
		ProbeRules: []contract.ProbeRule{{
			RuleID:              "availability",
			SignalType:          "availability",
			Interval:            contract.NewDuration(probeInterval),
			Timeout:             contract.NewDuration(time.Second),
			Threshold:           0.9,
			ConsecutiveFailures: 2,
			RecoverySamples:     2,
			SLOWindow:           contract.NewDuration(time.Minute),
			Severity:            contract.SeverityWarning,
		}},
		EvidencePolicy: contract.EvidencePolicy{RedactionProfile: "default", MaxBytes: 512},
		StabilizationPolicy: contract.StabilizationPolicy{
			RecoverySamples: 2,
			Window:          contract.NewDuration(stabilizeWindow),
		},
		Enabled: true,
	}
	runbook := contract.Runbook{
		SchemaVersion: contract.SchemaVersionV1,
		RunbookID:     "restart-web",
		Digest:        "digest-restart-web",
		AdapterType:   docker.AdapterType,
		TypedActions: []contract.TypedAction{{
			ActionType:     contract.ActionDockerContainerRestart,
			TargetSelector: targetValue.Selector,
			StopTimeout:    contract.NewDuration(time.Second),
		}},
		RiskTier:       contract.RiskLow,
		AutoExecute:    true,
		ApprovalPolicy: contract.ApprovalPolicy{Required: false},
		Preconditions:  []string{"docker_healthy"},
		RetryPolicy:    contract.RetryPolicy{MaxAttempts: 1},
		StabilizationPolicy: contract.StabilizationPolicy{
			RecoverySamples: 2,
			Window:          contract.NewDuration(stabilizeWindow),
		},
	}
	snapshot := policy.Snapshot{
		Runbooks: []policy.RegisteredRunbook{{
			Runbook:          runbook,
			TargetID:         targetValue.TargetID,
			AnalysisRequired: true,
		}},
		AuthorizedApprovers: []string{"operator-1"},
	}
	input := policy.Input{
		RunbookID:     runbook.RunbookID,
		RunbookDigest: runbook.Digest,
		TargetID:      targetValue.TargetID,
		ActionIndex:   0,
		Preconditions: map[string]bool{"docker_healthy": true},
		Now:           now,
	}
	return targetValue, snapshot, input
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

type executionStateSource struct {
	target   contract.ServiceTarget
	snapshot policy.Snapshot
	input    policy.Input
}

// Load returns current execution facts for one command.
func (s *executionStateSource) Load(context.Context, contract.RecoveryCommand) (recovery.ExecutionState, error) {
	return s.executionState(), nil
}

// LoadRetryState returns current retry facts for one command.
func (s *executionStateSource) LoadRetryState(context.Context, contract.RecoveryCommand) (stabilization.RetryState, error) {
	state := s.executionState()
	return stabilization.RetryState{Target: state.Target, PolicySnapshot: state.PolicySnapshot, PolicyInput: state.PolicyInput}, nil
}

func (s *executionStateSource) executionState() recovery.ExecutionState {
	targetValue := s.target
	targetValue.ProbeRules = append([]contract.ProbeRule(nil), s.target.ProbeRules...)

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
	return recovery.ExecutionState{Target: targetValue, PolicySnapshot: snapshot, PolicyInput: input}
}

type adapterProbe struct{ adapter *docker.Adapter }

// Observe turns a bounded Docker verification result into one stabilization sample.
func (p adapterProbe) Observe(ctx context.Context, targetValue contract.ServiceTarget) (stabilization.Sample, error) {
	snapshot, err := p.adapter.Verify(ctx, targetValue)
	if err != nil {
		return stabilization.Sample{}, err
	}
	availability := 0.0
	if snapshot.Healthy {
		availability = 1
	}
	return stabilization.Sample{Healthy: snapshot.Healthy, Metrics: map[string]float64{"availability": availability}}, nil
}

type fixtureDockerClient struct {
	containers   map[string]docker.Container
	logs         string
	inspectErr   error
	restartCalls int
}

// NegotiateAPIVersion accepts the adapter's bounded API negotiation.
func (c *fixtureDockerClient) NegotiateAPIVersion(context.Context) error {
	return nil
}

// Inspect returns the configured bounded container state.
func (c *fixtureDockerClient) Inspect(_ context.Context, identifier string) (docker.Container, error) {
	if c.inspectErr != nil {
		return docker.Container{}, c.inspectErr
	}
	container, found := c.containers[identifier]
	if !found {
		return docker.Container{}, errors.New("container not found")
	}
	return container, nil
}

// ListByLabel returns no Compose containers because this suite uses a direct container selector.
func (c *fixtureDockerClient) ListByLabel(context.Context, string, string) ([]docker.Container, error) {
	return nil, nil
}

// Logs returns bounded synthetic container logs for the evidence collector.
func (c *fixtureDockerClient) Logs(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(c.logs)), nil
}

// Restart records one bounded restart and returns the matching container to healthy state.
func (c *fixtureDockerClient) Restart(_ context.Context, identifier string, _ time.Duration) error {
	c.restartCalls++
	for key, container := range c.containers {
		if container.ID == identifier {
			container.Health = "healthy"
			c.containers[key] = container
			return nil
		}
	}
	return errors.New("container not found")
}

type webhookReceiver struct {
	server  *httptest.Server
	keyring *webhook.Keyring
	clock   *flowClock

	mu         sync.Mutex
	deliveries int
	err        error
}

func newWebhookReceiver(t *testing.T, keyring *webhook.Keyring, clock *flowClock) *webhookReceiver {
	t.Helper()
	receiver := &webhookReceiver{keyring: keyring, clock: clock}
	receiver.server = httptest.NewTLSServer(http.HandlerFunc(receiver.handle))
	t.Cleanup(receiver.server.Close)
	return receiver
}

func (r *webhookReceiver) handle(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(io.LimitReader(request.Body, maxWebhookBytes+1))
	closeErr := request.Body.Close()
	if err == nil && closeErr != nil {
		err = closeErr
	}
	if err == nil && len(body) > maxWebhookBytes {
		err = errors.New("webhook payload exceeds limit")
	}
	if err == nil {
		err = r.keyring.Verify(webhook.Headers{
			ID:        request.Header.Get(webhook.HeaderID),
			Timestamp: request.Header.Get(webhook.HeaderTimestamp),
			Signature: request.Header.Get(webhook.HeaderSignature),
		}, body, r.clock.Now())
	}
	r.mu.Lock()
	if err != nil && r.err == nil {
		r.err = err
	}
	if err == nil {
		r.deliveries++
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
	return r.deliveries
}

func (r *webhookReceiver) failure() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
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
