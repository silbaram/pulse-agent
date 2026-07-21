// Package e2ecompose verifies signed alert ingress and single-replica Compose recovery.
package e2ecompose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"pulse-agent/internal/alert"
	"pulse-agent/internal/audit"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/correlator"
	"pulse-agent/internal/delivery"
	"pulse-agent/internal/docker"
	"pulse-agent/internal/evidence"
	"pulse-agent/internal/lifecycle"
	"pulse-agent/internal/observer"
	"pulse-agent/internal/policy"
	"pulse-agent/internal/recovery"
	"pulse-agent/internal/store"
	"pulse-agent/internal/target"
	"pulse-agent/internal/webhook"
)

const (
	composeServiceLabel  = "com.docker.compose.service"
	currentSecret        = "whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
	previousSecret       = "whsec_YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg="
	fixedVectorBody      = "{\"type\":\"contact.created\",\"timestamp\":\"2022-11-03T20:26:10.344522Z\",\"data\":{\"id\":\"1f81eb52-5198-4599-803e-771906343485\"}}"
	fixedVectorID        = "msg_2KWPBgLlAfxdpx2AI54pPJ85f4W"
	fixedVectorSignature = "v1,bHcdokGpKSvv+rPc25y1T9BMlil9GlOBHYzm/w8qjl0="

	selectorMismatchReason        = "selector_mismatch"
	unsupportedMultiReplicaReason = "unsupported_multi_replica"
	maxEvidenceBytes              = 512
	maxWebhookBytes               = 64 * 1024
	composeTestTimeout            = 3 * time.Second
)

// TestComposeFlow_SignedAlertAndDirectProbeRestartOneReplicaOnce verifies the accepted Compose recovery boundary.
func TestComposeFlow_SignedAlertAndDirectProbeRestartOneReplicaOnce(t *testing.T) {
	flow := newComposeFlow(t, []docker.Container{composeContainer("container-web", "web")})
	ctx := testContext(t)
	body := flow.alertBody(t, "external-alert-1", contract.StateUnhealthy)
	headers := flow.sign(t, flow.currentSigner, "msg-compose-accepted", body, flow.clock.Now())

	normalized, err := flow.ingress.Accept(ctx, headers, body)
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	candidate, err := flow.correlator.Ingest(correlator.Signal{
		Source:          normalized.Source,
		ExternalAlertID: normalized.ExternalAlertID,
		Severity:        contract.SeverityCritical,
		Observation:     normalized.Observation,
	})
	if err != nil || candidate.Phase != correlator.PhaseCandidate {
		t.Fatalf("Ingest(alert) = %#v, %v, want candidate", candidate, err)
	}

	direct := flow.observeOnce(t, ctx)
	confirmed, err := flow.correlator.Ingest(correlator.Signal{Source: "observer", Severity: contract.SeverityWarning, Observation: direct})
	if err != nil || confirmed.Phase != correlator.PhaseConfirmed {
		t.Fatalf("Ingest(direct) = %#v, %v, want confirmed", confirmed, err)
	}
	if confirmed.Incident.IncidentID != candidate.Incident.IncidentID || confirmed.Incident.DedupeKey != candidate.Incident.DedupeKey || flow.bucketCount(t, store.BucketIncidents) != 1 {
		t.Fatalf("confirmed incident = %#v, candidate = %#v, incident count = %d, want one deduplicated incident", confirmed.Incident, candidate.Incident, flow.bucketCount(t, store.BucketIncidents))
	}
	if _, err := flow.lifecycle.Publish(ctx, lifecycle.Input{
		EventID:    lifecycle.StableEventID(contract.LifecycleIncidentConfirmed, confirmed.Incident.IncidentID, "alert-direct"),
		EventType:  contract.LifecycleIncidentConfirmed,
		IncidentID: confirmed.Incident.IncidentID,
		ReasonCode: "alert_direct_confirmed",
		OccurredAt: flow.clock.Now(),
	}); err != nil {
		t.Fatalf("Publish(incident.confirmed) error = %v", err)
	}

	request := flow.recoveryRequest(confirmed.Incident.IncidentID, "compose-recovery-1")
	result, err := flow.coordinator.Submit(ctx, request)
	if err != nil || result.Outcome != recovery.OutcomeStabilizing {
		t.Fatalf("Submit() = %#v, %v, want stabilizing", result, err)
	}
	action := flow.source.snapshot.Runbooks[0].Runbook.TypedActions[0]
	if action.ActionType != contract.ActionDockerComposeServiceRestart || action.TargetSelector != flow.target.Selector {
		t.Fatalf("typed action = %#v, want exact Compose service restart", action)
	}
	if got := flow.dockerClient.restartedIDs(); len(got) != 1 || got[0] != "container-web" {
		t.Fatalf("restarted container IDs = %#v, want [container-web]", got)
	}

	duplicate, err := flow.coordinator.Submit(ctx, request)
	if err != nil || !duplicate.Duplicate || duplicate.Command.CommandID != result.Command.CommandID {
		t.Fatalf("Submit(duplicate) = %#v, %v, want original command duplicate", duplicate, err)
	}
	if _, err := flow.ingress.Accept(ctx, headers, body); !errors.Is(err, alert.ErrReplay) {
		t.Fatalf("Accept(replay) error = %v, want %v", err, alert.ErrReplay)
	}
	flow.assertOnlyOneSafeRestart(t)
}

// TestComposeFlow_UnsafeSelectorsNotifyAndAuditWithoutDockerMutation verifies every unsupported Compose shape fails closed.
func TestComposeFlow_UnsafeSelectorsNotifyAndAuditWithoutDockerMutation(t *testing.T) {
	for _, test := range []struct {
		name       string
		containers []docker.Container
		reason     string
	}{
		{name: "zero replicas", reason: unsupportedMultiReplicaReason},
		{name: "two replicas", containers: composeReplicas(2), reason: unsupportedMultiReplicaReason},
		{name: "three replicas", containers: composeReplicas(3), reason: unsupportedMultiReplicaReason},
		{name: "missing label", containers: []docker.Container{{ID: "container-web", Running: true, Health: "unhealthy", Labels: map[string]string{}}}, reason: selectorMismatchReason},
		{name: "selector ambiguity", containers: []docker.Container{{ID: "", Running: true, Health: "unhealthy", Labels: map[string]string{composeServiceLabel: "web"}}}, reason: selectorMismatchReason},
	} {
		t.Run(test.name, func(t *testing.T) {
			flow := newComposeFlow(t, test.containers)
			ctx := testContext(t)
			request := flow.recoveryRequest("incident-unsafe", "unsafe-"+strings.ReplaceAll(test.name, " ", "-"))

			result, err := flow.coordinator.Submit(ctx, request)
			if !errors.Is(err, docker.ErrAmbiguousTarget) || result.Outcome != recovery.OutcomeDenied {
				t.Fatalf("Submit() = %#v, %v, want denied ambiguous target", result, err)
			}
			flow.recordRejectedRecovery(t, ctx, result.Command, request.IdempotencyKey, test.reason)

			if !flow.hasLifecycleReason(t, result.Command.IncidentID, test.reason) {
				t.Fatalf("lifecycle events do not contain reason %q", test.reason)
			}
			if !flow.hasAuditReason(t, result.Command.CommandID, test.reason) {
				t.Fatalf("audit events do not contain command %q reason %q", result.Command.CommandID, test.reason)
			}
			if flow.dockerClient.restartCount() != 0 || flow.dockerClient.forbiddenCount() != 0 {
				t.Fatalf("Docker mutations = restart:%d forbidden:%d, want zero", flow.dockerClient.restartCount(), flow.dockerClient.forbiddenCount())
			}
		})
	}
}

// TestComposeFlow_RejectedAndReverseOrderEventsNeverRecover verifies unsafe ingress and out-of-order recovery input cannot reach Docker mutation.
func TestComposeFlow_RejectedAndReverseOrderEventsNeverRecover(t *testing.T) {
	for _, test := range []struct {
		name   string
		accept func(*testing.T, *composeFlow, context.Context) error
	}{
		{
			name: "invalid signature",
			accept: func(t *testing.T, flow *composeFlow, ctx context.Context) error {
				body := flow.alertBody(t, "invalid-signature", contract.StateUnhealthy)
				headers := flow.sign(t, flow.currentSigner, "msg-invalid-signature", body, flow.clock.Now())
				body = append(append([]byte(nil), body...), ' ')
				_, err := flow.ingress.Accept(ctx, headers, body)
				return err
			},
		},
		{
			name: "expired signature",
			accept: func(t *testing.T, flow *composeFlow, ctx context.Context) error {
				body := flow.alertBody(t, "expired", contract.StateUnhealthy)
				headers := flow.sign(t, flow.currentSigner, "msg-expired", body, flow.clock.Now().Add(-webhook.DefaultTolerance-time.Second))
				_, err := flow.ingress.Accept(ctx, headers, body)
				return err
			},
		},
		{
			name: "malformed payload",
			accept: func(t *testing.T, flow *composeFlow, ctx context.Context) error {
				body := []byte("{")
				headers := flow.sign(t, flow.currentSigner, "msg-malformed", body, flow.clock.Now())
				_, err := flow.ingress.Accept(ctx, headers, body)
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			flow := newComposeFlow(t, []docker.Container{composeContainer("container-web", "web")})
			if err := test.accept(t, flow, testContext(t)); err == nil {
				t.Fatal("Accept() error = nil, want rejection")
			}
			if flow.bucketCount(t, store.BucketCommandJournal) != 0 || flow.dockerClient.restartCount() != 0 {
				t.Fatalf("command journal = %d, restarts = %d, want no recovery", flow.bucketCount(t, store.BucketCommandJournal), flow.dockerClient.restartCount())
			}
		})
	}

	flow := newComposeFlow(t, []docker.Container{composeContainer("container-web", "web")})
	ctx := testContext(t)
	body := flow.alertBody(t, "reverse-order", contract.StateUnhealthy)
	headers := flow.sign(t, flow.currentSigner, "msg-reverse-order", body, flow.clock.Now())
	normalized, err := flow.ingress.Accept(ctx, headers, body)
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	candidate, err := flow.correlator.Ingest(correlator.Signal{Source: normalized.Source, ExternalAlertID: normalized.ExternalAlertID, Severity: contract.SeverityWarning, Observation: normalized.Observation})
	if err != nil || candidate.Phase != correlator.PhaseCandidate {
		t.Fatalf("Ingest(alert) = %#v, %v, want candidate", candidate, err)
	}
	reverseRecovery := normalized.Observation
	reverseRecovery.ObservationID = "observation-recovery-before-confirmation"
	reverseRecovery.ObservedAt = flow.clock.Now().Add(time.Second)
	reverseRecovery.NormalizedState = contract.StateHealthy
	closed, err := flow.correlator.Ingest(correlator.Signal{Source: "observer", Severity: contract.SeverityWarning, Observation: reverseRecovery})
	if err != nil || closed.Phase != correlator.PhaseTerminal || closed.Incident.State != contract.IncidentClosed {
		t.Fatalf("Ingest(reverse recovery) = %#v, %v, want terminal closed candidate", closed, err)
	}
	afterReverse, err := flow.correlator.Ingest(correlator.Signal{Source: "observer", Severity: contract.SeverityWarning, Observation: flow.observeOnce(t, ctx)})
	if err != nil || afterReverse.Phase != correlator.PhaseTerminal || afterReverse.Incident.IncidentID != candidate.Incident.IncidentID {
		t.Fatalf("Ingest(after reverse recovery) = %#v, %v, want same terminal incident", afterReverse, err)
	}
	if flow.bucketCount(t, store.BucketCommandJournal) != 0 || flow.dockerClient.restartCount() != 0 {
		t.Fatalf("reverse-order command journal = %d, restarts = %d, want no recovery", flow.bucketCount(t, store.BucketCommandJournal), flow.dockerClient.restartCount())
	}
}

// TestComposeFlow_StandardWebhookVectorRotationAndPersistedReplay verifies the signed boundary before recovery state exists.
func TestComposeFlow_StandardWebhookVectorRotationAndPersistedReplay(t *testing.T) {
	vectorKeyring, err := webhook.NewKeyring(currentSecret)
	if err != nil {
		t.Fatalf("NewKeyring(vector) error = %v", err)
	}
	if err := vectorKeyring.Verify(webhook.Headers{
		ID:        fixedVectorID,
		Timestamp: "1674087231",
		Signature: fixedVectorSignature,
	}, []byte(fixedVectorBody), time.Unix(1674087231, 0).UTC()); err != nil {
		t.Fatalf("Verify(fixed vector) error = %v", err)
	}

	flow := newComposeFlow(t, []docker.Container{composeContainer("container-web", "web")})
	ctx := testContext(t)
	body := flow.alertBody(t, "rotation", contract.StateUnhealthy)
	for _, signer := range []struct {
		name string
		key  *webhook.Keyring
	}{
		{name: "current", key: flow.currentSigner},
		{name: "previous", key: flow.previousSigner},
	} {
		headers := flow.sign(t, signer.key, "msg-rotation-"+signer.name, body, flow.clock.Now())
		if _, err := flow.ingress.Accept(ctx, headers, body); err != nil {
			t.Fatalf("Accept(%s secret) error = %v", signer.name, err)
		}
	}
	rotationHeaders := flow.sign(t, flow.keyring, "msg-outbound-rotation", body, flow.clock.Now())
	if strings.Count(rotationHeaders.Signature, webhook.SignatureVersionV1+",") != 2 {
		t.Fatalf("rotation signature = %q, want current and previous signatures", rotationHeaders.Signature)
	}
	if flow.dockerClient.restartCount() != 0 || flow.bucketCount(t, store.BucketCommandJournal) != 0 {
		t.Fatal("signature verification mutated Compose recovery state")
	}

	verifyPersistedReplayBeforeRecovery(t)
}

type composeFlow struct {
	state          *store.Store
	clock          *composeClock
	target         contract.ServiceTarget
	dockerClient   *recordingDockerClient
	scheduler      *observer.Scheduler
	correlator     *correlator.Correlator
	coordinator    *recovery.Coordinator
	lifecycle      *lifecycle.Publisher
	ingress        *alert.Ingress
	keyring        *webhook.Keyring
	currentSigner  *webhook.Keyring
	previousSigner *webhook.Keyring
	ids            func(string) func() (string, error)
	source         *composeStateSource
}

func newComposeFlow(t *testing.T, containers []docker.Container) *composeFlow {
	t.Helper()
	clock := &composeClock{now: time.Date(2026, time.July, 22, 1, 0, 0, 0, time.UTC)}
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
	targetValue, snapshot, input := composePolicy(clock.Now())
	registry := newRegistry(t, state, clock, ids, targetValue)
	if _, err := registry.Register(target.Registration{Target: targetValue, ActorIdentity: "operator-1", RequestID: "register-compose", ReasonCode: "onboarding"}); err != nil {
		t.Fatalf("register target: %v", err)
	}

	collector, err := evidence.NewCollector(evidence.Options{
		AllowedFields: []string{"message"},
		MaxLines:      8,
		MaxBytes:      maxEvidenceBytes,
		Retention:     time.Hour,
		Clock:         clock.Now,
		NewEvidenceID: ids("evidence"),
	})
	if err != nil {
		t.Fatalf("create evidence collector: %v", err)
	}
	dockerClient := &recordingDockerClient{containers: cloneContainers(containers)}
	adapter, err := docker.NewAdapter(docker.Options{Client: dockerClient, Evidence: collector, Clock: clock, MaxLogBytes: maxEvidenceBytes, Timeout: time.Second})
	if err != nil {
		t.Fatalf("create Docker adapter: %v", err)
	}
	scheduler, err := observer.NewScheduler(observer.Options{Targets: registry, Probe: adapter, Clock: clock, NewObservationID: ids("observation")})
	if err != nil {
		t.Fatalf("create observer scheduler: %v", err)
	}
	incidentCorrelator, err := correlator.New(correlator.Options{State: state, NewIncidentID: ids("incident"), DedupeWindow: time.Minute})
	if err != nil {
		t.Fatalf("create correlator: %v", err)
	}

	keyring, currentSigner, previousSigner := newKeyrings(t)
	lifecycleSource, err := lifecycle.NewSource(state)
	if err != nil {
		t.Fatalf("create lifecycle source: %v", err)
	}
	dispatcher, err := delivery.New(delivery.Options{
		State:           state,
		Client:          &http.Client{},
		Payloads:        delivery.PayloadSources{contract.DeliveryPayloadLifecycleEvent: lifecycleSource},
		Keyring:         keyring,
		Clock:           clock,
		NewDeliveryID:   ids("delivery"),
		NewWebhookID:    ids("webhook"),
		NewAuditEventID: ids("delivery-audit"),
		Destinations:    map[string]string{"operations": "https://example.test/webhooks"},
		MaxQueueItems:   32,
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
	source := &composeStateSource{target: targetValue, snapshot: snapshot, input: input}
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
	ingress := newIngress(t, state, registry, keyring, clock, ids)

	return &composeFlow{
		state:          state,
		clock:          clock,
		target:         targetValue,
		dockerClient:   dockerClient,
		scheduler:      scheduler,
		correlator:     incidentCorrelator,
		coordinator:    coordinator,
		lifecycle:      lifecyclePublisher,
		ingress:        ingress,
		keyring:        keyring,
		currentSigner:  currentSigner,
		previousSigner: previousSigner,
		ids:            ids,
		source:         source,
	}
}

func (f *composeFlow) alertBody(t *testing.T, externalAlertID string, state contract.NormalizedState) []byte {
	t.Helper()
	return marshalAlert(t, f.clock.Now(), externalAlertID, state)
}

func (f *composeFlow) sign(t *testing.T, signer *webhook.Keyring, id string, body []byte, at time.Time) webhook.Headers {
	t.Helper()
	headers, err := signer.Sign(id, at, body)
	if err != nil {
		t.Fatalf("Sign(%q) error = %v", id, err)
	}
	return headers
}

func (f *composeFlow) observeOnce(t *testing.T, ctx context.Context) contract.HealthObservation {
	t.Helper()
	observations, err := f.scheduler.RunCycle(ctx)
	if err != nil || len(observations) != 1 {
		t.Fatalf("RunCycle() observations = %#v, error = %v, want one observation", observations, err)
	}
	if observations[0].NormalizedState != contract.StateUnhealthy {
		t.Fatalf("observation state = %q, want %q", observations[0].NormalizedState, contract.StateUnhealthy)
	}
	return observations[0]
}

func (f *composeFlow) recoveryRequest(incidentID, idempotencyKey string) recovery.Request {
	return recovery.Request{
		IncidentID:     incidentID,
		Target:         f.target,
		PolicySnapshot: f.source.snapshot,
		PolicyInput:    f.source.input,
		ExpiresAt:      f.clock.Now().Add(5 * time.Minute),
		IdempotencyKey: idempotencyKey,
	}
}

func (f *composeFlow) recordRejectedRecovery(t *testing.T, ctx context.Context, command contract.RecoveryCommand, idempotencyKey, reason string) {
	t.Helper()
	if err := f.lifecycle.PublishPolicyDenied(ctx, command.IncidentID, idempotencyKey, reason); err != nil {
		t.Fatalf("PublishPolicyDenied(%q) error = %v", reason, err)
	}
	eventID, err := f.ids("recovery-audit")()
	if err != nil {
		t.Fatalf("create recovery audit ID: %v", err)
	}
	err = f.state.Update(func(tx *store.Tx) error {
		_, err := audit.Append(tx, contract.AuditEvent{
			SchemaVersion: contract.SchemaVersionV1,
			EventID:       eventID,
			AggregateType: "recovery_command",
			AggregateID:   command.CommandID,
			ActorIdentity: "pulse-agent",
			Action:        "recovery.reject",
			Result:        "rejected",
			ReasonCode:    reason,
			OccurredAt:    f.clock.Now(),
		}, nil)
		return err
	})
	if err != nil {
		t.Fatalf("append recovery audit: %v", err)
	}
}

func (f *composeFlow) hasLifecycleReason(t *testing.T, incidentID, reason string) bool {
	t.Helper()
	eventID := ""
	if err := f.state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketLifecycleEvents, func(_ string, document []byte) error {
			var event contract.LifecycleEvent
			if err := json.Unmarshal(document, &event); err != nil {
				return err
			}
			if event.EventType == contract.LifecyclePolicyDenied && event.IncidentID == incidentID && event.ReasonCode == reason {
				eventID = event.EventID
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("scan lifecycle events: %v", err)
	}
	if eventID == "" {
		return false
	}
	found := false
	if err := f.state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketDeliveryQueue, func(_ string, document []byte) error {
			var item contract.DeliveryQueueItem
			if err := json.Unmarshal(document, &item); err != nil {
				return err
			}
			if item.PayloadType == contract.DeliveryPayloadLifecycleEvent && item.PayloadRef == eventID && item.State == contract.DeliveryPending {
				found = true
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("scan delivery queue: %v", err)
	}
	return found
}

func (f *composeFlow) hasAuditReason(t *testing.T, commandID, reason string) bool {
	t.Helper()
	found := false
	if err := f.state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketAudit, func(_ string, document []byte) error {
			var event contract.AuditEvent
			if err := json.Unmarshal(document, &event); err != nil {
				return err
			}
			if event.AggregateType == "recovery_command" && event.AggregateID == commandID && event.Result == "rejected" && event.ReasonCode == reason {
				found = true
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("scan audit events: %v", err)
	}
	return found
}

func (f *composeFlow) bucketCount(t *testing.T, bucket store.Bucket) int {
	t.Helper()
	return bucketCount(t, f.state, bucket)
}

func (f *composeFlow) assertOnlyOneSafeRestart(t *testing.T) {
	t.Helper()
	if f.dockerClient.restartCount() != 1 || f.dockerClient.forbiddenCount() != 0 {
		t.Fatalf("Docker mutations = restart:%d forbidden:%d, want one restart and no forbidden calls", f.dockerClient.restartCount(), f.dockerClient.forbiddenCount())
	}
	for _, operation := range f.dockerClient.operationKinds() {
		switch operation {
		case "negotiate", "list_by_label", "restart":
		default:
			t.Fatalf("Docker operation %q is outside the bounded Compose recovery API", operation)
		}
	}
}

type composeAlert struct {
	SchemaVersion   string                   `json:"schema_version"`
	Source          string                   `json:"source"`
	ExternalAlertID string                   `json:"external_alert_id"`
	TargetID        string                   `json:"target_id"`
	RuleID          string                   `json:"rule_id"`
	State           contract.NormalizedState `json:"state"`
	Severity        contract.Severity        `json:"severity"`
	ObservedAt      time.Time                `json:"observed_at"`
	Values          map[string]float64       `json:"values"`
	EvidenceRefs    []string                 `json:"evidence_refs"`
}

func marshalAlert(t *testing.T, now time.Time, externalAlertID string, state contract.NormalizedState) []byte {
	t.Helper()
	document, err := json.Marshal(composeAlert{
		SchemaVersion:   contract.SchemaVersionV1,
		Source:          "monitor",
		ExternalAlertID: externalAlertID,
		TargetID:        "web",
		RuleID:          "availability",
		State:           state,
		Severity:        contract.SeverityCritical,
		ObservedAt:      now,
		Values:          map[string]float64{"availability": 0},
		EvidenceRefs:    []string{},
	})
	if err != nil {
		t.Fatalf("marshal alert: %v", err)
	}
	return document
}

func newIngress(t *testing.T, state *store.Store, registry *target.Registry, keyring *webhook.Keyring, clock *composeClock, ids func(string) func() (string, error)) *alert.Ingress {
	t.Helper()
	ingress, err := alert.NewIngress(alert.Options{
		State:            state,
		Targets:          registry,
		Keyring:          keyring,
		Clock:            clock.Now,
		NewObservationID: ids("alert-observation"),
		NewAuditEventID:  ids("alert-audit"),
		MaxBodyBytes:     maxWebhookBytes,
		Timeout:          time.Second,
		Retention:        time.Hour,
	})
	if err != nil {
		t.Fatalf("create alert ingress: %v", err)
	}
	return ingress
}

func newRegistry(t *testing.T, state *store.Store, clock *composeClock, ids func(string) func() (string, error), targetValue contract.ServiceTarget) *target.Registry {
	t.Helper()
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
	return registry
}

func newKeyrings(t *testing.T) (combined, current, previous *webhook.Keyring) {
	t.Helper()
	var err error
	combined, err = webhook.NewKeyring(currentSecret, previousSecret)
	if err != nil {
		t.Fatalf("create rotation keyring: %v", err)
	}
	current, err = webhook.NewKeyring(currentSecret)
	if err != nil {
		t.Fatalf("create current keyring: %v", err)
	}
	previous, err = webhook.NewKeyring(previousSecret)
	if err != nil {
		t.Fatalf("create previous keyring: %v", err)
	}
	return combined, current, previous
}

func verifyPersistedReplayBeforeRecovery(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "replay.db")
	clock := &composeClock{now: time.Date(2026, time.July, 22, 2, 0, 0, 0, time.UTC)}
	ids := newIDGenerator()
	targetValue, _, _ := composePolicy(clock.Now())
	keyring, currentSigner, _ := newKeyrings(t)
	first, err := store.Open(store.Options{Path: path, LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("open first replay state: %v", err)
	}
	registry := newRegistry(t, first, clock, ids, targetValue)
	if _, err := registry.Register(target.Registration{Target: targetValue, ActorIdentity: "operator-1", RequestID: "register-replay", ReasonCode: "onboarding"}); err != nil {
		_ = first.Close()
		t.Fatalf("register replay target: %v", err)
	}
	ingress := newIngress(t, first, registry, keyring, clock, ids)
	body := marshalAlert(t, clock.Now(), "persisted-replay", contract.StateUnhealthy)
	headers, err := currentSigner.Sign("msg-persisted-replay", clock.Now(), body)
	if err != nil {
		_ = first.Close()
		t.Fatalf("sign persisted replay alert: %v", err)
	}
	if _, err := ingress.Accept(context.Background(), headers, body); err != nil {
		_ = first.Close()
		t.Fatalf("Accept(first) error = %v", err)
	}
	if bucketCount(t, first, store.BucketCommandJournal) != 0 {
		_ = first.Close()
		t.Fatal("first ingress acceptance created recovery state")
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first replay state: %v", err)
	}

	reopened, err := store.Open(store.Options{Path: path, LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("reopen replay state: %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close replay state: %v", err)
		}
	})
	restartedRegistry := newRegistry(t, reopened, clock, ids, targetValue)
	restartedIngress := newIngress(t, reopened, restartedRegistry, keyring, clock, ids)
	dockerClient := &recordingDockerClient{}
	if _, err := restartedIngress.Accept(context.Background(), headers, body); !errors.Is(err, alert.ErrReplay) {
		t.Fatalf("Accept(persisted replay) error = %v, want %v", err, alert.ErrReplay)
	}
	if bucketCount(t, reopened, store.BucketCommandJournal) != 0 || dockerClient.restartCount() != 0 || dockerClient.forbiddenCount() != 0 {
		t.Fatalf("persisted replay command journal = %d, restart = %d, forbidden = %d, want no recovery mutation", bucketCount(t, reopened, store.BucketCommandJournal), dockerClient.restartCount(), dockerClient.forbiddenCount())
	}
}

func bucketCount(t *testing.T, state *store.Store, bucket store.Bucket) int {
	t.Helper()
	count := 0
	if err := state.View(func(tx *store.Tx) error {
		return tx.ForEach(bucket, func(_ string, _ []byte) error {
			count++
			return nil
		})
	}); err != nil {
		t.Fatalf("count bucket %q: %v", bucket, err)
	}
	return count
}

func composePolicy(now time.Time) (contract.ServiceTarget, policy.Snapshot, policy.Input) {
	targetValue := contract.ServiceTarget{
		SchemaVersion: contract.SchemaVersionV1,
		TargetID:      "web",
		AdapterType:   docker.AdapterType,
		Selector:      "compose_service:web",
		ProbeRules: []contract.ProbeRule{{
			RuleID:              "availability",
			SignalType:          "availability",
			Interval:            contract.NewDuration(20 * time.Second),
			Timeout:             contract.NewDuration(time.Second),
			Threshold:           0.9,
			ConsecutiveFailures: 1,
			RecoverySamples:     1,
			SLOWindow:           contract.NewDuration(time.Minute),
			Severity:            contract.SeverityWarning,
		}},
		EvidencePolicy: contract.EvidencePolicy{RedactionProfile: "default", MaxBytes: maxEvidenceBytes},
		StabilizationPolicy: contract.StabilizationPolicy{
			RecoverySamples: 1,
			Window:          contract.NewDuration(20 * time.Second),
		},
		Enabled: true,
	}
	runbook := contract.Runbook{
		SchemaVersion: contract.SchemaVersionV1,
		RunbookID:     "restart-compose-web",
		Digest:        "digest-restart-compose-web",
		AdapterType:   docker.AdapterType,
		TypedActions: []contract.TypedAction{{
			ActionType:     contract.ActionDockerComposeServiceRestart,
			TargetSelector: targetValue.Selector,
			StopTimeout:    contract.NewDuration(time.Second),
		}},
		RiskTier:       contract.RiskLow,
		AutoExecute:    true,
		ApprovalPolicy: contract.ApprovalPolicy{Required: false},
		Preconditions:  []string{"docker_available"},
		RetryPolicy:    contract.RetryPolicy{MaxAttempts: 1},
		StabilizationPolicy: contract.StabilizationPolicy{
			RecoverySamples: 1,
			Window:          contract.NewDuration(20 * time.Second),
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
		RunbookID:              runbook.RunbookID,
		RunbookDigest:          runbook.Digest,
		TargetID:               targetValue.TargetID,
		ActionIndex:            0,
		AnalysisAvailable:      true,
		AnalysisCandidateIDs:   []string{runbook.RunbookID},
		AnalysisConfidence:     []contract.ConfidenceLabel{contract.ConfidenceHigh},
		NotificationSuggestion: contract.NotificationNotify,
		Preconditions:          map[string]bool{"docker_available": true},
		Now:                    now,
	}
	return targetValue, snapshot, input
}

type composeClock struct{ now time.Time }

// Now returns the deterministic test time.
func (c *composeClock) Now() time.Time {
	return c.now
}

type composeStateSource struct {
	target   contract.ServiceTarget
	snapshot policy.Snapshot
	input    policy.Input
}

// Load returns the latest immutable Compose execution state.
func (s *composeStateSource) Load(context.Context, contract.RecoveryCommand) (recovery.ExecutionState, error) {
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
	return recovery.ExecutionState{Target: targetValue, PolicySnapshot: snapshot, PolicyInput: input}, nil
}

type dockerOperation struct {
	kind       string
	identifier string
}

type recordingDockerClient struct {
	mu         sync.Mutex
	containers []docker.Container
	operations []dockerOperation
	restarted  []string
}

// NegotiateAPIVersion records bounded Docker API negotiation.
func (c *recordingDockerClient) NegotiateAPIVersion(context.Context) error {
	c.record("negotiate", "")
	return nil
}

// Inspect records an exact-container lookup; Compose flows do not use it.
func (c *recordingDockerClient) Inspect(context.Context, string) (docker.Container, error) {
	c.record("inspect", "")
	return docker.Container{}, errors.New("container not found")
}

// ListByLabel returns the deterministic Compose replica set.
func (c *recordingDockerClient) ListByLabel(_ context.Context, label, value string) ([]docker.Container, error) {
	c.record("list_by_label", label+"="+value)
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneContainers(c.containers), nil
}

// Logs records bounded log access and returns synthetic content.
func (c *recordingDockerClient) Logs(context.Context, string) (io.ReadCloser, error) {
	c.record("logs", "")
	return io.NopCloser(strings.NewReader("compose service unavailable")), nil
}

// Restart records one SDK restart and changes only the selected replica to healthy.
func (c *recordingDockerClient) Restart(_ context.Context, identifier string, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.operations = append(c.operations, dockerOperation{kind: "restart", identifier: identifier})
	for index, container := range c.containers {
		if container.ID != identifier {
			continue
		}
		c.restarted = append(c.restarted, identifier)
		container.Health = "healthy"
		c.containers[index] = container
		return nil
	}
	return errors.New("container not found")
}

func (c *recordingDockerClient) record(kind, identifier string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.operations = append(c.operations, dockerOperation{kind: kind, identifier: identifier})
}

func (c *recordingDockerClient) restartCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.restarted)
}

func (c *recordingDockerClient) restartedIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.restarted...)
}

func (c *recordingDockerClient) operationKinds() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	kinds := make([]string, 0, len(c.operations))
	for _, operation := range c.operations {
		kinds = append(kinds, operation.kind)
	}
	return kinds
}

func (c *recordingDockerClient) forbiddenCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for _, operation := range c.operations {
		switch operation.kind {
		case "rolling_restart", "scale", "compose_down", "down", "remove", "rm", "restart_healthy_replicas":
			count++
		}
	}
	return count
}

func composeContainer(id, service string) docker.Container {
	return docker.Container{
		ID:      id,
		Running: true,
		Health:  "unhealthy",
		Labels:  map[string]string{composeServiceLabel: service},
	}
}

func composeReplicas(count int) []docker.Container {
	containers := make([]docker.Container, 0, count)
	for index := range count {
		containers = append(containers, composeContainer(fmt.Sprintf("container-web-%d", index+1), "web"))
	}
	return containers
}

func cloneContainers(containers []docker.Container) []docker.Container {
	cloned := make([]docker.Container, len(containers))
	for index, container := range containers {
		cloned[index] = container
		cloned[index].Labels = make(map[string]string, len(container.Labels))
		for key, value := range container.Labels {
			cloned[index].Labels[key] = value
		}
	}
	return cloned
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
	ctx, cancel := context.WithTimeout(context.Background(), composeTestTimeout)
	t.Cleanup(cancel)
	return ctx
}
