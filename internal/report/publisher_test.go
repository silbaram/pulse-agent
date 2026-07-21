package report

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/delivery"
	"pulse-agent/internal/lifecycle"
	"pulse-agent/internal/store"
	"pulse-agent/internal/telemetry"
	"pulse-agent/internal/webhook"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

const webhookSecret = "whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="

func TestPublisher_PublishesCompleteClosedReportAndTerminalEvent(t *testing.T) {
	now := testNow()
	publisher, reportSource, _, dispatcher, client := newPublisher(t, now, acceptClient{}, 8, 2)
	result, err := publisher.PublishTerminal(context.Background(), completeInput(now, contract.IncidentClosed))
	if err != nil || result.Duplicate {
		t.Fatalf("PublishTerminal() = %#v, %v, want complete terminal payloads", result, err)
	}
	if result.ReportQueueItem.PayloadType != contract.DeliveryPayloadIncidentReport || result.LifecycleQueueItem.PayloadType != contract.DeliveryPayloadLifecycleEvent || result.ReportQueueItem.WebhookID == result.LifecycleQueueItem.WebhookID {
		t.Fatalf("queue items = %#v, %#v, want distinct report and lifecycle webhook IDs", result.ReportQueueItem, result.LifecycleQueueItem)
	}
	if result.Report.DeliveryStatus != contract.DeliveryPending || len(result.Report.Hypotheses) != 1 || len(result.Report.Actions) != 1 || len(result.Report.Approvals) != 1 || result.Report.VerificationResult != "stabilized" {
		t.Fatalf("report = %#v, want complete pending report", result.Report)
	}
	body, err := reportSource.Load(context.Background(), contract.DeliveryPayloadIncidentReport, result.Report.ReportID)
	if err != nil || strings.Contains(string(body), "raw-secret") || !strings.Contains(string(body), `"postmortem_draft":"Root cause and verification summary."`) {
		t.Fatalf("Load(report) = %s, %v, want durable secret-free report", body, err)
	}
	deliveries, err := dispatcher.DeliverDue(context.Background())
	if err != nil || len(deliveries) != 2 || !deliveries[0].Sent || !deliveries[1].Sent || len(client.bodies) != 2 {
		t.Fatalf("DeliverDue() = %#v, %v; bodies=%d, want both terminal payloads sent", deliveries, err, len(client.bodies))
	}
}

func TestPublisher_PublishesFailedReportWithoutAnalysisOrActionAndKeepsFailureSeparate(t *testing.T) {
	now := testNow()
	publisher, reportSource, _, dispatcher, _ := newPublisher(t, now, rejectClient{}, 8, 1)
	input := completeInput(now, contract.IncidentFailed)
	input.Analysis = nil
	input.AnalysisUnavailable = true
	input.Actions = nil
	input.ApprovalIDs = nil
	input.PreventionRecommendations = nil
	input.PostmortemDraft = ""
	input.RunbookImprovementSuggestions = nil
	result, err := publisher.PublishTerminal(context.Background(), input)
	if err != nil || result.Report.VerificationResult != "stabilization_failed" || len(result.Report.Hypotheses) != 1 || len(result.Report.Actions) != 0 || len(result.Report.PreventionRecommendations) != 1 || len(result.Report.RunbookImprovementSuggestions) != 1 {
		t.Fatalf("PublishTerminal(no analysis/action) = %#v, %v, want complete fallback report", result, err)
	}
	deliveries, err := dispatcher.DeliverDue(context.Background())
	if err != nil || len(deliveries) != 2 || deliveries[0].Item.State != contract.DeliveryFailed || deliveries[1].Item.State != contract.DeliveryFailed {
		t.Fatalf("DeliverDue() = %#v, %v, want independently failed terminal deliveries", deliveries, err)
	}
	body, err := reportSource.Load(context.Background(), contract.DeliveryPayloadIncidentReport, result.Report.ReportID)
	if err != nil {
		t.Fatalf("Load(report after delivery failure) error = %v", err)
	}
	var persisted contract.IncidentReport
	if err := json.Unmarshal(body, &persisted); err != nil || persisted.DeliveryStatus != contract.DeliveryPending || persisted.VerificationResult != "stabilization_failed" {
		t.Fatalf("persisted report = %#v, %v, want unchanged terminal report", persisted, err)
	}
	if count := auditCount(t, publisher.state); count != 2 {
		t.Fatalf("delivery terminal audit records = %d, want 2", count)
	}
}

func TestPublisher_DuplicateTerminalTransitionUsesOnePairOfDeliveries(t *testing.T) {
	now := testNow()
	publisher, _, _, dispatcher, _ := newPublisher(t, now, acceptClient{}, 8, 2)
	input := completeInput(now, contract.IncidentClosed)
	first, err := publisher.PublishTerminal(context.Background(), input)
	if err != nil || first.Duplicate {
		t.Fatalf("first PublishTerminal() = %#v, %v", first, err)
	}
	second, err := publisher.PublishTerminal(context.Background(), input)
	if err != nil || !second.Duplicate || second.ReportQueueItem != (contract.DeliveryQueueItem{}) || second.LifecycleQueueItem != (contract.DeliveryQueueItem{}) {
		t.Fatalf("duplicate PublishTerminal() = %#v, %v, want no new queue items", second, err)
	}
	deliveries, err := dispatcher.DeliverDue(context.Background())
	if err != nil || len(deliveries) != 2 {
		t.Fatalf("DeliverDue() = %#v, %v, want one report and one lifecycle delivery", deliveries, err)
	}
}

func TestPublisher_RejectsSecretBearingTerminalInputWithoutPersistingPayload(t *testing.T) {
	now := testNow()
	publisher, reportSource, _, _, _ := newPublisher(t, now, acceptClient{}, 8, 2)
	input := completeInput(now, contract.IncidentClosed)
	input.Analysis.Hypotheses[0].Summary = "authorization: raw-secret"
	result, err := publisher.PublishTerminal(context.Background(), input)
	if !errors.Is(err, ErrInvalidInput) || result.Report.ReportID != "" || result.ReportQueueItem != (contract.DeliveryQueueItem{}) || result.LifecycleQueueItem != (contract.DeliveryQueueItem{}) {
		t.Fatalf("PublishTerminal(secret) = %#v, %v, want ErrInvalidInput", result, err)
	}
	reportID := StableReportID(input.IncidentID, input.TerminalState, input.IdempotencyKey)
	if _, loadErr := reportSource.Load(context.Background(), contract.DeliveryPayloadIncidentReport, reportID); !errors.Is(loadErr, ErrPayloadNotFound) {
		t.Fatalf("Load(rejected report) error = %v, want ErrPayloadNotFound", loadErr)
	}
}

func TestPublisherAndDelivery_EmitBoundedTelemetryWithoutSecretFixture(t *testing.T) {
	now := testNow()
	spanExporter := tracetest.NewInMemoryExporter()
	recorder, err := telemetry.New(telemetry.Options{SpanExporter: spanExporter})
	if err != nil {
		t.Fatalf("telemetry.New() error = %v", err)
	}
	t.Cleanup(func() { _ = recorder.Shutdown(context.Background()) })
	publisher, _, _, dispatcher, _ := newPublisher(t, now, acceptClient{}, 8, 2, recorder)
	input := completeInput(now, contract.IncidentClosed)
	input.IncidentID = "incident-raw-secret"
	input.Analysis.IncidentID = input.IncidentID
	result, err := publisher.PublishTerminal(context.Background(), input)
	if err != nil {
		t.Fatalf("PublishTerminal() error = %v", err)
	}
	if _, err := dispatcher.DeliverDue(context.Background()); err != nil {
		t.Fatalf("DeliverDue() error = %v", err)
	}
	secretInput := completeInput(now, contract.IncidentClosed)
	secretInput.IdempotencyKey = "terminal-secret-fixture"
	secretInput.Analysis.Hypotheses[0].Summary = "token=raw-secret"
	if _, err := publisher.PublishTerminal(context.Background(), secretInput); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("PublishTerminal(secret fixture) error = %v, want %v", err, ErrInvalidInput)
	}
	if err := recorder.ForceFlush(context.Background()); err != nil {
		t.Fatalf("telemetry flush error = %v", err)
	}
	seen := make(map[string]struct{})
	for _, span := range spanExporter.GetSpans() {
		seen[span.Name] = struct{}{}
		for _, value := range span.Attributes {
			if strings.Contains(value.Value.AsString(), "raw-secret") || strings.Contains(value.Value.AsString(), "terminal-secret-fixture") {
				t.Fatalf("telemetry leaked secret fixture: %s %#v", span.Name, span.Attributes)
			}
		}
	}
	for _, name := range []string{"pulse.agent.report.publish", "pulse.agent.delivery.write", "pulse.agent.delivery.deliver"} {
		if _, found := seen[name]; !found {
			t.Fatalf("telemetry spans = %#v, want %q", seen, name)
		}
	}
	if result.Report.ReportID == "" {
		t.Fatal("PublishTerminal() returned an empty report ID")
	}
}

func completeInput(now time.Time, terminalState contract.IncidentState) Input {
	verification := "stabilized"
	if terminalState == contract.IncidentFailed {
		verification = "stabilization_failed"
	}
	return Input{
		IncidentID:     "incident-1",
		TerminalState:  terminalState,
		IdempotencyKey: "terminal-1",
		OccurredAt:     now,
		Analysis: &contract.AnalysisResult{
			SchemaVersion:              contract.SchemaVersionV1,
			IncidentID:                 "incident-1",
			Hypotheses:                 []contract.Hypothesis{{Summary: "Dependency saturation caused elevated latency.", EvidenceRefs: []string{"evidence-1"}}},
			EvidenceRefs:               []string{"evidence-1"},
			ConfidenceLabels:           []contract.ConfidenceLabel{contract.ConfidenceHigh},
			NotificationRecommendation: contract.NotificationNotify,
			CandidateRunbookIDs:        []string{"runbook-1"},
		},
		EvidenceRefs: []string{"evidence-1"},
		Actions: []contract.ReportAction{{
			CommandID:  "command-1",
			ActionType: contract.ActionDockerContainerRestart,
			Result:     "succeeded",
		}},
		ApprovalIDs:                   []string{"approval-1"},
		VerificationResult:            verification,
		PreventionRecommendations:     []string{"Add saturation alert coverage."},
		PostmortemDraft:               "Root cause and verification summary.",
		RunbookImprovementSuggestions: []string{"Document the dependency saturation check."},
	}
}

func newPublisher(t *testing.T, now time.Time, client delivery.HTTPClient, queueLimit, attempts int, recorders ...*telemetry.Recorder) (*Publisher, *Source, *lifecycle.Source, *delivery.Dispatcher, *captureClient) {
	t.Helper()
	if len(recorders) > 1 {
		t.Fatalf("newPublisher() received %d telemetry recorders, want at most 1", len(recorders))
	}
	var recorder *telemetry.Recorder
	if len(recorders) == 1 {
		recorder = recorders[0]
	}
	state, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db"), LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := state.Close(); closeErr != nil {
			t.Errorf("state.Close() error = %v", closeErr)
		}
	})
	reportSource, err := NewSource(state)
	if err != nil {
		t.Fatalf("report NewSource() error = %v", err)
	}
	lifecycleSource, err := lifecycle.NewSource(state)
	if err != nil {
		t.Fatalf("lifecycle NewSource() error = %v", err)
	}
	keyring, err := webhook.NewKeyring(webhookSecret)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	sequence := 0
	nextID := func(prefix string) func() (string, error) {
		return func() (string, error) {
			sequence++
			return prefix + "-" + strconv.Itoa(sequence), nil
		}
	}
	capture := &captureClient{delegate: client}
	clock := testClock{now: now}
	dispatcher, err := delivery.New(delivery.Options{
		State:           state,
		Client:          capture,
		Payloads:        delivery.PayloadSources{contract.DeliveryPayloadIncidentReport: reportSource, contract.DeliveryPayloadLifecycleEvent: lifecycleSource},
		Keyring:         keyring,
		Clock:           clock,
		NewDeliveryID:   nextID("delivery"),
		NewWebhookID:    nextID("webhook"),
		NewAuditEventID: nextID("audit"),
		Destinations:    map[string]string{"operations": "https://example.test/webhooks"},
		MaxQueueItems:   queueLimit,
		MaxAttempts:     attempts,
		InitialBackoff:  time.Second,
		MaxBackoff:      time.Second,
		RequestTimeout:  time.Second,
		MaxPayloadBytes: 64 * 1024,
		Telemetry:       recorder,
	})
	if err != nil {
		t.Fatalf("delivery.New() error = %v", err)
	}
	lifecyclePublisher, err := lifecycle.New(lifecycle.Options{State: state, Queue: dispatcher, DestinationRef: "operations", Clock: clock, DeliveryTTL: time.Hour})
	if err != nil {
		t.Fatalf("lifecycle.New() error = %v", err)
	}
	publisher, err := New(Options{State: state, Queue: dispatcher, Lifecycle: lifecyclePublisher, DestinationRef: "operations", Clock: clock, DeliveryTTL: time.Hour, Telemetry: recorder})
	if err != nil {
		t.Fatalf("report.New() error = %v", err)
	}
	return publisher, reportSource, lifecycleSource, dispatcher, capture
}

type testClock struct{ now time.Time }

func (c testClock) Now() time.Time { return c.now }

type acceptClient struct{}

func (acceptClient) Do(_ *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
}

type rejectClient struct{}

func (rejectClient) Do(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("endpoint disconnected")
}

type captureClient struct {
	delegate delivery.HTTPClient
	bodies   [][]byte
}

func (c *captureClient) Do(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	c.bodies = append(c.bodies, body)
	return c.delegate.Do(request)
}

func auditCount(t *testing.T, state *store.Store) int {
	t.Helper()
	count := 0
	if err := state.View(func(transaction *store.Tx) error {
		return transaction.ForEach(store.BucketAudit, func(_ string, _ []byte) error {
			count++
			return nil
		})
	}); err != nil {
		t.Fatalf("audit count error = %v", err)
	}
	return count
}

func testNow() time.Time { return time.Date(2026, time.July, 21, 9, 0, 0, 0, time.UTC) }
