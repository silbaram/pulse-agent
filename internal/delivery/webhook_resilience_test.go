package delivery_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/delivery"
	"pulse-agent/internal/lifecycle"
	"pulse-agent/internal/report"
	"pulse-agent/internal/store"
	"pulse-agent/internal/webhook"
)

const resilienceWebhookSecret = "whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="

func TestWebhookResilience_DisconnectRestartReconnectPreservesLifecycleAndReport(t *testing.T) {
	now := time.Date(2026, time.July, 22, 0, 0, 0, 0, time.UTC)
	clock := &resilienceClock{now: now}
	client := &reconnectClient{}
	path := filepath.Join(t.TempDir(), "state.db")
	firstState := openResilienceStore(t, path)
	firstClosed := false
	t.Cleanup(func() {
		if !firstClosed {
			if err := firstState.Close(); err != nil {
				t.Errorf("first Store.Close() error = %v", err)
			}
		}
	})

	firstDispatcher, reportPublisher := newResiliencePublishers(t, firstState, clock, client, sequentialResilienceIDs())
	published, err := reportPublisher.PublishTerminal(context.Background(), report.Input{
		IncidentID:                    "incident-webhook-resilience",
		TerminalState:                 contract.IncidentClosed,
		IdempotencyKey:                "terminal-transition-1",
		OccurredAt:                    now,
		AnalysisUnavailable:           true,
		EvidenceRefs:                  []string{"evidence-1"},
		Actions:                       []contract.ReportAction{{CommandID: "command-1", ActionType: contract.ActionDockerContainerRestart, Result: "stabilized"}},
		VerificationResult:            "service healthy",
		PreventionRecommendations:     []string{"Review alert thresholds."},
		PostmortemDraft:               "The registered recovery restored service health.",
		RunbookImprovementSuggestions: []string{"Add a recovery verification note."},
	})
	if err != nil {
		t.Fatalf("PublishTerminal() error = %v", err)
	}
	if published.ReportQueueItem.WebhookID == "" || published.LifecycleQueueItem.WebhookID == "" || published.ReportQueueItem.WebhookID == published.LifecycleQueueItem.WebhookID {
		t.Fatalf("published queue items = %#v, %#v; want distinct stable webhook IDs", published.ReportQueueItem, published.LifecycleQueueItem)
	}

	failed, err := firstDispatcher.DeliverDue(context.Background())
	if err != nil {
		t.Fatalf("disconnected DeliverDue() error = %v", err)
	}
	assertRetryingDeliveries(t, failed, map[string]string{
		published.ReportQueueItem.DeliveryID:    published.ReportQueueItem.WebhookID,
		published.LifecycleQueueItem.DeliveryID: published.LifecycleQueueItem.WebhookID,
	})
	if err := firstState.Close(); err != nil {
		t.Fatalf("first Store.Close() error = %v", err)
	}
	firstClosed = true

	clock.now = now.Add(time.Second)
	client.connected = true
	reopened := openResilienceStore(t, path)
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("reopened Store.Close() error = %v", err)
		}
	})
	restartedDispatcher, restartedLifecycleSource, restartedReportSource := newResilienceDispatcher(t, reopened, clock, client, failingResilienceIDs())

	sent, err := restartedDispatcher.DeliverDue(context.Background())
	if err != nil {
		t.Fatalf("reconnected DeliverDue() error = %v", err)
	}
	assertDeliveredAfterRestart(t, sent, map[string]string{
		published.ReportQueueItem.DeliveryID:    published.ReportQueueItem.WebhookID,
		published.LifecycleQueueItem.DeliveryID: published.LifecycleQueueItem.WebhookID,
	})
	assertWebhookAttempts(t, client.webhookIDs, published.ReportQueueItem.WebhookID, published.LifecycleQueueItem.WebhookID)
	assertPayloadSurvivedRestart(t, restartedReportSource, restartedLifecycleSource, published)
	assertPersistedDeliveries(t, reopened, published.ReportQueueItem.WebhookID, published.LifecycleQueueItem.WebhookID)
}

type resilienceClock struct{ now time.Time }

func (c *resilienceClock) Now() time.Time { return c.now }

type reconnectClient struct {
	connected  bool
	webhookIDs []string
}

func (c *reconnectClient) Do(request *http.Request) (*http.Response, error) {
	c.webhookIDs = append(c.webhookIDs, request.Header.Get(webhook.HeaderID))
	if !c.connected {
		return nil, errors.New("webhook endpoint disconnected")
	}
	return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
}

type resilienceIDs struct {
	delivery func() (string, error)
	webhook  func() (string, error)
	audit    func() (string, error)
}

func sequentialResilienceIDs() resilienceIDs {
	return resilienceIDs{
		delivery: sequenceID("delivery"),
		webhook:  sequenceID("webhook"),
		audit:    sequenceID("audit"),
	}
}

func failingResilienceIDs() resilienceIDs {
	unexpected := func() (string, error) { return "", errors.New("unexpected ID generation during restart delivery") }
	return resilienceIDs{delivery: unexpected, webhook: unexpected, audit: unexpected}
}

func sequenceID(prefix string) func() (string, error) {
	next := 0
	return func() (string, error) {
		next++
		return prefix + "-" + strconv.Itoa(next), nil
	}
}

func openResilienceStore(t *testing.T, path string) *store.Store {
	t.Helper()
	state, err := store.Open(store.Options{Path: path, LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	return state
}

func newResiliencePublishers(t *testing.T, state *store.Store, clock *resilienceClock, client delivery.HTTPClient, ids resilienceIDs) (*delivery.Dispatcher, *report.Publisher) {
	t.Helper()
	dispatcher, _, _ := newResilienceDispatcher(t, state, clock, client, ids)
	lifecyclePublisher, err := lifecycle.New(lifecycle.Options{State: state, Queue: dispatcher, DestinationRef: "operations", Clock: clock, DeliveryTTL: time.Hour})
	if err != nil {
		t.Fatalf("lifecycle.New() error = %v", err)
	}
	reportPublisher, err := report.New(report.Options{State: state, Queue: dispatcher, Lifecycle: lifecyclePublisher, DestinationRef: "operations", Clock: clock, DeliveryTTL: time.Hour})
	if err != nil {
		t.Fatalf("report.New() error = %v", err)
	}
	return dispatcher, reportPublisher
}

func newResilienceDispatcher(t *testing.T, state *store.Store, clock *resilienceClock, client delivery.HTTPClient, ids resilienceIDs) (*delivery.Dispatcher, *lifecycle.Source, *report.Source) {
	t.Helper()
	lifecycleSource, err := lifecycle.NewSource(state)
	if err != nil {
		t.Fatalf("lifecycle.NewSource() error = %v", err)
	}
	reportSource, err := report.NewSource(state)
	if err != nil {
		t.Fatalf("report.NewSource() error = %v", err)
	}
	keyring, err := webhook.NewKeyring(resilienceWebhookSecret)
	if err != nil {
		t.Fatalf("webhook.NewKeyring() error = %v", err)
	}
	dispatcher, err := delivery.New(delivery.Options{
		State:           state,
		Client:          client,
		Payloads:        delivery.PayloadSources{contract.DeliveryPayloadLifecycleEvent: lifecycleSource, contract.DeliveryPayloadIncidentReport: reportSource},
		Keyring:         keyring,
		Clock:           clock,
		NewDeliveryID:   ids.delivery,
		NewWebhookID:    ids.webhook,
		NewAuditEventID: ids.audit,
		Destinations:    map[string]string{"operations": "https://example.test/webhooks"},
		MaxQueueItems:   8,
		MaxAttempts:     3,
		InitialBackoff:  time.Second,
		MaxBackoff:      time.Second,
		RequestTimeout:  time.Second,
		MaxPayloadBytes: 64 * 1024,
	})
	if err != nil {
		t.Fatalf("delivery.New() error = %v", err)
	}
	return dispatcher, lifecycleSource, reportSource
}

func assertRetryingDeliveries(t *testing.T, results []delivery.Result, want map[string]string) {
	t.Helper()
	if len(results) != len(want) {
		t.Fatalf("disconnected results = %#v, want %d retries", results, len(want))
	}
	for _, result := range results {
		if !result.Retrying || result.Sent || result.Item.AttemptCount != 1 || result.Item.State != contract.DeliveryPending || result.Item.WebhookID != want[result.Item.DeliveryID] {
			t.Fatalf("disconnected result = %#v, want pending retry with stable webhook ID", result)
		}
	}
}

func assertDeliveredAfterRestart(t *testing.T, results []delivery.Result, want map[string]string) {
	t.Helper()
	if len(results) != len(want) {
		t.Fatalf("reconnected results = %#v, want %d deliveries", results, len(want))
	}
	for _, result := range results {
		if !result.Sent || result.Retrying || result.Item.AttemptCount != 2 || result.Item.State != contract.DeliveryDelivered || result.Item.WebhookID != want[result.Item.DeliveryID] {
			t.Fatalf("reconnected result = %#v, want delivered retry with stable webhook ID", result)
		}
	}
}

func assertWebhookAttempts(t *testing.T, attempts []string, want ...string) {
	t.Helper()
	if len(attempts) != len(want)*2 {
		t.Fatalf("webhook attempts = %#v, want two attempts for each ID", attempts)
	}
	counts := make(map[string]int, len(want))
	for _, identifier := range attempts {
		counts[identifier]++
	}
	for _, identifier := range want {
		if counts[identifier] != 2 {
			t.Fatalf("webhook ID %q attempts = %d, want 2 in %#v", identifier, counts[identifier], attempts)
		}
	}
}

func assertPayloadSurvivedRestart(t *testing.T, reportSource *report.Source, lifecycleSource *lifecycle.Source, published report.Result) {
	t.Helper()
	if _, err := reportSource.Load(context.Background(), contract.DeliveryPayloadIncidentReport, published.ReportQueueItem.PayloadRef); err != nil {
		t.Fatalf("reopened report payload Load() error = %v", err)
	}
	if _, err := lifecycleSource.Load(context.Background(), contract.DeliveryPayloadLifecycleEvent, published.LifecycleQueueItem.PayloadRef); err != nil {
		t.Fatalf("reopened lifecycle payload Load() error = %v", err)
	}
}

func assertPersistedDeliveries(t *testing.T, state *store.Store, webhookIDs ...string) {
	t.Helper()
	want := make(map[string]struct{}, len(webhookIDs))
	for _, identifier := range webhookIDs {
		want[identifier] = struct{}{}
	}
	seen := make(map[string]struct{}, len(webhookIDs))
	if err := state.View(func(transaction *store.Tx) error {
		return transaction.ForEach(store.BucketDeliveryQueue, func(_ string, document []byte) error {
			var item contract.DeliveryQueueItem
			if err := json.Unmarshal(document, &item); err != nil {
				return err
			}
			if err := item.Validate(); err != nil {
				return err
			}
			if item.State != contract.DeliveryDelivered || item.AttemptCount != 2 {
				return errors.New("delivery did not retain terminal reconnect state")
			}
			if _, expected := want[item.WebhookID]; !expected {
				return errors.New("delivery webhook ID changed after restart")
			}
			seen[item.WebhookID] = struct{}{}
			return nil
		})
	}); err != nil {
		t.Fatalf("inspect reopened delivery queue: %v", err)
	}
	if len(seen) != len(want) {
		t.Fatalf("persisted webhook IDs = %#v, want %#v", seen, want)
	}
}
