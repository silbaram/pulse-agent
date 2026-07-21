package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
	"pulse-agent/internal/webhook"
)

const (
	testCurrentSecret  = "whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
	testPreviousSecret = "whsec_YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg="
)

func TestDispatcher_EnqueuePersistsOnlySharedDeliveryFields(t *testing.T) {
	now := testNow()
	state := openState(t)
	dispatcher := newDispatcher(t, state, &clockFunc{now: now}, &staticPayloads{body: []byte(`{"event":"ignored"}`)}, rejectClient{}, "https://example.test/webhooks", 2, 3)

	for _, payloadType := range []contract.DeliveryPayloadType{contract.DeliveryPayloadLifecycleEvent, contract.DeliveryPayloadIncidentReport} {
		item, err := dispatcher.Enqueue(EnqueueRequest{PayloadType: payloadType, PayloadRef: string(payloadType) + "-ref", DestinationRef: "operations", ExpiresAt: now.Add(time.Hour)})
		if err != nil {
			t.Fatalf("Enqueue(%q) error = %v", payloadType, err)
		}
		if item.PayloadType != payloadType || item.PayloadRef != string(payloadType)+"-ref" || item.DestinationRef != "operations" || item.AttemptCount != 0 || item.NextAttemptAt != now || item.State != contract.DeliveryPending || item.WebhookID == "" || item.DeliveryID == "" {
			t.Fatalf("Enqueue(%q) = %#v, want shared pending item", payloadType, item)
		}
	}

	documents := deliveryDocuments(t, state)
	if len(documents) != 2 {
		t.Fatalf("stored deliveries = %d, want 2", len(documents))
	}
	for _, document := range documents {
		if strings.Contains(string(document), testCurrentSecret) || strings.Contains(string(document), "ignored") || strings.Contains(string(document), "report_id") {
			t.Fatalf("delivery document retained secret, payload, or report-only field: %s", document)
		}
	}
	if _, err := dispatcher.Enqueue(EnqueueRequest{PayloadType: "unsupported", PayloadRef: "payload", DestinationRef: "operations", ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Enqueue(unsupported) error = %v, want ErrInvalidRequest", err)
	}
}

func TestDispatcher_SendsExactBodyWithCurrentAndPreviousSignatures(t *testing.T) {
	now := testNow()
	var received struct {
		body    []byte
		headers http.Header
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var err error
		received.body, err = io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		received.headers = request.Header.Clone()
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	state := openState(t)
	payload := []byte("{\n  \"event\": \"confirmed\"\n}")
	dispatcher := newDispatcher(t, state, &clockFunc{now: now}, &staticPayloads{body: payload}, server.Client(), server.URL, 4, 3)
	item, err := dispatcher.Enqueue(EnqueueRequest{PayloadType: contract.DeliveryPayloadLifecycleEvent, PayloadRef: "event-1", DestinationRef: "operations", ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	results, err := dispatcher.DeliverDue(context.Background())
	if err != nil {
		t.Fatalf("DeliverDue() error = %v", err)
	}
	if len(results) != 1 || !results[0].Sent || results[0].Item.State != contract.DeliveryDelivered || results[0].Item.AttemptCount != 1 {
		t.Fatalf("DeliverDue() = %#v, want one delivered attempt", results)
	}
	if string(received.body) != string(payload) || received.headers.Get(webhook.HeaderID) != item.WebhookID || received.headers.Get("Content-Type") != "application/json" {
		t.Fatalf("received body/headers = %q/%#v, want exact body and stable ID", received.body, received.headers)
	}
	headers := webhook.Headers{ID: received.headers.Get(webhook.HeaderID), Timestamp: received.headers.Get(webhook.HeaderTimestamp), Signature: received.headers.Get(webhook.HeaderSignature)}
	for _, secret := range []string{testCurrentSecret, testPreviousSecret} {
		keyring, keyErr := webhook.NewKeyring(secret)
		if keyErr != nil {
			t.Fatalf("NewKeyring() error = %v", keyErr)
		}
		if verifyErr := keyring.Verify(headers, received.body, now); verifyErr != nil {
			t.Fatalf("Verify(rotation) error = %v", verifyErr)
		}
	}
}

func TestDispatcher_RetriesEndpointFailureWithStableWebhookID(t *testing.T) {
	now := testNow()
	clock := &clockFunc{now: now}
	var webhookIDs []string
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		webhookIDs = append(webhookIDs, request.Header.Get(webhook.HeaderID))
		if requests == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := newDispatcher(t, openState(t), clock, &staticPayloads{body: []byte(`{"report":"ready"}`)}, server.Client(), server.URL, 4, 3)
	item, err := dispatcher.Enqueue(EnqueueRequest{PayloadType: contract.DeliveryPayloadIncidentReport, PayloadRef: "report-1", DestinationRef: "operations", ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	first, err := dispatcher.DeliverDue(context.Background())
	if err != nil {
		t.Fatalf("first DeliverDue() error = %v", err)
	}
	if len(first) != 1 || !first[0].Retrying || first[0].Item.AttemptCount != 1 || first[0].Item.NextAttemptAt != now.Add(time.Second) {
		t.Fatalf("first DeliverDue() = %#v, want retry after one-second backoff", first)
	}
	clock.now = first[0].Item.NextAttemptAt
	second, err := dispatcher.DeliverDue(context.Background())
	if err != nil {
		t.Fatalf("second DeliverDue() error = %v", err)
	}
	if len(second) != 1 || !second[0].Sent || second[0].Item.State != contract.DeliveryDelivered || second[0].Item.AttemptCount != 2 {
		t.Fatalf("second DeliverDue() = %#v, want delivered retry", second)
	}
	if len(webhookIDs) != 2 || webhookIDs[0] != item.WebhookID || webhookIDs[1] != item.WebhookID {
		t.Fatalf("webhook IDs = %#v, want stable %q", webhookIDs, item.WebhookID)
	}

	again, err := dispatcher.DeliverDue(context.Background())
	if err != nil || len(again) != 0 || requests != 2 {
		t.Fatalf("duplicate 2xx DeliverDue() = %#v, %v, requests=%d, want no replay", again, err, requests)
	}
}

func TestDispatcher_EnforcesQueueBoundAndRecoversAfterRestart(t *testing.T) {
	now := testNow()
	clock := &clockFunc{now: now}
	state := openState(t)
	first := newDispatcher(t, state, clock, &staticPayloads{body: []byte(`{"event":"restart"}`)}, acceptClient{}, "https://example.test/webhooks", 1, 3)
	item, err := first.Enqueue(EnqueueRequest{PayloadType: contract.DeliveryPayloadLifecycleEvent, PayloadRef: "event-1", DestinationRef: "operations", ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("first Enqueue() error = %v", err)
	}
	if _, err := first.Enqueue(EnqueueRequest{PayloadType: contract.DeliveryPayloadLifecycleEvent, PayloadRef: "event-2", DestinationRef: "operations", ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("bounded Enqueue() error = %v, want ErrQueueFull", err)
	}

	restarted := newDispatcher(t, state, clock, &staticPayloads{body: []byte(`{"event":"restart"}`)}, acceptClient{}, "https://example.test/webhooks", 1, 3)
	results, err := restarted.DeliverDue(context.Background())
	if err != nil || len(results) != 1 || !results[0].Sent || results[0].Item.DeliveryID != item.DeliveryID {
		t.Fatalf("restart DeliverDue() = %#v, %v, want durable queued item delivered", results, err)
	}
}

func TestDispatcher_ExpiresAndAuditsDeliveryFailure(t *testing.T) {
	now := testNow()
	clock := &clockFunc{now: now}
	state := openState(t)
	dispatcher := newDispatcher(t, state, clock, &staticPayloads{body: []byte(`{"event":"expiry"}`)}, rejectClient{}, "https://example.test/webhooks", 2, 3)
	item, err := dispatcher.Enqueue(EnqueueRequest{PayloadType: contract.DeliveryPayloadLifecycleEvent, PayloadRef: "event-1", DestinationRef: "operations", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	clock.now = now.Add(time.Minute)
	results, err := dispatcher.DeliverDue(context.Background())
	if err != nil {
		t.Fatalf("DeliverDue() error = %v", err)
	}
	if len(results) != 1 || results[0].Item.DeliveryID != item.DeliveryID || results[0].Item.State != contract.DeliveryExpired || results[0].ReasonCode != "expired" {
		t.Fatalf("DeliverDue() = %#v, want expired delivery", results)
	}
	events := auditEvents(t, state)
	if len(events) != 1 || events[0].Action != "delivery.failed" || events[0].Result != "failed" || events[0].ReasonCode != "expired" || events[0].AggregateID != item.DeliveryID {
		t.Fatalf("expiry audit = %#v, want delivery_failed expired audit", events)
	}
}

func TestDispatcher_UsesTimeoutAndFailsAfterBoundedAttempts(t *testing.T) {
	now := testNow()
	clock := &clockFunc{now: now}
	client := &timeoutClient{}
	dispatcher := newDispatcher(t, openState(t), clock, &staticPayloads{body: []byte(`{"event":"timeout"}`)}, client, "https://example.test/webhooks", 2, 2)
	if _, err := dispatcher.Enqueue(EnqueueRequest{PayloadType: contract.DeliveryPayloadLifecycleEvent, PayloadRef: "event-1", DestinationRef: "operations", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	first, err := dispatcher.DeliverDue(context.Background())
	if err != nil || len(first) != 1 || !first[0].Retrying || !client.sawDeadline {
		t.Fatalf("first DeliverDue() = %#v, %v, timeout deadline=%t, want retry with deadline", first, err, client.sawDeadline)
	}
	clock.now = first[0].Item.NextAttemptAt
	second, err := dispatcher.DeliverDue(context.Background())
	if err != nil || len(second) != 1 || second[0].Item.State != contract.DeliveryFailed || second[0].ReasonCode != "attempts_exhausted" {
		t.Fatalf("second DeliverDue() = %#v, %v, want bounded terminal failure", second, err)
	}
}

func TestDispatcher_RetriesWhenResponseCloseFails(t *testing.T) {
	now := testNow()
	dispatcher := newDispatcher(t, openState(t), &clockFunc{now: now}, &staticPayloads{body: []byte(`{"event":"close"}`)}, closeErrorClient{}, "https://example.test/webhooks", 2, 2)
	if _, err := dispatcher.Enqueue(EnqueueRequest{PayloadType: contract.DeliveryPayloadLifecycleEvent, PayloadRef: "event-1", DestinationRef: "operations", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	results, err := dispatcher.DeliverDue(context.Background())
	if err != nil || len(results) != 1 || !results[0].Retrying || results[0].ReasonCode != "endpoint_failed" {
		t.Fatalf("DeliverDue() = %#v, %v, want retry after response close failure", results, err)
	}
}

type clockFunc struct{ now time.Time }

func (c *clockFunc) Now() time.Time { return c.now }

type staticPayloads struct {
	body []byte
	err  error
}

func (p *staticPayloads) Load(_ context.Context, _ contract.DeliveryPayloadType, _ string) ([]byte, error) {
	if p.err != nil {
		return nil, p.err
	}
	return append([]byte(nil), p.body...), nil
}

type acceptClient struct{}

func (acceptClient) Do(_ *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
}

type rejectClient struct{}

func (rejectClient) Do(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("endpoint disconnected")
}

type timeoutClient struct{ sawDeadline bool }

func (c *timeoutClient) Do(request *http.Request) (*http.Response, error) {
	_, c.sawDeadline = request.Context().Deadline()
	return nil, context.DeadlineExceeded
}

type closeErrorClient struct{}

func (closeErrorClient) Do(_ *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusNoContent, Body: closeErrorBody{}}, nil
}

type closeErrorBody struct{}

func (closeErrorBody) Read(_ []byte) (int, error) { return 0, io.EOF }

func (closeErrorBody) Close() error { return errors.New("response close failed") }

func newDispatcher(t *testing.T, state *store.Store, clock Clock, payloads PayloadSource, client HTTPClient, endpoint string, queueLimit, attempts int) *Dispatcher {
	t.Helper()
	keyring, err := webhook.NewKeyring(testCurrentSecret, testPreviousSecret)
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
	dispatcher, err := New(Options{
		State:           state,
		Client:          client,
		Payloads:        payloads,
		Keyring:         keyring,
		Clock:           clock,
		NewDeliveryID:   nextID("delivery"),
		NewWebhookID:    nextID("webhook"),
		NewAuditEventID: nextID("audit"),
		Destinations:    map[string]string{"operations": endpoint},
		MaxQueueItems:   queueLimit,
		MaxAttempts:     attempts,
		InitialBackoff:  time.Second,
		MaxBackoff:      4 * time.Second,
		RequestTimeout:  time.Second,
		MaxPayloadBytes: 1024,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return dispatcher
}

func openState(t *testing.T) *store.Store {
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
	return state
}

func deliveryDocuments(t *testing.T, state *store.Store) [][]byte {
	t.Helper()
	documents := make([][]byte, 0)
	if err := state.View(func(transaction *store.Tx) error {
		return transaction.ForEach(store.BucketDeliveryQueue, func(_ string, document []byte) error {
			documents = append(documents, document)
			return nil
		})
	}); err != nil {
		t.Fatalf("read delivery queue: %v", err)
	}
	return documents
}

func auditEvents(t *testing.T, state *store.Store) []contract.AuditEvent {
	t.Helper()
	events := make([]contract.AuditEvent, 0)
	if err := state.View(func(transaction *store.Tx) error {
		return transaction.ForEach(store.BucketAudit, func(_ string, document []byte) error {
			var event contract.AuditEvent
			if err := json.Unmarshal(document, &event); err != nil {
				return err
			}
			events = append(events, event)
			return nil
		})
	}); err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	return events
}

func testNow() time.Time { return time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC) }
