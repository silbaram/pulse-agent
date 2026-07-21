package lifecycle

import (
	"context"
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
	"pulse-agent/internal/store"
	"pulse-agent/internal/webhook"
)

const testWebhookSecret = "whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="

func TestPublisher_PersistsEveryApprovedLifecycleTypeWithMinimalEvidence(t *testing.T) {
	now := testNow()
	publisher, source, _ := newPublisher(t, now, acceptClient{}, 16)
	types := []contract.LifecycleEventType{
		contract.LifecycleIncidentConfirmed,
		contract.LifecycleAnalysisUnavailable,
		contract.LifecyclePolicyDenied,
		contract.LifecycleApprovalRequested,
		contract.LifecycleRecoveryStarted,
		contract.LifecycleIncidentClosed,
		contract.LifecycleIncidentFailed,
	}
	for index, eventType := range types {
		result, err := publisher.Publish(context.Background(), Input{
			EventID:      "event-" + strconv.Itoa(index),
			EventType:    eventType,
			IncidentID:   "incident-1",
			ReasonCode:   "transitioned",
			EvidenceRefs: []string{"evidence-1"},
			OccurredAt:   now,
		})
		if err != nil || result.Duplicate || result.QueueItem.PayloadType != contract.DeliveryPayloadLifecycleEvent || result.QueueItem.PayloadRef != result.Event.EventID {
			t.Fatalf("Publish(%q) = %#v, %v, want durable lifecycle queue item", eventType, result, err)
		}
		body, loadErr := source.Load(context.Background(), contract.DeliveryPayloadLifecycleEvent, result.Event.EventID)
		if loadErr != nil || !strings.Contains(string(body), `"evidence_refs":["evidence-1"]`) || strings.Contains(string(body), "raw-secret") {
			t.Fatalf("Load(%q) = %s, %v, want minimal secret-free payload", eventType, body, loadErr)
		}
	}
}

func TestPublisher_DuplicateTransitionUsesOneDeliveryAndExactPayload(t *testing.T) {
	now := testNow()
	publisher, source, dispatcher := newPublisher(t, now, acceptClient{}, 2)
	input := Input{EventID: "event-confirmed", EventType: contract.LifecycleIncidentConfirmed, IncidentID: "incident-1", ReasonCode: "probe_failed", EvidenceRefs: []string{"evidence-1"}, OccurredAt: now}
	first, err := publisher.Publish(context.Background(), input)
	if err != nil || first.Duplicate {
		t.Fatalf("first Publish() = %#v, %v", first, err)
	}
	second, err := publisher.Publish(context.Background(), input)
	if err != nil || !second.Duplicate || second.QueueItem != (contract.DeliveryQueueItem{}) {
		t.Fatalf("second Publish() = %#v, %v, want duplicate without another queue item", second, err)
	}
	body, err := source.Load(context.Background(), contract.DeliveryPayloadLifecycleEvent, input.EventID)
	if err != nil || string(body) != `{"schema_version":"v1","event_id":"event-confirmed","event_type":"incident.confirmed","incident_id":"incident-1","occurred_at":"2026-07-21T09:00:00Z","reason_code":"probe_failed","evidence_refs":["evidence-1"]}` {
		t.Fatalf("Load() = %s, %v, want exact durable event JSON", body, err)
	}
	results, err := dispatcher.DeliverDue(context.Background())
	if err != nil || len(results) != 1 || !results[0].Sent {
		t.Fatalf("DeliverDue() = %#v, %v, want exactly one delivery", results, err)
	}
}

func TestPublisher_QueueFailureRollsBackPayloadAndRejectsSecrets(t *testing.T) {
	now := testNow()
	publisher, source, _ := newPublisher(t, now, acceptClient{}, 1)
	if _, err := publisher.Publish(context.Background(), Input{EventID: "event-one", EventType: contract.LifecycleIncidentConfirmed, IncidentID: "incident-1", ReasonCode: "probe_failed", OccurredAt: now}); err != nil {
		t.Fatalf("first Publish() error = %v", err)
	}
	if _, err := publisher.Publish(context.Background(), Input{EventID: "event-two", EventType: contract.LifecyclePolicyDenied, IncidentID: "incident-1", ReasonCode: "policy_denied", OccurredAt: now}); !errors.Is(err, delivery.ErrQueueFull) {
		t.Fatalf("queue-full Publish() error = %v, want ErrQueueFull", err)
	}
	if _, err := source.Load(context.Background(), contract.DeliveryPayloadLifecycleEvent, "event-two"); !errors.Is(err, ErrPayloadNotFound) {
		t.Fatalf("Load(rolled back event) error = %v, want ErrPayloadNotFound", err)
	}
	if _, err := publisher.Publish(context.Background(), Input{EventID: "event-secret", EventType: contract.LifecycleIncidentConfirmed, IncidentID: "incident-1", ReasonCode: "probe_failed", EvidenceRefs: []string{"api_key=raw-secret"}, OccurredAt: now}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("secret-bearing Publish() error = %v, want ErrInvalidEvent", err)
	}
}

func TestPublisher_EndpointFailureDoesNotUndoDurableEvent(t *testing.T) {
	now := testNow()
	publisher, source, dispatcher := newPublisher(t, now, rejectClient{}, 2)
	result, err := publisher.Publish(context.Background(), Input{EventID: "event-recovery", EventType: contract.LifecycleRecoveryStarted, IncidentID: "incident-1", ReasonCode: "recovery_started", OccurredAt: now})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	results, err := dispatcher.DeliverDue(context.Background())
	if err != nil || len(results) != 1 || !results[0].Retrying || results[0].Item.DeliveryID != result.QueueItem.DeliveryID {
		t.Fatalf("DeliverDue() = %#v, %v, want independent endpoint retry", results, err)
	}
	if _, err := source.Load(context.Background(), contract.DeliveryPayloadLifecycleEvent, result.Event.EventID); err != nil {
		t.Fatalf("Load(durable event) error = %v", err)
	}
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

func newPublisher(t *testing.T, now time.Time, client delivery.HTTPClient, queueLimit int) (*Publisher, *Source, *delivery.Dispatcher) {
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
	source, err := NewSource(state)
	if err != nil {
		t.Fatalf("NewSource() error = %v", err)
	}
	keyring, err := webhook.NewKeyring(testWebhookSecret)
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
	clock := testClock{now: now}
	dispatcher, err := delivery.New(delivery.Options{
		State:           state,
		Client:          client,
		Payloads:        source,
		Keyring:         keyring,
		Clock:           clock,
		NewDeliveryID:   nextID("delivery"),
		NewWebhookID:    nextID("webhook"),
		NewAuditEventID: nextID("audit"),
		Destinations:    map[string]string{"operations": "https://example.test/webhooks"},
		MaxQueueItems:   queueLimit,
		MaxAttempts:     2,
		InitialBackoff:  time.Second,
		MaxBackoff:      time.Second,
		RequestTimeout:  time.Second,
		MaxPayloadBytes: 1024,
	})
	if err != nil {
		t.Fatalf("delivery.New() error = %v", err)
	}
	publisher, err := New(Options{State: state, Queue: dispatcher, DestinationRef: "operations", Clock: clock, DeliveryTTL: time.Hour})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return publisher, source, dispatcher
}

func testNow() time.Time { return time.Date(2026, time.July, 21, 9, 0, 0, 0, time.UTC) }
