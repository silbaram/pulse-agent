package lifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
)

const lifecycleRedactionCorpusSize = 6

func TestPublisher_SensitiveIdentifierCorpusNeverPersists(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "API key", raw: "api_key=api-key-synthetic"},
		{name: "token", raw: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
		{name: "password", raw: "password=password-synthetic"},
		{name: "customer email", raw: "alice@example.test"},
		{name: "customer phone", raw: "010-1234-5678"},
		{name: "new opaque token", raw: "sessionv2.ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"},
	}
	if got := len(tests); got != lifecycleRedactionCorpusSize {
		t.Fatalf("lifecycle redaction corpus size = %d, want %d", got, lifecycleRedactionCorpusSize)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := testNow()
			publisher, _, _ := newPublisher(t, now, acceptClient{}, 2)
			_, err := publisher.Publish(context.Background(), Input{EventID: "event-security", EventType: contract.LifecycleIncidentConfirmed, IncidentID: test.raw, ReasonCode: "probe_failed", OccurredAt: now})
			if !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("Publish() error = %v, want %v", err, ErrInvalidEvent)
			}
			if strings.Contains(err.Error(), test.raw) {
				t.Fatal("lifecycle error contains raw sensitive value")
			}
			if got := countLifecycleSecurityRecords(t, publisher.state, store.BucketLifecycleEvents) + countLifecycleSecurityRecords(t, publisher.state, store.BucketDeliveryQueue); got != 0 {
				t.Fatalf("persisted lifecycle and queue records = %d, want 0", got)
			}
		})
	}
}

func countLifecycleSecurityRecords(t *testing.T, state *store.Store, bucket store.Bucket) int {
	t.Helper()
	count := 0
	if err := state.View(func(transaction *store.Tx) error {
		return transaction.ForEach(bucket, func(string, []byte) error {
			count++
			return nil
		})
	}); err != nil {
		t.Fatalf("count %s records: %v", bucket, err)
	}
	return count
}
