package report

import (
	"context"
	"errors"
	"strings"
	"testing"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
)

const reportRedactionCorpusSize = 6

func TestPublisher_SensitiveReportCorpusNeverPersists(t *testing.T) {
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
	if got := len(tests); got != reportRedactionCorpusSize {
		t.Fatalf("report redaction corpus size = %d, want %d", got, reportRedactionCorpusSize)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := testNow()
			publisher, _, _, _, _ := newPublisher(t, now, acceptClient{}, 4, 2)
			input := completeInput(now, contract.IncidentClosed)
			input.PostmortemDraft = "diagnostic " + test.raw
			_, err := publisher.PublishTerminal(context.Background(), input)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("PublishTerminal() error = %v, want %v", err, ErrInvalidInput)
			}
			if strings.Contains(err.Error(), test.raw) {
				t.Fatal("report error contains raw sensitive value")
			}
			if got := countReportSecurityRecords(t, publisher.state, store.BucketIncidentReports) + countReportSecurityRecords(t, publisher.state, store.BucketLifecycleEvents) + countReportSecurityRecords(t, publisher.state, store.BucketDeliveryQueue); got != 0 {
				t.Fatalf("persisted report, lifecycle, and queue records = %d, want 0", got)
			}
		})
	}
}

func countReportSecurityRecords(t *testing.T, state *store.Store, bucket store.Bucket) int {
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
