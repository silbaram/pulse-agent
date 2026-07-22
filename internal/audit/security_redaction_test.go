package audit

import (
	"errors"
	"strings"
	"testing"
	"time"

	"pulse-agent/internal/store"
)

const auditRedactionCorpusSize = 6

func TestAppend_SensitiveFieldCorpusNeverPersists(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "GitHub token", raw: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
		{name: "Slack token", raw: "xoxb-redaction-fixture"},
		{name: "secret key", raw: "sk_fixture_opaque"},
		{name: "customer email", raw: "alice@example.test"},
		{name: "customer phone", raw: "010-1234-5678"},
		{name: "new opaque token", raw: "sessionv2.ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"},
	}
	if got := len(tests); got != auditRedactionCorpusSize {
		t.Fatalf("audit redaction corpus size = %d, want %d", got, auditRedactionCorpusSize)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, _ := openTestStore(t, "state.db")
			t.Cleanup(func() {
				if err := state.Close(); err != nil {
					t.Errorf("close state: %v", err)
				}
			})
			event := testEvent("audit-security", time.Date(2026, time.July, 22, 1, 0, 0, 0, time.UTC))
			event.AggregateID = test.raw
			err := state.Update(func(transaction *store.Tx) error {
				_, appendErr := Append(transaction, event, nil)
				return appendErr
			})
			if !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("Append() error = %v, want %v", err, ErrInvalidEvent)
			}
			if strings.Contains(err.Error(), test.raw) {
				t.Fatal("audit error contains raw sensitive value")
			}
			if got := countAuditSecurityRecords(t, state); got != 0 {
				t.Fatalf("persisted audit records = %d, want 0", got)
			}
		})
	}
}

func countAuditSecurityRecords(t *testing.T, state *store.Store) int {
	t.Helper()
	count := 0
	if err := state.View(func(transaction *store.Tx) error {
		return transaction.ForEach(store.BucketAudit, func(string, []byte) error {
			count++
			return nil
		})
	}); err != nil {
		t.Fatalf("count audit records: %v", err)
	}
	return count
}
