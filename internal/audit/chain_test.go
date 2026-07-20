package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	bbolt "go.etcd.io/bbolt"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
)

func TestCanonicalDigest_UsesStableUTCSerialization(t *testing.T) {
	event := testEvent("audit-1", time.Date(2026, time.July, 21, 9, 10, 11, 123456789, time.FixedZone("KST", 9*60*60)))

	canonical, err := canonicalBytes(event)
	if err != nil {
		t.Fatalf("canonicalBytes() error = %v", err)
	}
	const wantCanonical = `{"schema_version":"v1","event_id":"audit-1","aggregate_type":"incident","aggregate_id":"incident-1","actor_identity":"uid:1000","action":"incident.open","result":"accepted","reason_code":"threshold_exceeded","occurred_at":"2026-07-21T00:10:11.123456789Z","previous_digest":""}`
	if got := string(canonical); got != wantCanonical {
		t.Fatalf("canonical bytes = %q, want %q", got, wantCanonical)
	}
	digest, err := CanonicalDigest(event)
	if err != nil {
		t.Fatalf("CanonicalDigest() error = %v", err)
	}
	const wantDigest = "5f6fa75ba59729a98dec1564f1627ab58e0992e68802e62204fe5618c8c49225"
	if digest != wantDigest {
		t.Fatalf("digest = %q, want %q", digest, wantDigest)
	}
}

func TestAppend_BindsAggregateChangeAndAuditEventInOneTransaction(t *testing.T) {
	state, _ := openTestStore(t, "state.db")
	defer state.Close()

	var appended contract.AuditEvent
	err := state.Update(func(tx *store.Tx) error {
		var err error
		appended, err = Append(tx, testEvent("audit-1", time.Now()), func(tx *store.Tx) error {
			return tx.Put(store.BucketIncidents, "incident-1", []byte("opened"))
		})
		return err
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if appended.PreviousDigest != "" || !validDigest(appended.Digest) {
		t.Fatalf("appended event = %+v, want root event with digest", appended)
	}

	err = state.View(func(tx *store.Tx) error {
		value, found, err := tx.Get(store.BucketIncidents, "incident-1")
		if err != nil || !found || !bytes.Equal(value, []byte("opened")) {
			t.Fatalf("Get() = %q, found %t, error %v; want committed aggregate", value, found, err)
		}
		return ValidateChain(tx)
	})
	if err != nil {
		t.Fatalf("View() error = %v", err)
	}

	if err := state.View(func(tx *store.Tx) error {
		value, found, err := tx.Get(store.BucketAudit, eventKey(0))
		if err != nil || !found {
			t.Fatalf("Get(audit event) = found %t, error %v", found, err)
		}
		var stored contract.AuditEvent
		if err := json.Unmarshal(value, &stored); err != nil {
			return err
		}
		if stored != appended {
			t.Fatalf("stored event = %+v, want %+v", stored, appended)
		}
		return nil
	}); err != nil {
		t.Fatalf("View() error = %v", err)
	}

}

func TestAppend_RollsBackAggregateAndAuditWhenTransactionFails(t *testing.T) {
	state, _ := openTestStore(t, "state.db")
	defer state.Close()

	errRollback := errors.New("rollback transaction")
	err := state.Update(func(tx *store.Tx) error {
		if _, err := Append(tx, testEvent("audit-1", time.Now()), func(tx *store.Tx) error {
			return tx.Put(store.BucketIncidents, "incident-1", []byte("opened"))
		}); err != nil {
			return err
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("Update() error = %v, want errors.Is(_, %v)", err, errRollback)
	}

	if err := state.View(func(tx *store.Tx) error {
		if _, found, err := tx.Get(store.BucketIncidents, "incident-1"); err != nil || found {
			t.Fatalf("aggregate after rollback = found %t, error %v", found, err)
		}
		if _, found, err := tx.Get(store.BucketAudit, eventKey(0)); err != nil || found {
			t.Fatalf("audit after rollback = found %t, error %v", found, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("View() error = %v", err)
	}
}

func TestAppend_RejectsTamperedChainBeforeAggregateMutation(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*bbolt.Bucket) error
	}{
		{
			name: "modified middle event",
			tamper: func(bucket *bbolt.Bucket) error {
				var event contract.AuditEvent
				if err := json.Unmarshal(bucket.Get([]byte(eventKey(1))), &event); err != nil {
					return err
				}
				event.Action = "incident.closed"
				document, err := json.Marshal(event)
				if err != nil {
					return err
				}
				return bucket.Put([]byte(eventKey(1)), document)
			},
		},
		{
			name: "deleted middle event",
			tamper: func(bucket *bbolt.Bucket) error {
				return bucket.Delete([]byte(eventKey(1)))
			},
		},
		{
			name: "reordered events",
			tamper: func(bucket *bbolt.Bucket) error {
				first := append([]byte(nil), bucket.Get([]byte(eventKey(0)))...)
				second := append([]byte(nil), bucket.Get([]byte(eventKey(1)))...)
				if err := bucket.Put([]byte(eventKey(0)), second); err != nil {
					return err
				}
				return bucket.Put([]byte(eventKey(1)), first)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, options := openTestStore(t, "state.db")
			appendTestChain(t, state)
			if err := state.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			tamperBucket(t, options.Path, tt.tamper)

			state, err := store.Open(options)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer state.Close()

			err = state.Update(func(tx *store.Tx) error {
				_, err := Append(tx, testEvent("audit-after-tamper", time.Now()), func(tx *store.Tx) error {
					return tx.Put(store.BucketIncidents, "must-not-write", []byte("blocked"))
				})
				return err
			})
			if !errors.Is(err, ErrChainInvalid) {
				t.Fatalf("Update() error = %v, want errors.Is(_, %v)", err, ErrChainInvalid)
			}
			if err := state.View(func(tx *store.Tx) error {
				if _, found, err := tx.Get(store.BucketIncidents, "must-not-write"); err != nil || found {
					t.Fatalf("blocked aggregate = found %t, error %v; want rollback", found, err)
				}
				return nil
			}); err != nil {
				t.Fatalf("View() error = %v", err)
			}
		})
	}
}

func TestAppend_RejectsSecretValuesAndRawLogs(t *testing.T) {
	state, _ := openTestStore(t, "state.db")
	defer state.Close()

	tests := []struct {
		name   string
		mutate func(*contract.AuditEvent)
	}{
		{
			name: "secret marker",
			mutate: func(event *contract.AuditEvent) {
				event.ReasonCode = "whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE"
			},
		},
		{
			name: "secret prefix",
			mutate: func(event *contract.AuditEvent) {
				event.ReasonCode = "sk-live-secret-value"
			},
		},
		{
			name: "raw log content",
			mutate: func(event *contract.AuditEvent) {
				event.Action = "incident.open\nraw-log=do-not-store"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := testEvent("audit-1", time.Now())
			tt.mutate(&event)
			err := state.Update(func(tx *store.Tx) error {
				_, err := Append(tx, event, nil)
				return err
			})
			if !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("Update() error = %v, want errors.Is(_, %v)", err, ErrInvalidEvent)
			}
		})
	}

	if err := state.View(func(tx *store.Tx) error {
		count := 0
		if err := tx.ForEach(store.BucketAudit, func(string, []byte) error {
			count++
			return nil
		}); err != nil {
			return err
		}
		if count != 0 {
			t.Fatalf("stored audit records = %d, want 0", count)
		}
		return nil
	}); err != nil {
		t.Fatalf("View() error = %v", err)
	}
}

func TestAppend_AllowsSafeActionContainingSKPrefixSubstring(t *testing.T) {
	state, _ := openTestStore(t, "state.db")
	defer state.Close()

	event := testEvent("audit-1", time.Now())
	event.Action = "task-created"
	event.ReasonCode = "secret-rotation"
	if err := state.Update(func(tx *store.Tx) error {
		_, err := Append(tx, event, nil)
		return err
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
}

func appendTestChain(t *testing.T, state *store.Store) {
	t.Helper()
	for index := range 3 {
		eventID := "audit-" + string(rune('1'+index))
		err := state.Update(func(tx *store.Tx) error {
			_, err := Append(tx, testEvent(eventID, time.Date(2026, time.July, 21, 0, index, 0, 0, time.UTC)), nil)
			return err
		})
		if err != nil {
			t.Fatalf("append event %d error = %v", index, err)
		}
	}
}

func tamperBucket(t *testing.T, path string, tamper func(*bbolt.Bucket) error) {
	t.Helper()
	database, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("raw bbolt Open() error = %v", err)
	}
	if err := database.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(store.BucketAudit))
		if bucket == nil {
			return errors.New("audit bucket missing")
		}
		return tamper(bucket)
	}); err != nil {
		t.Fatalf("tamper audit bucket error = %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("raw bbolt Close() error = %v", err)
	}
}

func openTestStore(t *testing.T, name string) (*store.Store, store.Options) {
	t.Helper()
	options := store.Options{
		Path:        filepath.Join(t.TempDir(), name),
		LockTimeout: time.Second,
	}
	state, err := store.Open(options)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return state, options
}

func testEvent(eventID string, occurredAt time.Time) contract.AuditEvent {
	return contract.AuditEvent{
		SchemaVersion: contract.SchemaVersionV1,
		EventID:       eventID,
		AggregateType: "incident",
		AggregateID:   "incident-1",
		ActorIdentity: "uid:1000",
		Action:        "incident.open",
		Result:        "accepted",
		ReasonCode:    "threshold_exceeded",
		OccurredAt:    occurredAt,
	}
}
