package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	bbolt "go.etcd.io/bbolt"
)

func TestStoreFaultResilience_FailsClosedWithoutPartialState(t *testing.T) {
	t.Run("daemon lock", func(t *testing.T) {
		options := testOptions(t, "state.db")
		options.LockTimeout = 40 * time.Millisecond
		state := openTestStore(t, options)
		cleanupResilienceStore(t, state)
		putResilienceRecord(t, state, "baseline", "preserved")

		second, err := Open(options)
		if second != nil {
			if closeErr := second.Close(); closeErr != nil {
				t.Errorf("unexpected second Store.Close() error = %v", closeErr)
			}
			t.Fatal("Open() unexpectedly acquired the daemon-owned store lock")
		}
		if !errors.Is(err, ErrLockTimeout) {
			t.Fatalf("Open() error = %v, want errors.Is(_, %v)", err, ErrLockTimeout)
		}
		assertResilienceRecords(t, state, map[string]string{"baseline": "preserved"}, "partial")
	})

	t.Run("storage full", func(t *testing.T) {
		options := testOptions(t, "state.db")
		options.MaxFileBytes = 16 * 1024 * 1024
		state := openTestStore(t, options)
		cleanupResilienceStore(t, state)
		putResilienceRecord(t, state, "baseline", "preserved")

		err := state.Update(func(transaction *Tx) error {
			if err := transaction.Put(BucketIncidents, "partial", []byte("must-roll-back")); err != nil {
				return err
			}
			return transaction.Put(BucketDeliveryQueue, "oversized", bytes.Repeat([]byte("x"), 20*1024*1024))
		})
		if !errors.Is(err, ErrStoreFull) {
			t.Fatalf("Update() error = %v, want errors.Is(_, %v)", err, ErrStoreFull)
		}
		assertResilienceRecords(t, state, map[string]string{"baseline": "preserved"}, "partial")
		assertRecordAbsent(t, state, BucketDeliveryQueue, "oversized")
	})

	t.Run("failed migration", func(t *testing.T) {
		options := testOptions(t, "state.db")
		errMigration := errors.New("injected migration failure")
		opened, err := openWithMigrations(options, []migration{{
			from: 0,
			to:   CurrentSchemaVersion,
			apply: func(transaction *bbolt.Tx) error {
				bucket, err := transaction.CreateBucketIfNotExists([]byte(BucketIncidents))
				if err != nil {
					return err
				}
				if err := bucket.Put([]byte("partial"), []byte("must-roll-back")); err != nil {
					return err
				}
				return errMigration
			},
		}})
		if opened != nil {
			if closeErr := opened.Close(); closeErr != nil {
				t.Errorf("unexpected migrated Store.Close() error = %v", closeErr)
			}
			t.Fatal("openWithMigrations() unexpectedly accepted the failed migration")
		}
		if !errors.Is(err, errMigration) {
			t.Fatalf("openWithMigrations() error = %v, want errors.Is(_, %v)", err, errMigration)
		}

		state := openTestStore(t, options)
		cleanupResilienceStore(t, state)
		assertRecordAbsent(t, state, BucketIncidents, "partial")
	})

	t.Run("corrupt backup", func(t *testing.T) {
		fixture, err := os.ReadFile(filepath.Join("testdata", "corrupt.db"))
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		options := testOptions(t, "restored.db")
		restored, err := Restore(options, bytes.NewReader(fixture))
		if restored != nil {
			if closeErr := restored.Close(); closeErr != nil {
				t.Errorf("unexpected restored Store.Close() error = %v", closeErr)
			}
			t.Fatal("Restore() unexpectedly accepted the corrupt backup")
		}
		if !errors.Is(err, ErrRestore) {
			t.Fatalf("Restore() error = %v, want errors.Is(_, %v)", err, ErrRestore)
		}
		if _, err := os.Stat(options.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restored target stat error = %v, want no partial target", err)
		}
	})
}

func cleanupResilienceStore(t *testing.T, state *Store) {
	t.Helper()
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Errorf("Store.Close() error = %v", err)
		}
	})
}

func putResilienceRecord(t *testing.T, state *Store, key, value string) {
	t.Helper()
	if err := state.Update(func(transaction *Tx) error {
		return transaction.Put(BucketIncidents, key, []byte(value))
	}); err != nil {
		t.Fatalf("put resilience record %q: %v", key, err)
	}
}

func assertResilienceRecords(t *testing.T, state *Store, present map[string]string, absent ...string) {
	t.Helper()
	if err := state.View(func(transaction *Tx) error {
		for key, want := range present {
			got, found, err := transaction.Get(BucketIncidents, key)
			if err != nil || !found || string(got) != want {
				t.Fatalf("Get(%q) = %q, found %t, error %v; want %q", key, got, found, err, want)
			}
		}
		for _, key := range absent {
			if _, found, err := transaction.Get(BucketIncidents, key); err != nil || found {
				t.Fatalf("Get(%q) = found %t, error %v; want absent", key, found, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("View() error = %v", err)
	}
}

func assertRecordAbsent(t *testing.T, state *Store, bucket Bucket, key string) {
	t.Helper()
	if err := state.View(func(transaction *Tx) error {
		if _, found, err := transaction.Get(bucket, key); err != nil || found {
			t.Fatalf("Get(%q, %q) = found %t, error %v; want absent", bucket, key, found, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("View() error = %v", err)
	}
}
