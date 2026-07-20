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

func TestOpen_CreatesExplicitBucketsWithOwnerOnlyPermissions(t *testing.T) {
	store := openTestStore(t, testOptions(t, "state.db"))
	defer store.Close()

	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if permissions := info.Mode().Perm(); permissions&^dataFileMode != 0 {
		t.Fatalf("data file permissions = %#o, want no bits outside %#o", permissions, dataFileMode)
	}

	version, err := store.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion() error = %v", err)
	}
	if version != CurrentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, CurrentSchemaVersion)
	}

	err = store.View(func(transaction *Tx) error {
		for _, bucket := range dataBuckets {
			if _, found, err := transaction.Get(bucket, "absent"); err != nil || found {
				t.Fatalf("Get(%q) = found %t, error %v; want missing record", bucket, found, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View() error = %v", err)
	}
}

func TestStore_TransactionsRollbackAndCopyValues(t *testing.T) {
	store := openTestStore(t, testOptions(t, "state.db"))
	defer store.Close()

	value := []byte("original")
	if err := store.Update(func(transaction *Tx) error {
		return transaction.Put(BucketIncidents, "incident-1", value)
	}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	value[0] = 'X'

	errRollback := errors.New("rollback")
	err := store.Update(func(transaction *Tx) error {
		if err := transaction.Put(BucketIncidents, "incident-2", []byte("transient")); err != nil {
			return err
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("rollback error = %v, want errors.Is(_, %v)", err, errRollback)
	}

	err = store.View(func(transaction *Tx) error {
		got, found, err := transaction.Get(BucketIncidents, "incident-1")
		if err != nil || !found {
			t.Fatalf("Get(incident-1) = %q, found %t, error %v", got, found, err)
		}
		if string(got) != "original" {
			t.Fatalf("Get(incident-1) = %q, want %q", got, "original")
		}
		got[0] = 'Y'
		if _, found, err := transaction.Get(BucketIncidents, "incident-2"); err != nil || found {
			t.Fatalf("Get(incident-2) = found %t, error %v; want rollback", found, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View() error = %v", err)
	}

	err = store.View(func(transaction *Tx) error {
		got, found, err := transaction.Get(BucketIncidents, "incident-1")
		if err != nil || !found || string(got) != "original" {
			t.Fatalf("second Get(incident-1) = %q, found %t, error %v", got, found, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View() error = %v", err)
	}
}

func TestStore_StoresRecordsInEveryContractBucket(t *testing.T) {
	store := openTestStore(t, testOptions(t, "state.db"))
	defer store.Close()

	records := make(map[Bucket][]byte, len(dataBuckets))
	for _, bucket := range dataBuckets {
		records[bucket] = []byte("record-for-" + string(bucket))
	}
	if err := store.Update(func(transaction *Tx) error {
		for bucket, value := range records {
			if err := transaction.Put(bucket, "record-1", value); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if err := store.View(func(transaction *Tx) error {
		for bucket, want := range records {
			got, found, err := transaction.Get(bucket, "record-1")
			if err != nil || !found || !bytes.Equal(got, want) {
				t.Fatalf("Get(%q) = %q, found %t, error %v; want %q", bucket, got, found, err, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("View() error = %v", err)
	}
}

func TestOpen_RejectsSecondWriterAfterConfiguredTimeout(t *testing.T) {
	options := testOptions(t, "state.db")
	options.LockTimeout = 40 * time.Millisecond
	store := openTestStore(t, options)
	defer store.Close()

	started := time.Now()
	second, err := Open(options)
	if second != nil {
		second.Close()
		t.Fatal("second Open() unexpectedly acquired the daemon lock")
	}
	if !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("second Open() error = %v, want errors.Is(_, %v)", err, ErrLockTimeout)
	}
	if elapsed := time.Since(started); elapsed < options.LockTimeout || elapsed > time.Second {
		t.Fatalf("lock timeout elapsed = %v, want between %v and 1s", elapsed, options.LockTimeout)
	}
}

func TestOpen_MigrationFailureRollsBackPartialState(t *testing.T) {
	options := testOptions(t, "state.db")
	errMigration := errors.New("migration fault")
	_, err := openWithMigrations(options, []migration{{
		from: 0,
		to:   CurrentSchemaVersion,
		apply: func(transaction *bbolt.Tx) error {
			bucket, err := transaction.CreateBucketIfNotExists([]byte(BucketIncidents))
			if err != nil {
				return err
			}
			if err := bucket.Put([]byte("partial"), []byte("must-not-survive")); err != nil {
				return err
			}
			return errMigration
		},
	}})
	if !errors.Is(err, errMigration) {
		t.Fatalf("Open() error = %v, want errors.Is(_, %v)", err, errMigration)
	}

	store := openTestStore(t, options)
	defer store.Close()
	if err := store.View(func(transaction *Tx) error {
		if _, found, err := transaction.Get(BucketIncidents, "partial"); err != nil || found {
			t.Fatalf("partial migration record = found %t, error %v; want rollback", found, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("View() after failed migration error = %v", err)
	}
}

func TestStore_StorageFullRollsBackTransaction(t *testing.T) {
	options := testOptions(t, "state.db")
	options.MaxFileBytes = 16 * 1024 * 1024
	store := openTestStore(t, options)
	defer store.Close()

	err := store.Update(func(transaction *Tx) error {
		return transaction.Put(BucketDeliveryQueue, "oversized", bytes.Repeat([]byte("x"), 20*1024*1024))
	})
	if !errors.Is(err, ErrStoreFull) {
		t.Fatalf("Update() error = %v, want errors.Is(_, %v)", err, ErrStoreFull)
	}
	if err := store.View(func(transaction *Tx) error {
		if _, found, err := transaction.Get(BucketDeliveryQueue, "oversized"); err != nil || found {
			t.Fatalf("oversized record = found %t, error %v; want rollback", found, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("View() error = %v", err)
	}
}

func TestStore_BackupRestoreReproducesRecordsAndSchema(t *testing.T) {
	source := openTestStore(t, testOptions(t, "source.db"))
	defer source.Close()

	records := make(map[Bucket][]byte, len(dataBuckets))
	for _, bucket := range dataBuckets {
		records[bucket] = []byte("backup-" + string(bucket))
	}
	if err := source.Update(func(transaction *Tx) error {
		for bucket, value := range records {
			if err := transaction.Put(bucket, "record-1", value); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	var backup bytes.Buffer
	if err := source.Backup(&backup); err != nil {
		t.Fatalf("Backup() error = %v", err)
	}
	restored, err := Restore(testOptions(t, "restored.db"), bytes.NewReader(backup.Bytes()))
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	defer restored.Close()

	version, err := restored.SchemaVersion()
	if err != nil || version != CurrentSchemaVersion {
		t.Fatalf("restored SchemaVersion() = %d, error %v; want %d", version, err, CurrentSchemaVersion)
	}
	if err := restored.View(func(transaction *Tx) error {
		for bucket, want := range records {
			got, found, err := transaction.Get(bucket, "record-1")
			if err != nil || !found || !bytes.Equal(got, want) {
				t.Fatalf("restored Get(%q) = %q, found %t, error %v; want %q", bucket, got, found, err, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("restored View() error = %v", err)
	}
}

func TestRestore_RejectsCorruptionFixtureWithoutCreatingTarget(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "corrupt.db"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	options := testOptions(t, "restored.db")
	store, err := Restore(options, bytes.NewReader(fixture))
	if store != nil {
		store.Close()
		t.Fatal("Restore() unexpectedly accepted the corruption fixture")
	}
	if !errors.Is(err, ErrRestore) {
		t.Fatalf("Restore() error = %v, want errors.Is(_, %v)", err, ErrRestore)
	}
	if _, err := os.Stat(options.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restore target stat error = %v, want target not created", err)
	}
}

func TestOpen_RejectsMissingBucketAsIntegrityFailure(t *testing.T) {
	options := testOptions(t, "state.db")
	store := openTestStore(t, options)
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	database, err := bbolt.Open(options.Path, dataFileMode, nil)
	if err != nil {
		t.Fatalf("raw bbolt Open() error = %v", err)
	}
	if err := database.Update(func(transaction *bbolt.Tx) error {
		return transaction.DeleteBucket([]byte(BucketAudit))
	}); err != nil {
		database.Close()
		t.Fatalf("DeleteBucket() error = %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("raw bbolt Close() error = %v", err)
	}

	store, err = Open(options)
	if store != nil {
		store.Close()
		t.Fatal("Open() unexpectedly accepted a missing required bucket")
	}
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Open() error = %v, want errors.Is(_, %v)", err, ErrIntegrity)
	}
}

func testOptions(t *testing.T, name string) Options {
	t.Helper()
	return Options{
		Path:        filepath.Join(t.TempDir(), name),
		LockTimeout: time.Second,
	}
}

func openTestStore(t *testing.T, options Options) *Store {
	t.Helper()
	store, err := Open(options)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return store
}
