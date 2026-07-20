// Package store provides the daemon-owned local state store.
package store

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	bbolt "go.etcd.io/bbolt"
	bbolterrors "go.etcd.io/bbolt/errors"
)

const (
	// CurrentSchemaVersion is the newest local-state schema supported by this
	// binary. Future schema changes must append a transactional migration.
	CurrentSchemaVersion uint32 = 1

	dataFileMode os.FileMode = 0o600
)

var (
	// ErrInvalidOptions indicates options that cannot safely open a local store.
	ErrInvalidOptions = errors.New("invalid local store options")
	// ErrStoreOpen indicates that the local store could not be opened.
	ErrStoreOpen = errors.New("open local store")
	// ErrLockTimeout indicates that another process still owns the store file.
	ErrLockTimeout = errors.New("local store lock timeout")
	// ErrInsecureDataFile indicates a non-regular file or permissions broader
	// than the daemon-only file mode.
	ErrInsecureDataFile = errors.New("insecure local store data file")
	// ErrUnsupportedSchema indicates data newer than this binary or a missing
	// migration path.
	ErrUnsupportedSchema = errors.New("unsupported local store schema")
	// ErrIntegrity indicates a database that fails a required logical or bbolt
	// consistency check.
	ErrIntegrity = errors.New("local store integrity check failed")
	// ErrUnknownBucket indicates an attempt to access a bucket outside the
	// explicit local-state contract.
	ErrUnknownBucket = errors.New("unknown local store bucket")
	// ErrInvalidKey indicates an empty record key.
	ErrInvalidKey = errors.New("invalid local store key")
	// ErrInvalidTransaction indicates a missing transaction callback.
	ErrInvalidTransaction = errors.New("invalid local store transaction")
	// ErrStoreFull indicates a storage-full condition. It wraps both actual
	// ENOSPC errors and the deterministic configured-size guard.
	ErrStoreFull = errors.New("local store is full")
	// ErrRestoreTargetExists indicates that restore refused to overwrite an
	// existing state file.
	ErrRestoreTargetExists = errors.New("local store restore target exists")
	// ErrRestore indicates a backup that could not be restored safely.
	ErrRestore = errors.New("restore local store backup")
)

// Bucket identifies a durable local-state collection. The set is deliberately
// closed so callers cannot create ad-hoc state outside the reviewed contract.
type Bucket string

const (
	// BucketConfigurationVersions holds accepted configuration revisions.
	BucketConfigurationVersions Bucket = "configuration_versions"
	// BucketIncidents holds durable incident records.
	BucketIncidents Bucket = "incidents"
	// BucketAnalysisReferences holds analysis references, never raw prompts or evidence.
	BucketAnalysisReferences Bucket = "analysis_references"
	// BucketApprovals holds approval decisions and their audit context.
	BucketApprovals Bucket = "approvals"
	// BucketCommandJournal holds recovery command lifecycle entries.
	BucketCommandJournal Bucket = "command_journal"
	// BucketAudit holds append-only audit records.
	BucketAudit Bucket = "audit"
	// BucketStabilizationResults holds post-recovery verification results.
	BucketStabilizationResults Bucket = "stabilization_results"
	// BucketDeliveryQueue holds durable, not-yet-finalized delivery items.
	BucketDeliveryQueue Bucket = "delivery_queue"
)

var dataBuckets = []Bucket{
	BucketConfigurationVersions,
	BucketIncidents,
	BucketAnalysisReferences,
	BucketApprovals,
	BucketCommandJournal,
	BucketAudit,
	BucketStabilizationResults,
	BucketDeliveryQueue,
}

var allowedBuckets = func() map[Bucket]struct{} {
	buckets := make(map[Bucket]struct{}, len(dataBuckets))
	for _, bucket := range dataBuckets {
		buckets[bucket] = struct{}{}
	}
	return buckets
}()

var (
	metadataBucket   = []byte("metadata")
	schemaVersionKey = []byte("schema_version")
)

// Options controls one daemon-owned store file.
type Options struct {
	// Path is the absolute, clean path to the bbolt data file.
	Path string
	// LockTimeout bounds how long startup waits for another process to release
	// the daemon-owned file.
	LockTimeout time.Duration
	// MaxFileBytes optionally bounds database growth. Zero leaves the size
	// unbounded; a positive value provides a deterministic storage-full guard.
	MaxFileBytes int
}

// Store owns one open bbolt handle. It is intended to be opened only by the
// standalone daemon; administrative clients must use daemon IPC instead.
type Store struct {
	db   *bbolt.DB
	path string
}

// LocalStateStore is the daemon-facing durable-state boundary. Typed command,
// audit, and delivery workflows use its explicit buckets inside one transaction.
type LocalStateStore interface {
	Close() error
	Update(func(*Tx) error) error
	View(func(*Tx) error) error
	SchemaVersion() (uint32, error)
	CheckIntegrity() error
	Backup(io.Writer) error
}

var _ LocalStateStore = (*Store)(nil)

// Tx is a managed read or write transaction over the explicit state buckets.
// Values returned from its methods are copies and remain valid after the
// callback returns.
type Tx struct {
	tx *bbolt.Tx
}

type migration struct {
	from  uint32
	to    uint32
	apply func(*bbolt.Tx) error
}

var defaultMigrations = []migration{
	{from: 0, to: CurrentSchemaVersion, apply: applyInitialMigration},
}

// Open opens a daemon-owned local store, applies supported migrations, and
// verifies its integrity before exposing it to callers.
func Open(options Options) (*Store, error) {
	return openWithMigrations(options, defaultMigrations)
}

func openWithMigrations(options Options, migrations []migration) (*Store, error) {
	if err := validateOptions(options); err != nil {
		return nil, err
	}
	if err := validateDataFile(options.Path, false); err != nil {
		return nil, err
	}

	started := time.Now()
	database, err := bbolt.Open(options.Path, dataFileMode, &bbolt.Options{
		Timeout: options.LockTimeout,
		MaxSize: options.MaxFileBytes,
	})
	if err != nil {
		if errors.Is(err, bbolterrors.ErrTimeout) {
			// bbolt's Unix retry cadence is coarser than a caller may configure.
			// Do not report an ownership timeout before the configured deadline.
			if remaining := options.LockTimeout - time.Since(started); remaining > 0 {
				time.Sleep(remaining)
			}
			return nil, fmt.Errorf("%w: %w", ErrLockTimeout, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrStoreOpen, err)
	}

	store := &Store{db: database, path: options.Path}
	if err := validateDataFile(options.Path, false); err != nil {
		_ = database.Close()
		return nil, err
	}
	if err := store.migrate(migrations); err != nil {
		_ = database.Close()
		return nil, err
	}
	if err := store.CheckIntegrity(); err != nil {
		_ = database.Close()
		return nil, err
	}
	return store, nil
}

// Close releases the daemon-owned lock and closes the local store.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return ErrStoreOpen
	}
	return s.db.Close()
}

// Update runs fn in one managed read-write transaction. Returning an error from
// fn rolls back every write made through the transaction.
func (s *Store) Update(fn func(*Tx) error) error {
	if s == nil || s.db == nil || fn == nil {
		return ErrInvalidTransaction
	}
	return normalizeError(s.db.Update(func(transaction *bbolt.Tx) error {
		return fn(&Tx{tx: transaction})
	}))
}

// View runs fn in one managed read-only transaction.
func (s *Store) View(fn func(*Tx) error) error {
	if s == nil || s.db == nil || fn == nil {
		return ErrInvalidTransaction
	}
	return normalizeError(s.db.View(func(transaction *bbolt.Tx) error {
		return fn(&Tx{tx: transaction})
	}))
}

// SchemaVersion returns the persisted local-state schema version.
func (s *Store) SchemaVersion() (uint32, error) {
	var version uint32
	err := s.View(func(transaction *Tx) error {
		value, err := readSchemaVersion(transaction.tx)
		if err != nil {
			return err
		}
		version = value
		return nil
	})
	return version, err
}

// Put stores a value under key in the selected explicit bucket.
func (tx *Tx) Put(bucket Bucket, key string, value []byte) error {
	databaseBucket, err := tx.bucket(bucket)
	if err != nil {
		return err
	}
	if key == "" {
		return ErrInvalidKey
	}
	return normalizeError(databaseBucket.Put([]byte(key), value))
}

// Get returns a copy of the value for key. found is false when the key does
// not exist.
func (tx *Tx) Get(bucket Bucket, key string) (value []byte, found bool, err error) {
	databaseBucket, err := tx.bucket(bucket)
	if err != nil {
		return nil, false, err
	}
	if key == "" {
		return nil, false, ErrInvalidKey
	}
	value = databaseBucket.Get([]byte(key))
	if value == nil {
		return nil, false, nil
	}
	return cloneBytes(value), true, nil
}

// Delete removes key from the selected explicit bucket.
func (tx *Tx) Delete(bucket Bucket, key string) error {
	databaseBucket, err := tx.bucket(bucket)
	if err != nil {
		return err
	}
	if key == "" {
		return ErrInvalidKey
	}
	return normalizeError(databaseBucket.Delete([]byte(key)))
}

// ForEach calls fn for a stable transaction snapshot of one explicit bucket.
// Both key and value are copied before fn receives them.
func (tx *Tx) ForEach(bucket Bucket, fn func(key string, value []byte) error) error {
	databaseBucket, err := tx.bucket(bucket)
	if err != nil {
		return err
	}
	if fn == nil {
		return ErrInvalidTransaction
	}
	return databaseBucket.ForEach(func(key, value []byte) error {
		return fn(string(key), cloneBytes(value))
	})
}

// CheckIntegrity verifies the bbolt structure and required local-state schema
// without exposing record data in diagnostics.
func (s *Store) CheckIntegrity() error {
	if s == nil || s.db == nil {
		return ErrIntegrity
	}
	err := s.db.View(func(transaction *bbolt.Tx) error {
		version, err := readSchemaVersion(transaction)
		if err != nil {
			return err
		}
		if version != CurrentSchemaVersion {
			return ErrUnsupportedSchema
		}
		if err := ensureDataBuckets(transaction); err != nil {
			return err
		}
		invalid := false
		for err := range transaction.Check() {
			invalid = invalid || err != nil
		}
		if invalid {
			return ErrIntegrity
		}
		return nil
	})
	if err == nil || errors.Is(err, ErrUnsupportedSchema) || errors.Is(err, ErrIntegrity) {
		return err
	}
	return ErrIntegrity
}

// Backup writes a consistent raw bbolt snapshot from a managed read-only
// transaction. The daemon remains the only process with the live file handle.
func (s *Store) Backup(destination io.Writer) error {
	if s == nil || s.db == nil || destination == nil {
		return ErrInvalidOptions
	}
	err := s.db.View(func(transaction *bbolt.Tx) error {
		_, err := transaction.WriteTo(destination)
		return err
	})
	return normalizeError(err)
}

// Restore validates a backup in a temporary file, atomically creates a new
// target state file, and then opens the restored store. It never overwrites an
// existing target.
func Restore(options Options, source io.Reader) (*Store, error) {
	if source == nil {
		return nil, ErrInvalidOptions
	}
	if err := validateOptions(options); err != nil {
		return nil, err
	}
	if err := validateDataFile(options.Path, true); err != nil {
		return nil, err
	}

	temporary, err := os.CreateTemp(filepath.Dir(options.Path), "."+filepath.Base(options.Path)+".restore-*")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRestore, err)
	}
	temporaryPath := temporary.Name()
	cleanupTemporary := true
	defer func() {
		if cleanupTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(dataFileMode); err != nil {
		_ = temporary.Close()
		return nil, fmt.Errorf("%w: %w", ErrRestore, err)
	}
	written, copyErr := io.Copy(temporary, source)
	if syncErr := temporary.Sync(); copyErr == nil {
		copyErr = syncErr
	}
	if closeErr := temporary.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil || written == 0 {
		if copyErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrRestore, normalizeError(copyErr))
		}
		return nil, ErrRestore
	}

	temporaryOptions := options
	temporaryOptions.Path = temporaryPath
	restored, err := openWithMigrations(temporaryOptions, defaultMigrations)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRestore, err)
	}
	if err := restored.Close(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRestore, err)
	}
	if err := os.Link(temporaryPath, options.Path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, ErrRestoreTargetExists
		}
		return nil, fmt.Errorf("%w: %w", ErrRestore, err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRestore, err)
	}
	cleanupTemporary = false

	return Open(options)
}

func (s *Store) migrate(migrations []migration) error {
	target, err := migrationTarget(migrations)
	if err != nil {
		return err
	}
	err = s.db.Update(func(transaction *bbolt.Tx) error {
		version, err := readSchemaVersion(transaction)
		if err != nil {
			return err
		}
		if version > target {
			return ErrUnsupportedSchema
		}
		for version < target {
			next, err := nextMigration(migrations, version)
			if err != nil {
				return err
			}
			if err := next.apply(transaction); err != nil {
				return err
			}
			if err := writeSchemaVersion(transaction, next.to); err != nil {
				return err
			}
			version = next.to
		}
		return ensureDataBuckets(transaction)
	})
	return normalizeError(err)
}

func validateOptions(options Options) error {
	if options.Path == "" || !filepath.IsAbs(options.Path) || filepath.Clean(options.Path) != options.Path || options.LockTimeout <= 0 || options.MaxFileBytes < 0 {
		return ErrInvalidOptions
	}
	parent, err := os.Stat(filepath.Dir(options.Path))
	if err != nil || !parent.IsDir() {
		return ErrInvalidOptions
	}
	return nil
}

func validateDataFile(path string, mustNotExist bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrStoreOpen
	}
	if mustNotExist {
		return ErrRestoreTargetExists
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&^dataFileMode != 0 {
		return ErrInsecureDataFile
	}
	return nil
}

func (tx *Tx) bucket(bucket Bucket) (*bbolt.Bucket, error) {
	if tx == nil || tx.tx == nil {
		return nil, ErrInvalidTransaction
	}
	if _, allowed := allowedBuckets[bucket]; !allowed {
		return nil, ErrUnknownBucket
	}
	databaseBucket := tx.tx.Bucket([]byte(bucket))
	if databaseBucket == nil {
		return nil, ErrIntegrity
	}
	return databaseBucket, nil
}

func migrationTarget(migrations []migration) (uint32, error) {
	if len(migrations) == 0 {
		return 0, ErrUnsupportedSchema
	}
	var target uint32
	for _, candidate := range migrations {
		if candidate.apply == nil || candidate.to <= candidate.from {
			return 0, ErrUnsupportedSchema
		}
		if candidate.to > target {
			target = candidate.to
		}
	}
	return target, nil
}

func nextMigration(migrations []migration, version uint32) (migration, error) {
	var next migration
	found := false
	for _, candidate := range migrations {
		if candidate.from != version {
			continue
		}
		if found {
			return migration{}, ErrUnsupportedSchema
		}
		next = candidate
		found = true
	}
	if !found || next.to <= version || next.apply == nil {
		return migration{}, ErrUnsupportedSchema
	}
	return next, nil
}

func applyInitialMigration(transaction *bbolt.Tx) error {
	if _, err := transaction.CreateBucketIfNotExists(metadataBucket); err != nil {
		return err
	}
	for _, bucket := range dataBuckets {
		if _, err := transaction.CreateBucketIfNotExists([]byte(bucket)); err != nil {
			return err
		}
	}
	return nil
}

func readSchemaVersion(transaction *bbolt.Tx) (uint32, error) {
	metadata := transaction.Bucket(metadataBucket)
	if metadata == nil {
		empty := true
		if err := transaction.ForEach(func(_ []byte, _ *bbolt.Bucket) error {
			empty = false
			return ErrIntegrity
		}); err != nil {
			return 0, err
		}
		if empty {
			return 0, nil
		}
		return 0, ErrIntegrity
	}
	encoded := metadata.Get(schemaVersionKey)
	if len(encoded) != 4 {
		return 0, ErrIntegrity
	}
	return uint32(encoded[0])<<24 | uint32(encoded[1])<<16 | uint32(encoded[2])<<8 | uint32(encoded[3]), nil
}

func writeSchemaVersion(transaction *bbolt.Tx, version uint32) error {
	metadata := transaction.Bucket(metadataBucket)
	if metadata == nil || version == 0 {
		return ErrIntegrity
	}
	encoded := []byte{byte(version >> 24), byte(version >> 16), byte(version >> 8), byte(version)}
	return metadata.Put(schemaVersionKey, encoded)
}

func ensureDataBuckets(transaction *bbolt.Tx) error {
	for _, bucket := range dataBuckets {
		if transaction.Bucket([]byte(bucket)) == nil {
			return ErrIntegrity
		}
	}
	return nil
}

func normalizeError(err error) error {
	if err == nil || errors.Is(err, ErrStoreFull) || errors.Is(err, ErrLockTimeout) {
		return err
	}
	if errors.Is(err, bbolterrors.ErrMaxSizeReached) || errors.Is(err, syscall.ENOSPC) {
		return fmt.Errorf("%w: %w", ErrStoreFull, err)
	}
	return err
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	copied := make([]byte, len(value))
	copy(copied, value)
	return copied
}
