// Package runbook validates and durably registers typed recovery runbook pairs.
package runbook

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"pulse-agent/internal/audit"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
)

// SchemaVersion is the version accepted for typed runbook contracts.
const SchemaVersion = contract.SchemaVersionV1

var (
	// ErrInvalidPair indicates an unsafe or malformed runbook pair.
	ErrInvalidPair = errors.New("invalid runbook pair")
	// ErrDuplicate indicates a runbook ID already exists in daemon-owned state.
	ErrDuplicate = errors.New("duplicate runbook")
	// ErrInvalidOpts indicates missing runbook registry dependencies.
	ErrInvalidOpts = errors.New("invalid runbook registry options")
)

var metadataPattern = regexp.MustCompile(`^\s*(runbook_id|version)\s*:\s*([A-Za-z0-9._-]+)\s*$`)

// Pair is one validated documentation and executable-contract pair.
type Pair struct {
	Runbook contract.Runbook
	Digest  string
}

// Registration supplies authenticated daemon-owned registration context.
type Registration struct {
	Pair          Pair
	ActorIdentity string
	RequestID     string
	ReasonCode    string
}

// RegistrationResult is the bounded daemon response after persistence.
type RegistrationResult struct {
	SchemaVersion string `json:"schema_version"`
	RunbookID     string `json:"runbook_id"`
	Digest        string `json:"digest"`
}

// Options configures a daemon-owned runbook registry.
type Options struct {
	// State is the daemon-owned persistent state handle.
	State *store.Store
	// Clock supplies audit timestamps.
	Clock func() time.Time
	// NewAuditEventID supplies unique audit event IDs.
	NewAuditEventID func() (string, error)
}

// Registry validates, persists, and audits typed recovery runbooks.
type Registry struct {
	state *store.Store
	clock func() time.Time
	newID func() (string, error)
	mu    sync.Mutex
}

// NewRegistry validates daemon-owned dependencies.
func NewRegistry(options Options) (*Registry, error) {
	if options.State == nil || options.Clock == nil || options.NewAuditEventID == nil {
		return nil, ErrInvalidOpts
	}
	return &Registry{state: options.State, clock: options.Clock, newID: options.NewAuditEventID}, nil
}

// Load reads only the exact runbook.md and runbook.json children of directory.
func Load(directory string) (Pair, error) {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return Pair{}, ErrInvalidPair
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Pair{}, ErrInvalidPair
	}
	markdown, err := readRegular(filepath.Join(directory, "runbook.md"))
	if err != nil {
		return Pair{}, ErrInvalidPair
	}
	document, err := readRegular(filepath.Join(directory, "runbook.json"))
	if err != nil {
		return Pair{}, ErrInvalidPair
	}
	return Decode(markdown, document)
}

// Decode strictly validates a pair already read from a trusted bounded source.
func Decode(markdown, document []byte) (Pair, error) {
	if len(markdown) == 0 || len(markdown) > contract.MaxDocumentBytes || len(document) == 0 || len(document) > contract.MaxDocumentBytes {
		return Pair{}, ErrInvalidPair
	}
	runbook, err := contract.Decode(document, contract.DecodeOptions[contract.Runbook]{
		MaxBytes: contract.MaxDocumentBytes, SchemaVersion: SchemaVersion, Validate: validateRunbook,
	})
	if err != nil {
		return Pair{}, ErrInvalidPair
	}
	metadata, validMetadata := markdownMetadata(string(markdown))
	if !validMetadata || metadata["runbook_id"] != runbook.RunbookID || metadata["version"] != runbook.Version {
		return Pair{}, ErrInvalidPair
	}
	digest, err := Digest(runbook)
	if err != nil || (runbook.Digest != "" && runbook.Digest != digest) {
		return Pair{}, ErrInvalidPair
	}
	runbook.Digest = digest
	return Pair{Runbook: runbook, Digest: digest}, nil
}

// Digest computes the canonical digest for one already strict-decoded runbook.
func Digest(value contract.Runbook) (string, error) {
	value.Digest = ""
	document, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalidPair
	}
	return CanonicalDigest(document)
}

// CanonicalDigest computes the SHA-256 digest of the strict JSON contract with
// its derived digest field omitted.
func CanonicalDigest(document []byte) (string, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(document, &object); err != nil {
		return "", ErrInvalidPair
	}
	delete(object, "digest")
	canonical, err := json.Marshal(object)
	if err != nil {
		return "", ErrInvalidPair
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// Register atomically persists a valid runbook and its accepted audit event.
func (r *Registry) Register(registration Registration) (RegistrationResult, error) {
	digest, digestErr := Digest(registration.Pair.Runbook)
	if r == nil || !validContext(registration) || digestErr != nil || validateRunbook(registration.Pair.Runbook) != nil || registration.Pair.Digest == "" || registration.Pair.Digest != digest || registration.Pair.Runbook.Digest != registration.Pair.Digest {
		return RegistrationResult{}, ErrInvalidOpts
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var duplicate bool
	err := r.state.Update(func(tx *store.Tx) error {
		if _, found, err := tx.Get(store.BucketRunbooks, registration.Pair.Runbook.RunbookID); err != nil {
			return err
		} else if found {
			duplicate = true
			return r.appendAudit(tx, registration, "rejected", "duplicate_runbook", nil)
		}
		document, err := json.Marshal(registration.Pair.Runbook)
		if err != nil {
			return err
		}
		return r.appendAudit(tx, registration, "accepted", registration.ReasonCode, func(tx *store.Tx) error {
			return tx.Put(store.BucketRunbooks, registration.Pair.Runbook.RunbookID, document)
		})
	})
	if err != nil {
		return RegistrationResult{}, err
	}
	if duplicate {
		return RegistrationResult{}, ErrDuplicate
	}
	return RegistrationResult{SchemaVersion: SchemaVersion, RunbookID: registration.Pair.Runbook.RunbookID, Digest: registration.Pair.Digest}, nil
}

// NewAuditEventID returns a random audit-safe runbook registration event ID.
func NewAuditEventID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "runbook-" + hex.EncodeToString(random[:]), nil
}

func (r *Registry) appendAudit(tx *store.Tx, registration Registration, result, reason string, change audit.Mutation) error {
	id, err := r.newID()
	if err != nil {
		return err
	}
	now := r.clock()
	if now.IsZero() {
		return ErrInvalidOpts
	}
	_, err = audit.Append(tx, contract.AuditEvent{SchemaVersion: SchemaVersion, EventID: id, AggregateType: "runbook", AggregateID: registration.Pair.Runbook.RunbookID, ActorIdentity: registration.ActorIdentity, Action: "runbook.register", Result: result, ReasonCode: reason, OccurredAt: now}, change)
	return err
}

func readRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidPair
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	document, readErr := io.ReadAll(io.LimitReader(file, contract.MaxDocumentBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(document) > contract.MaxDocumentBytes {
		return nil, ErrInvalidPair
	}
	latest, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, latest) || !latest.Mode().IsRegular() {
		return nil, ErrInvalidPair
	}
	return document, nil
}

func markdownMetadata(markdown string) (map[string]string, bool) {
	lines := strings.Split(markdown, "\n")
	if len(lines) < 4 || strings.TrimSpace(lines[0]) != "---" {
		return nil, false
	}
	values := make(map[string]string)
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "---" {
			return values, true
		}
		match := metadataPattern.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}
		if _, duplicate := values[match[1]]; duplicate {
			return nil, false
		}
		values[match[1]] = match[2]
	}
	return nil, false
}

func validateRunbook(value contract.Runbook) error {
	if value.SchemaVersion != SchemaVersion || !validCode(value.RunbookID) || !validCode(value.Version) || value.AdapterType != "docker" || len(value.TypedActions) == 0 || len(value.TypedActions) > 64 || (value.RiskTier != contract.RiskLow && value.RiskTier != contract.RiskMedium && value.RiskTier != contract.RiskHigh) || value.RetryPolicy.MaxAttempts < 1 || value.RetryPolicy.MaxAttempts > 10 {
		return ErrInvalidPair
	}
	for _, action := range value.TypedActions {
		if (action.ActionType != contract.ActionDockerContainerRestart && action.ActionType != contract.ActionDockerComposeServiceRestart) || !strings.HasPrefix(action.TargetSelector, "container:") && !strings.HasPrefix(action.TargetSelector, "compose_service:") || strings.Contains(action.TargetSelector, "..") || action.StopTimeout.Value() <= 0 || action.Cooldown.Value() < 0 {
			return ErrInvalidPair
		}
	}
	return nil
}

func validContext(value Registration) bool {
	return validCode(value.ActorIdentity) && validCode(value.RequestID) && validCode(value.ReasonCode)
}
func validCode(value string) bool {
	return value != "" && len(value) <= 128 && !strings.Contains(value, "..")
}
