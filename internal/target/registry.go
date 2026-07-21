// Package target owns durable, validated monitoring-target registration.
package target

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"pulse-agent/internal/audit"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
)

const (
	// SchemaVersion is the ServiceTarget registration contract version.
	SchemaVersion = contract.SchemaVersionV1

	maxTargets       = 10_000
	maxTargetIDBytes = 96
	maxProbeRules    = 64
	maxDuration      = 24 * time.Hour
	maxSamples       = 100

	auditAggregateType   = "service_target"
	auditAction          = "target.register"
	auditResultAccepted  = "accepted"
	auditResultRejected  = "rejected"
	auditReasonInvalid   = "invalid_target"
	auditReasonDuplicate = "duplicate_target"
	auditReasonLimit     = "target_limit_reached"
)

var (
	// ErrInvalidOptions indicates registry dependencies or bounds that cannot
	// safely enforce daemon-owned target registration.
	ErrInvalidOptions = errors.New("invalid target registry options")
	// ErrInvalidTarget indicates a target document outside the supported local
	// target contract.
	ErrInvalidTarget = errors.New("invalid service target")
	// ErrUnknownAdapter indicates an adapter not allowed for the target by the
	// daemon configuration.
	ErrUnknownAdapter = errors.New("unknown target adapter")
	// ErrTargetNotAllowed indicates a target ID that the daemon configuration
	// did not authorize.
	ErrTargetNotAllowed = errors.New("target is not allowed")
	// ErrDuplicateTarget indicates an attempt to register an existing target ID.
	ErrDuplicateTarget = errors.New("duplicate service target")
	// ErrTargetLimit indicates a configured maximum number of targets.
	ErrTargetLimit = errors.New("service target limit reached")
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
	selectorPattern   = regexp.MustCompile(`^(container|compose_service):[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
)

// AllowedTarget identifies one configuration-authorized target ID and adapter.
type AllowedTarget struct {
	// TargetID is the stable configured target identity.
	TargetID string
	// AdapterType is the only adapter this target may use.
	AdapterType string
}

// Options configures a daemon-owned target registry.
type Options struct {
	// State is the only durable state handle used by the registry.
	State *store.Store
	// AllowedTargets is the closed configuration allowlist for target IDs.
	AllowedTargets []AllowedTarget
	// MaxTargets bounds the total number of persisted targets.
	MaxTargets int
	// MaxEvidenceBytes bounds one target's evidence policy.
	MaxEvidenceBytes int64
	// Clock supplies audit timestamps and must return a non-zero time.
	Clock func() time.Time
	// NewAuditEventID supplies unique, audit-safe event IDs.
	NewAuditEventID func() (string, error)
}

// Registration supplies all caller-controlled context for one audited target
// registration. The registry owns validation, persistence, and audit append.
type Registration struct {
	// Target is the versioned target submitted by an authenticated local peer.
	Target contract.ServiceTarget
	// ActorIdentity is the authenticated peer identity, never caller-supplied CLI text.
	ActorIdentity string
	// RequestID correlates the local IPC request with its durable audit event.
	RequestID string
	// ReasonCode is the bounded administrative reason attached to the audit event.
	ReasonCode string
}

// Snapshot is an immutable-at-the-boundary versioned target view for observers.
// Every method returns a deep copy, so callers cannot mutate registry state.
type Snapshot struct {
	// SchemaVersion is the snapshot contract version.
	SchemaVersion string `json:"schema_version"`
	// Version increases after every successful target registration.
	Version uint64 `json:"version"`
	// Targets is sorted by target ID and deep-copied at the API boundary.
	Targets []contract.ServiceTarget `json:"targets"`
}

// RegistrationResult is the bounded response returned to an administrative
// client after the daemon commits one target registration.
type RegistrationResult struct {
	// SchemaVersion is the result contract version.
	SchemaVersion string `json:"schema_version"`
	// Version is the registry snapshot version after the committed registration.
	Version uint64 `json:"version"`
	// TargetID identifies the newly registered target without returning the
	// complete observer snapshot over the bounded IPC response.
	TargetID string `json:"target_id"`
}

// TargetRegistry is the daemon-facing target registration and observer boundary.
type TargetRegistry interface {
	Register(Registration) (Snapshot, error)
	Snapshot() Snapshot
}

// Registry validates, persists, audits, and exposes immutable target snapshots.
// Its zero value is not valid; construct it with NewRegistry.
type Registry struct {
	state            *store.Store
	allowedTargets   map[string]string
	maxTargets       int
	maxEvidenceBytes int64
	clock            func() time.Time
	newAuditEventID  func() (string, error)

	mu       sync.RWMutex
	snapshot Snapshot
}

type persistedTarget struct {
	SchemaVersion string                 `json:"schema_version"`
	Version       uint64                 `json:"version"`
	Target        contract.ServiceTarget `json:"target"`
}

// NewRegistry validates its dependencies and recovers the immutable snapshot
// from the daemon-owned store before accepting registrations.
func NewRegistry(options Options) (*Registry, error) {
	allowedTargets, err := allowedTargetMap(options.AllowedTargets)
	if err != nil || options.State == nil || options.MaxTargets < 1 || options.MaxTargets > maxTargets || options.MaxEvidenceBytes < 1 || options.Clock == nil || options.NewAuditEventID == nil {
		return nil, ErrInvalidOptions
	}
	registry := &Registry{
		state:            options.State,
		allowedTargets:   allowedTargets,
		maxTargets:       options.MaxTargets,
		maxEvidenceBytes: options.MaxEvidenceBytes,
		clock:            options.Clock,
		newAuditEventID:  options.NewAuditEventID,
		snapshot: Snapshot{
			SchemaVersion: SchemaVersion,
			Targets:       []contract.ServiceTarget{},
		},
	}
	if err := registry.load(); err != nil {
		return nil, err
	}
	return registry, nil
}

// Register validates target before persistence, then atomically records either
// the target mutation and accepted audit event or a rejected audit result.
func (r *Registry) Register(registration Registration) (Snapshot, error) {
	if r == nil || !validRegistrationContext(registration) {
		return Snapshot{}, ErrInvalidOptions
	}
	if err := r.validateTarget(registration.Target); err != nil {
		if auditErr := r.recordRejected(registration, auditAggregateID(registration.Target.TargetID), auditReasonInvalid); auditErr != nil {
			return r.Snapshot(), auditErr
		}
		return r.Snapshot(), err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	var registrationErr error
	err := r.state.Update(func(transaction *store.Tx) error {
		if _, found, err := transaction.Get(store.BucketServiceTargets, registration.Target.TargetID); err != nil {
			return err
		} else if found {
			registrationErr = ErrDuplicateTarget
			return r.appendAudit(transaction, registration, auditAggregateID(registration.Target.TargetID), auditResultRejected, auditReasonDuplicate, nil)
		}
		if len(r.snapshot.Targets) >= r.maxTargets {
			registrationErr = ErrTargetLimit
			return r.appendAudit(transaction, registration, auditAggregateID(registration.Target.TargetID), auditResultRejected, auditReasonLimit, nil)
		}

		nextVersion := r.snapshot.Version + 1
		document, err := encodePersistedTarget(persistedTarget{
			SchemaVersion: SchemaVersion,
			Version:       nextVersion,
			Target:        cloneTarget(registration.Target),
		})
		if err != nil {
			return err
		}
		return r.appendAudit(transaction, registration, auditAggregateID(registration.Target.TargetID), auditResultAccepted, registration.ReasonCode, func(transaction *store.Tx) error {
			return transaction.Put(store.BucketServiceTargets, registration.Target.TargetID, document)
		})
	})
	if err != nil {
		return cloneSnapshot(r.snapshot), err
	}
	if registrationErr != nil {
		return cloneSnapshot(r.snapshot), registrationErr
	}

	targets := append(cloneTargets(r.snapshot.Targets), cloneTarget(registration.Target))
	sort.Slice(targets, func(left, right int) bool { return targets[left].TargetID < targets[right].TargetID })
	r.snapshot = Snapshot{
		SchemaVersion: SchemaVersion,
		Version:       r.snapshot.Version + 1,
		Targets:       targets,
	}
	return cloneSnapshot(r.snapshot), nil
}

// Snapshot returns a deep-copied versioned target view suitable for observers.
func (r *Registry) Snapshot() Snapshot {
	if r == nil {
		return Snapshot{SchemaVersion: SchemaVersion, Targets: []contract.ServiceTarget{}}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneSnapshot(r.snapshot)
}

// Decode strictly decodes one target document before it enters the local IPC
// request. Daemon-side registration applies configuration-bound validation.
func Decode(document []byte) (contract.ServiceTarget, error) {
	target, err := contract.Decode(document, contract.DecodeOptions[contract.ServiceTarget]{
		MaxBytes:      contract.MaxDocumentBytes,
		SchemaVersion: SchemaVersion,
		Validate: func(value contract.ServiceTarget) error {
			if value.SchemaVersion != SchemaVersion {
				return ErrInvalidTarget
			}
			return nil
		},
	})
	if err != nil {
		return contract.ServiceTarget{}, ErrInvalidTarget
	}
	return target, nil
}

// Load reads one bounded target document without opening daemon state or
// resolving any secret source.
func Load(path string) (contract.ServiceTarget, error) {
	file, err := os.Open(path)
	if err != nil {
		return contract.ServiceTarget{}, ErrInvalidTarget
	}
	document, readErr := io.ReadAll(io.LimitReader(file, contract.MaxDocumentBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(document) > contract.MaxDocumentBytes {
		return contract.ServiceTarget{}, ErrInvalidTarget
	}
	return Decode(document)
}

// NewAuditEventID returns a random audit-safe target registration event ID.
func NewAuditEventID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "target-" + hex.EncodeToString(random[:]), nil
}

func (r *Registry) load() error {
	loaded := Snapshot{SchemaVersion: SchemaVersion, Targets: []contract.ServiceTarget{}}
	err := r.state.View(func(transaction *store.Tx) error {
		return transaction.ForEach(store.BucketServiceTargets, func(key string, document []byte) error {
			record, err := decodePersistedTarget(document)
			if err != nil || key != record.Target.TargetID || record.Version == 0 {
				return ErrInvalidTarget
			}
			if err := r.validateTarget(record.Target); err != nil {
				return err
			}
			loaded.Targets = append(loaded.Targets, cloneTarget(record.Target))
			if record.Version > loaded.Version {
				loaded.Version = record.Version
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	if len(loaded.Targets) > r.maxTargets {
		return ErrTargetLimit
	}
	sort.Slice(loaded.Targets, func(left, right int) bool { return loaded.Targets[left].TargetID < loaded.Targets[right].TargetID })
	r.snapshot = cloneSnapshot(loaded)
	return nil
}

func (r *Registry) recordRejected(registration Registration, aggregateID, reason string) error {
	return r.state.Update(func(transaction *store.Tx) error {
		return r.appendAudit(transaction, registration, aggregateID, auditResultRejected, reason, nil)
	})
}

func (r *Registry) appendAudit(transaction *store.Tx, registration Registration, aggregateID, result, reason string, change audit.Mutation) error {
	eventID, err := r.newAuditEventID()
	if err != nil {
		return err
	}
	occurredAt := r.clock()
	if occurredAt.IsZero() {
		return ErrInvalidOptions
	}
	_, err = audit.Append(transaction, contract.AuditEvent{
		SchemaVersion: SchemaVersion,
		EventID:       eventID,
		AggregateType: auditAggregateType,
		AggregateID:   aggregateID,
		ActorIdentity: registration.ActorIdentity,
		Action:        auditAction,
		Result:        result,
		ReasonCode:    reason,
		OccurredAt:    occurredAt,
	}, change)
	return err
}

func (r *Registry) validateTarget(candidate contract.ServiceTarget) error {
	if candidate.SchemaVersion != SchemaVersion || !validIdentifier(candidate.TargetID) {
		return ErrInvalidTarget
	}
	allowedAdapter, allowed := r.allowedTargets[candidate.TargetID]
	if !allowed {
		return ErrTargetNotAllowed
	}
	if candidate.AdapterType != allowedAdapter || candidate.AdapterType != "docker" {
		return ErrUnknownAdapter
	}
	if !selectorPattern.MatchString(candidate.Selector) || strings.Contains(candidate.Selector, "..") {
		return ErrInvalidTarget
	}
	if len(candidate.ProbeRules) == 0 || len(candidate.ProbeRules) > maxProbeRules {
		return ErrInvalidTarget
	}
	seenRules := make(map[string]struct{}, len(candidate.ProbeRules))
	for _, rule := range candidate.ProbeRules {
		if err := validateProbeRule(rule); err != nil {
			return err
		}
		if _, duplicate := seenRules[rule.RuleID]; duplicate {
			return ErrInvalidTarget
		}
		seenRules[rule.RuleID] = struct{}{}
	}
	if (candidate.EvidencePolicy.RedactionProfile != "default" && candidate.EvidencePolicy.RedactionProfile != "strict") || candidate.EvidencePolicy.MaxBytes < 1 || int64(candidate.EvidencePolicy.MaxBytes) > r.maxEvidenceBytes {
		return ErrInvalidTarget
	}
	if candidate.StabilizationPolicy.RecoverySamples < 1 || candidate.StabilizationPolicy.RecoverySamples > maxSamples || candidate.StabilizationPolicy.Window.Value() < time.Second || candidate.StabilizationPolicy.Window.Value() > maxDuration {
		return ErrInvalidTarget
	}
	return nil
}

func validateProbeRule(rule contract.ProbeRule) error {
	if !validIdentifier(rule.RuleID) || (rule.SignalType != "availability" && rule.SignalType != "error_rate" && rule.SignalType != "latency_ms") || rule.Interval.Value() < time.Second || rule.Interval.Value() > time.Hour || rule.Timeout.Value() < time.Millisecond || rule.Timeout.Value() > rule.Interval.Value() || math.IsNaN(rule.Threshold) || math.IsInf(rule.Threshold, 0) || rule.Threshold <= 0 || rule.Threshold > 1_000_000 || rule.ConsecutiveFailures < 1 || rule.ConsecutiveFailures > maxSamples || rule.RecoverySamples < 1 || rule.RecoverySamples > maxSamples || rule.SLOWindow.Value() < rule.Interval.Value() || rule.SLOWindow.Value() > maxDuration {
		return ErrInvalidTarget
	}
	if rule.Severity != contract.SeverityInfo && rule.Severity != contract.SeverityWarning && rule.Severity != contract.SeverityCritical {
		return ErrInvalidTarget
	}
	return nil
}

func allowedTargetMap(targets []AllowedTarget) (map[string]string, error) {
	allowed := make(map[string]string, len(targets))
	for _, candidate := range targets {
		if !validIdentifier(candidate.TargetID) || candidate.AdapterType != "docker" {
			return nil, ErrInvalidOptions
		}
		if _, duplicate := allowed[candidate.TargetID]; duplicate {
			return nil, ErrInvalidOptions
		}
		allowed[candidate.TargetID] = candidate.AdapterType
	}
	return allowed, nil
}

func validRegistrationContext(registration Registration) bool {
	return validAuditValue(registration.ActorIdentity) && validAuditValue(registration.RequestID) && validAuditValue(registration.ReasonCode)
}

func validAuditValue(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case strings.ContainsRune("._-:/@", character):
		default:
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool {
	return len(value) <= maxTargetIDBytes && identifierPattern.MatchString(value) && !strings.Contains(value, "..")
}

func auditAggregateID(targetID string) string {
	if validIdentifier(targetID) {
		return targetID
	}
	return "target-unknown"
}

func encodePersistedTarget(record persistedTarget) ([]byte, error) {
	return json.Marshal(record)
}

func decodePersistedTarget(document []byte) (persistedTarget, error) {
	record, err := contract.Decode(document, contract.DecodeOptions[persistedTarget]{
		MaxBytes:      contract.MaxDocumentBytes,
		SchemaVersion: SchemaVersion,
		Validate: func(value persistedTarget) error {
			if value.SchemaVersion != SchemaVersion || value.Target.SchemaVersion != SchemaVersion {
				return ErrInvalidTarget
			}
			return nil
		},
	})
	if err != nil {
		return persistedTarget{}, ErrInvalidTarget
	}
	return record, nil
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	return Snapshot{
		SchemaVersion: snapshot.SchemaVersion,
		Version:       snapshot.Version,
		Targets:       cloneTargets(snapshot.Targets),
	}
}

func cloneTargets(targets []contract.ServiceTarget) []contract.ServiceTarget {
	cloned := make([]contract.ServiceTarget, len(targets))
	for index, candidate := range targets {
		cloned[index] = cloneTarget(candidate)
	}
	return cloned
}

func cloneTarget(candidate contract.ServiceTarget) contract.ServiceTarget {
	cloned := candidate
	cloned.ProbeRules = append([]contract.ProbeRule(nil), candidate.ProbeRules...)
	return cloned
}
