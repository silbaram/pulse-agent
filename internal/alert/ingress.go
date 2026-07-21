// Package alert implements authenticated, normalized external alert ingress.
package alert

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"pulse-agent/internal/audit"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
	"pulse-agent/internal/target"
	"pulse-agent/internal/webhook"
)

const (
	defaultMaxBodyBytes = 64 * 1024
	defaultTimeout      = 5 * time.Second
	defaultRetention    = 24 * time.Hour
	maxValues           = 16
	maxValue            = 1_000_000.0
)

var (
	// ErrInvalidOptions indicates an unsafe or incomplete ingress configuration.
	ErrInvalidOptions = errors.New("invalid alert ingress options")
	// ErrReplay indicates an already accepted webhook ID.
	ErrReplay = errors.New("replayed webhook")
	// ErrInvalidAlert indicates malformed or unknown normalized alert input.
	ErrInvalidAlert = errors.New("invalid normalized alert")
)

// TargetSource supplies immutable registered target snapshots.
type TargetSource interface {
	Snapshot() target.Snapshot
}

// Options configures one daemon-owned alert ingress boundary.
type Options struct {
	// State persists replay receipts and rejected-input audit events.
	State *store.Store
	// Targets resolves the registered target and rule for an incoming alert.
	Targets TargetSource
	// Keyring verifies Standard Webhooks v1 signatures.
	Keyring *webhook.Keyring
	// Clock supplies the verification and retention time.
	Clock func() time.Time
	// NewObservationID creates one observation identifier for accepted input.
	NewObservationID func() (string, error)
	// NewAuditEventID creates one audit-chain event identifier for rejected input.
	NewAuditEventID func() (string, error)
	// MaxBodyBytes bounds raw request bodies and defaults to 64 KiB.
	MaxBodyBytes int
	// Timeout bounds the request-scoped verification and normalization work.
	Timeout time.Duration
	// Retention bounds the persisted replay-receipt lifetime.
	Retention time.Duration
}

// Normalized contains safe alert identity metadata and one observation. It
// intentionally excludes raw request bodies and evidence references.
type Normalized struct {
	// Source identifies the external alert producer.
	Source string
	// ExternalAlertID identifies the source alert for downstream correlation.
	ExternalAlertID string
	// Observation contains only bounded, trusted normalized fields.
	Observation contract.HealthObservation
}

// Ingress authenticates raw alert bytes before strict decoding and replay storage.
type Ingress struct {
	state              *store.Store
	targets            TargetSource
	keyring            *webhook.Keyring
	clock              func() time.Time
	newID              func() (string, error)
	newAuditID         func() (string, error)
	maxBody            int
	timeout, retention time.Duration
}

// NewIngress validates daemon-owned dependencies and safe limits.
func NewIngress(options Options) (*Ingress, error) {
	maxBody := options.MaxBodyBytes
	if maxBody == 0 {
		maxBody = defaultMaxBodyBytes
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	retention := options.Retention
	if retention == 0 {
		retention = defaultRetention
	}
	if options.State == nil || options.Targets == nil || options.Keyring == nil || options.Clock == nil || options.NewObservationID == nil || options.NewAuditEventID == nil || maxBody < 1 || maxBody > defaultMaxBodyBytes || timeout < time.Millisecond || retention < time.Minute {
		return nil, ErrInvalidOptions
	}
	return &Ingress{
		state:      options.State,
		targets:    options.Targets,
		keyring:    options.Keyring,
		clock:      options.Clock,
		newID:      options.NewObservationID,
		newAuditID: options.NewAuditEventID,
		maxBody:    maxBody,
		timeout:    timeout,
		retention:  retention,
	}, nil
}

// ServeHTTP accepts only signed JSON POST requests and never echoes untrusted input.
func (i *Ingress) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if i == nil || request.Method != http.MethodPost || !isJSON(request.Header.Get("Content-Type")) {
		http.Error(response, "invalid request", http.StatusBadRequest)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, int64(i.maxBody))
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(response, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), i.timeout)
	defer cancel()
	_, err = i.Accept(ctx, webhook.Headers{ID: request.Header.Get(webhook.HeaderID), Timestamp: request.Header.Get(webhook.HeaderTimestamp), Signature: request.Header.Get(webhook.HeaderSignature)}, raw)
	if err != nil {
		http.Error(response, "alert rejected", http.StatusUnauthorized)
		return
	}
	response.WriteHeader(http.StatusAccepted)
}

// Accept verifies the exact raw request before JSON parsing, records its ID
// transactionally for replay protection, and returns a secret-free normalized alert.
func (i *Ingress) Accept(ctx context.Context, headers webhook.Headers, raw []byte) (Normalized, error) {
	if i == nil || ctx == nil || len(raw) == 0 || len(raw) > i.maxBody {
		return Normalized{}, ErrInvalidAlert
	}
	if err := ctx.Err(); err != nil {
		return Normalized{}, err
	}
	now := i.clock()
	if now.IsZero() {
		return Normalized{}, ErrInvalidOptions
	}
	if err := i.keyring.Verify(headers, raw, now); err != nil {
		if auditErr := i.recordRejected(now, "invalid_signature"); auditErr != nil {
			return Normalized{}, auditErr
		}
		return Normalized{}, err
	}
	if err := ctx.Err(); err != nil {
		return Normalized{}, err
	}
	decoded, err := decode(raw)
	if err != nil {
		if auditErr := i.recordRejected(now, "invalid_payload"); auditErr != nil {
			return Normalized{}, auditErr
		}
		return Normalized{}, err
	}
	normalized, err := i.normalize(decoded, now)
	if err != nil {
		if auditErr := i.recordRejected(now, "unknown_target_or_rule"); auditErr != nil {
			return Normalized{}, auditErr
		}
		return Normalized{}, err
	}
	receiptDocument, err := json.Marshal(receipt{ExpiresAt: now.Add(i.retention)})
	if err != nil {
		return Normalized{}, ErrInvalidAlert
	}
	err = i.state.Update(func(tx *store.Tx) error {
		expired := make([]string, 0)
		if err := tx.ForEach(store.BucketIngressReceipts, func(key string, value []byte) error {
			var old receipt
			if json.Unmarshal(value, &old) != nil || old.ExpiresAt.IsZero() {
				return ErrInvalidAlert
			}
			if !old.ExpiresAt.After(now) {
				expired = append(expired, key)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, key := range expired {
			if err := tx.Delete(store.BucketIngressReceipts, key); err != nil {
				return err
			}
		}
		if _, found, err := tx.Get(store.BucketIngressReceipts, headers.ID); err != nil {
			return err
		} else if found {
			return ErrReplay
		}
		return tx.Put(store.BucketIngressReceipts, headers.ID, receiptDocument)
	})
	if err != nil {
		return Normalized{}, err
	}
	return normalized, nil
}

func (i *Ingress) recordRejected(now time.Time, reason string) error {
	eventID, err := i.newAuditID()
	if err != nil {
		return err
	}
	return i.state.Update(func(tx *store.Tx) error {
		_, err := audit.Append(tx, contract.AuditEvent{
			SchemaVersion: contract.SchemaVersionV1,
			EventID:       eventID,
			AggregateType: "alert_ingress",
			AggregateID:   "ingress",
			ActorIdentity: "remote",
			Action:        "alert.reject",
			Result:        "rejected",
			ReasonCode:    reason,
			OccurredAt:    now,
		}, nil)
		return err
	})
}

type incoming struct {
	SchemaVersion   string                   `json:"schema_version"`
	Source          string                   `json:"source"`
	ExternalAlertID string                   `json:"external_alert_id"`
	TargetID        string                   `json:"target_id"`
	RuleID          string                   `json:"rule_id"`
	State           contract.NormalizedState `json:"state"`
	Severity        contract.Severity        `json:"severity"`
	ObservedAt      time.Time                `json:"observed_at"`
	Values          map[string]float64       `json:"values"`
	EvidenceRefs    []string                 `json:"evidence_refs"`
}
type receipt struct {
	ExpiresAt time.Time `json:"expires_at"`
}

func decode(raw []byte) (incoming, error) {
	value, err := contract.Decode(raw, contract.DecodeOptions[incoming]{
		MaxBytes:      defaultMaxBodyBytes,
		SchemaVersion: contract.SchemaVersionV1,
		Validate:      validateIncoming,
	})
	if err != nil {
		return incoming{}, ErrInvalidAlert
	}
	return value, nil
}

func validateIncoming(value incoming) error {
	if value.Source == "" || len(value.Source) > 96 || value.ExternalAlertID == "" || len(value.ExternalAlertID) > 128 || value.TargetID == "" || value.RuleID == "" || value.ObservedAt.IsZero() {
		return ErrInvalidAlert
	}
	if value.State != contract.StateHealthy && value.State != contract.StateUnhealthy && value.State != contract.StateUnknown {
		return ErrInvalidAlert
	}
	if value.Severity != contract.SeverityInfo && value.Severity != contract.SeverityWarning && value.Severity != contract.SeverityCritical {
		return ErrInvalidAlert
	}
	return nil
}

func (i *Ingress) normalize(value incoming, now time.Time) (Normalized, error) {
	snapshot := i.targets.Snapshot()
	var found bool
	for _, candidate := range snapshot.Targets {
		if !candidate.Enabled || candidate.TargetID != value.TargetID {
			continue
		}
		for _, rule := range candidate.ProbeRules {
			if rule.RuleID == value.RuleID {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return Normalized{}, ErrInvalidAlert
	}
	id, err := i.newID()
	if err != nil {
		return Normalized{}, err
	}
	return Normalized{
		Source:          value.Source,
		ExternalAlertID: value.ExternalAlertID,
		Observation: contract.HealthObservation{
			SchemaVersion:         contract.SchemaVersionV1,
			ObservationID:         id,
			TargetID:              value.TargetID,
			RuleID:                value.RuleID,
			TargetSnapshotVersion: snapshot.Version,
			ObservedAt:            value.ObservedAt.UTC(),
			NormalizedState:       value.State,
			BoundedValues:         bounded(value.Values),
			EvidenceRefs:          []string{},
			Sequence:              uint64(now.UnixNano()),
		},
	}, nil
}

func bounded(values map[string]float64) map[string]float64 {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make(map[string]float64, min(len(keys), maxValues))
	for _, key := range keys {
		if len(out) == maxValues {
			break
		}
		value := values[key]
		if math.IsNaN(value) || math.IsInf(value, 0) {
			continue
		}
		if value > maxValue {
			value = maxValue
		}
		if value < -maxValue {
			value = -maxValue
		}
		out[key] = value
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isJSON(value string) bool {
	mediaType, _, found := strings.Cut(value, ";")
	return value == "application/json" || (found && strings.TrimSpace(mediaType) == "application/json")
}
