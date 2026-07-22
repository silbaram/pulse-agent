// Package audit records transactionally appended, digest-linked audit events.
package audit

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/redaction"
	"pulse-agent/internal/store"
)

const maxFieldBytes = 128

var (
	// ErrInvalidEvent indicates an audit event that is not safe or complete
	// enough to enter the durable audit chain.
	ErrInvalidEvent = errors.New("invalid audit event")
	// ErrChainInvalid indicates that persisted audit records cannot be trusted
	// as one complete, ordered, digest-linked chain.
	ErrChainInvalid = errors.New("audit chain invalid")
	// ErrChainCapacity indicates that the ordered audit key space is exhausted.
	ErrChainCapacity = errors.New("audit chain capacity exhausted")
)

// Mutation applies an aggregate state change in the same transaction as an
// audit append. It must not modify store.BucketAudit directly.
type Mutation func(*store.Tx) error

type chainState struct {
	nextIndex      uint64
	previousDigest string
}

type canonicalEvent struct {
	SchemaVersion  string `json:"schema_version"`
	EventID        string `json:"event_id"`
	AggregateType  string `json:"aggregate_type"`
	AggregateID    string `json:"aggregate_id"`
	ActorIdentity  string `json:"actor_identity"`
	Action         string `json:"action"`
	Result         string `json:"result"`
	ReasonCode     string `json:"reason_code"`
	OccurredAt     string `json:"occurred_at"`
	PreviousDigest string `json:"previous_digest"`
}

// Append validates the existing chain before applying change, then appends a
// newly digested event. Returning an error from this method causes the caller's
// enclosing LocalStateStore transaction to roll back both the aggregate change
// and audit append.
func Append(tx *store.Tx, event contract.AuditEvent, change Mutation) (contract.AuditEvent, error) {
	state, err := readChain(tx)
	if err != nil {
		return contract.AuditEvent{}, err
	}
	if event.PreviousDigest != "" || event.Digest != "" {
		return contract.AuditEvent{}, ErrInvalidEvent
	}
	event.OccurredAt = event.OccurredAt.UTC()
	if err := validateEventFields(event); err != nil {
		return contract.AuditEvent{}, err
	}

	if change != nil {
		if err := change(tx); err != nil {
			return contract.AuditEvent{}, fmt.Errorf("apply audited state change: %w", err)
		}
		if afterChange, err := readChain(tx); err != nil {
			return contract.AuditEvent{}, err
		} else if afterChange != state {
			return contract.AuditEvent{}, ErrChainInvalid
		}
	}
	if state.nextIndex == math.MaxUint64 {
		return contract.AuditEvent{}, ErrChainCapacity
	}

	event.PreviousDigest = state.previousDigest
	digest, err := CanonicalDigest(event)
	if err != nil {
		return contract.AuditEvent{}, err
	}
	event.Digest = digest

	document, err := json.Marshal(event)
	if err != nil {
		return contract.AuditEvent{}, fmt.Errorf("serialize audit event: %w", err)
	}
	if err := tx.AppendAudit(eventKey(state.nextIndex), document); err != nil {
		return contract.AuditEvent{}, fmt.Errorf("store audit event: %w", err)
	}
	return event, nil
}

// ValidateChain verifies the stored sequence, the previous-digest links, and
// every canonical SHA-256 digest. A failure is intended to stop audited state
// changes before their mutation callback runs.
func ValidateChain(tx *store.Tx) error {
	_, err := readChain(tx)
	return err
}

// CanonicalDigest returns the lowercase SHA-256 digest for every immutable
// AuditEvent field except Digest itself. OccurredAt is normalized to UTC so one
// instant produces one digest regardless of its original location.
func CanonicalDigest(event contract.AuditEvent) (string, error) {
	canonical, err := canonicalBytes(event)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func readChain(tx *store.Tx) (chainState, error) {
	state := chainState{}
	seenEventIDs := make(map[string]struct{})
	err := tx.ForEach(store.BucketAudit, func(key string, document []byte) error {
		if key != eventKey(state.nextIndex) {
			return ErrChainInvalid
		}
		event, err := decodeEvent(document)
		if err != nil {
			return err
		}
		if event.PreviousDigest != state.previousDigest {
			return ErrChainInvalid
		}
		if _, duplicate := seenEventIDs[event.EventID]; duplicate {
			return ErrChainInvalid
		}
		seenEventIDs[event.EventID] = struct{}{}
		state.previousDigest = event.Digest
		if state.nextIndex == math.MaxUint64 {
			return ErrChainCapacity
		}
		state.nextIndex++
		return nil
	})
	if err == nil || errors.Is(err, ErrChainCapacity) {
		return state, err
	}
	if errors.Is(err, ErrChainInvalid) {
		return chainState{}, err
	}
	return chainState{}, ErrChainInvalid
}

func decodeEvent(document []byte) (contract.AuditEvent, error) {
	event, err := contract.Decode(document, contract.DecodeOptions[contract.AuditEvent]{
		SchemaVersion: contract.SchemaVersionV1,
		Validate:      validateStoredEvent,
	})
	if err != nil {
		return contract.AuditEvent{}, ErrChainInvalid
	}
	expected, err := CanonicalDigest(event)
	if err != nil || subtle.ConstantTimeCompare([]byte(event.Digest), []byte(expected)) != 1 {
		return contract.AuditEvent{}, ErrChainInvalid
	}
	return event, nil
}

func validateStoredEvent(event contract.AuditEvent) error {
	if err := validateEventFields(event); err != nil {
		return err
	}
	if !validDigest(event.Digest) || (event.PreviousDigest != "" && !validDigest(event.PreviousDigest)) {
		return ErrInvalidEvent
	}
	return nil
}

func canonicalBytes(event contract.AuditEvent) ([]byte, error) {
	if err := validateEventFields(event); err != nil {
		return nil, err
	}
	if event.PreviousDigest != "" && !validDigest(event.PreviousDigest) {
		return nil, ErrInvalidEvent
	}
	return json.Marshal(canonicalEvent{
		SchemaVersion:  event.SchemaVersion,
		EventID:        event.EventID,
		AggregateType:  event.AggregateType,
		AggregateID:    event.AggregateID,
		ActorIdentity:  event.ActorIdentity,
		Action:         event.Action,
		Result:         event.Result,
		ReasonCode:     event.ReasonCode,
		OccurredAt:     event.OccurredAt.UTC().Format(time.RFC3339Nano),
		PreviousDigest: event.PreviousDigest,
	})
}

func validateEventFields(event contract.AuditEvent) error {
	if event.SchemaVersion != contract.SchemaVersionV1 || event.OccurredAt.IsZero() {
		return ErrInvalidEvent
	}
	for _, value := range []string{
		event.EventID,
		event.AggregateType,
		event.AggregateID,
		event.ActorIdentity,
		event.Action,
		event.Result,
		event.ReasonCode,
	} {
		if !validAuditField(value) {
			return ErrInvalidEvent
		}
	}
	return nil
}

func validAuditField(value string) bool {
	if value == "" || len(value) > maxFieldBytes {
		return false
	}
	if redaction.ContainsSensitive(value) {
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

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func eventKey(index uint64) string {
	return fmt.Sprintf("%020d", index)
}
