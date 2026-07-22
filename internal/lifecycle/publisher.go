// Package lifecycle persists secret-free incident lifecycle payloads before
// they are accepted by the shared webhook delivery queue.
package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/delivery"
	"pulse-agent/internal/redaction"
	"pulse-agent/internal/store"
)

const (
	defaultDeliveryTTL    = 24 * time.Hour
	maxDeliveryTTL        = 30 * 24 * time.Hour
	maxEventIDLength      = 128
	maxReasonCodeLength   = 96
	maxEvidenceRefLength  = 128
	lifecycleRecordPrefix = "event/"
)

var (
	// ErrInvalidOptions indicates a missing or unsafe lifecycle publisher dependency.
	ErrInvalidOptions = errors.New("invalid lifecycle publisher options")
	// ErrInvalidEvent indicates an event that cannot safely reach the delivery queue.
	ErrInvalidEvent = errors.New("invalid lifecycle event")
	// ErrPayloadNotFound indicates a delivery queue reference without a durable event payload.
	ErrPayloadNotFound = errors.New("lifecycle payload not found")
	// ErrCorruptPayload indicates a persisted lifecycle payload outside the public contract.
	ErrCorruptPayload = errors.New("corrupt lifecycle payload")
	errEventExists    = errors.New("lifecycle event already exists")
)

// Clock supplies deterministic lifecycle timestamps.
type Clock interface {
	// Now returns the current lifecycle time.
	Now() time.Time
}

// ClockFunc adapts a function to the Clock interface.
type ClockFunc func() time.Time

// Now returns the time supplied by f.
func (f ClockFunc) Now() time.Time { return f() }

// Source loads exact lifecycle JSON bytes for the shared delivery dispatcher.
// Its zero value is invalid; construct it with NewSource.
type Source struct{ state *store.Store }

// NewSource returns a lifecycle payload source backed by daemon-owned state.
func NewSource(state *store.Store) (*Source, error) {
	if state == nil {
		return nil, ErrInvalidOptions
	}
	return &Source{state: state}, nil
}

// Load returns the exact persisted JSON body for a lifecycle-event queue item.
func (s *Source) Load(ctx context.Context, payloadType contract.DeliveryPayloadType, payloadRef string) ([]byte, error) {
	if s == nil || s.state == nil || ctx == nil || payloadType != contract.DeliveryPayloadLifecycleEvent || !validIdentifier(payloadRef, maxEventIDLength) {
		return nil, ErrInvalidEvent
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var document []byte
	found := false
	err := s.state.View(func(transaction *store.Tx) error {
		var readErr error
		document, found, readErr = transaction.Get(store.BucketLifecycleEvents, recordKey(payloadRef))
		return readErr
	})
	if err != nil {
		return nil, fmt.Errorf("load lifecycle payload: %w", err)
	}
	if !found {
		return nil, ErrPayloadNotFound
	}
	event, err := decodeEvent(document)
	if err != nil || event.EventID != payloadRef {
		return nil, ErrCorruptPayload
	}
	return append([]byte(nil), document...), nil
}

// Options configures a lifecycle publisher and its delivery lifetime.
type Options struct {
	// State is the daemon-owned store shared with the delivery dispatcher.
	State *store.Store
	// Queue atomically accepts the payload record and a webhook delivery item.
	Queue *delivery.Dispatcher
	// DestinationRef selects one configured outbound webhook destination.
	DestinationRef string
	// Clock supplies deterministic payload timestamps.
	Clock Clock
	// DeliveryTTL bounds how long a lifecycle event may remain pending. Zero defaults to one day.
	DeliveryTTL time.Duration
}

// Publisher persists each distinct lifecycle event and its queue item in one
// local transaction. It does not send HTTP requests; endpoint failures remain
// isolated in the delivery dispatcher.
type Publisher struct {
	state          *store.Store
	queue          *delivery.Dispatcher
	destinationRef string
	clock          Clock
	deliveryTTL    time.Duration

	mu sync.Mutex
}

// Input is a stable, secret-free lifecycle transition ready for publication.
// EventID is the caller-owned idempotency identity and must be reused when the
// same transition is retried.
type Input struct {
	EventID      string
	EventType    contract.LifecycleEventType
	IncidentID   string
	ReasonCode   string
	EvidenceRefs []string
	OccurredAt   time.Time
}

// Result identifies the persisted event and its shared delivery queue item.
type Result struct {
	Event     contract.LifecycleEvent
	QueueItem contract.DeliveryQueueItem
	Duplicate bool
}

// New validates a daemon-owned lifecycle publisher.
func New(options Options) (*Publisher, error) {
	ttl := options.DeliveryTTL
	if ttl == 0 {
		ttl = defaultDeliveryTTL
	}
	if options.State == nil || options.Queue == nil || !options.Queue.UsesStore(options.State) || options.Clock == nil || !validIdentifier(options.DestinationRef, maxEventIDLength) || ttl < time.Second || ttl > maxDeliveryTTL {
		return nil, ErrInvalidOptions
	}
	return &Publisher{
		state:          options.State,
		queue:          options.Queue,
		destinationRef: options.DestinationRef,
		clock:          options.Clock,
		deliveryTTL:    ttl,
	}, nil
}

// Publish persists one versioned lifecycle payload before it is visible to the
// delivery queue. A repeated EventID is an idempotent duplicate and never
// creates another webhook delivery item.
func (p *Publisher) Publish(ctx context.Context, input Input) (Result, error) {
	if p == nil || ctx == nil {
		return Result{}, ErrInvalidEvent
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	event, err := p.event(input)
	if err != nil {
		return Result{}, err
	}
	document, err := json.Marshal(event)
	if err != nil {
		return Result{}, fmt.Errorf("encode lifecycle event: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	existing, found, err := p.load(event.EventID)
	if err != nil {
		return Result{}, err
	}
	if found {
		if !sameEvent(existing, event) {
			return Result{}, ErrInvalidEvent
		}
		return Result{Event: existing, Duplicate: true}, nil
	}
	item, err := p.queue.EnqueueWithMutation(delivery.EnqueueRequest{
		PayloadType:    contract.DeliveryPayloadLifecycleEvent,
		PayloadRef:     event.EventID,
		DestinationRef: p.destinationRef,
		ExpiresAt:      event.OccurredAt.Add(p.deliveryTTL),
	}, func(transaction *store.Tx) error {
		key := recordKey(event.EventID)
		if _, present, err := transaction.Get(store.BucketLifecycleEvents, key); err != nil {
			return err
		} else if present {
			return errEventExists
		}
		return transaction.Put(store.BucketLifecycleEvents, key, document)
	})
	if errors.Is(err, errEventExists) {
		existing, found, loadErr := p.load(event.EventID)
		if loadErr != nil {
			return Result{}, loadErr
		}
		if found && sameEvent(existing, event) {
			return Result{Event: existing, Duplicate: true}, nil
		}
		return Result{}, ErrCorruptPayload
	}
	if err != nil {
		return Result{}, fmt.Errorf("enqueue lifecycle event: %w", err)
	}
	return Result{Event: event, QueueItem: item}, nil
}

// PublishAnalysisUnavailable records a stable model-unavailable transition for
// one recovery request before the request may continue through policy.
func (p *Publisher) PublishAnalysisUnavailable(ctx context.Context, incidentID, idempotencyKey, reasonCode string) error {
	_, err := p.Publish(ctx, Input{
		EventID:    StableEventID(contract.LifecycleAnalysisUnavailable, incidentID, idempotencyKey),
		EventType:  contract.LifecycleAnalysisUnavailable,
		IncidentID: incidentID,
		ReasonCode: reasonCode,
		OccurredAt: p.currentTime(),
	})
	return err
}

// PublishPolicyDenied records a stable policy denial for one recovery request.
func (p *Publisher) PublishPolicyDenied(ctx context.Context, incidentID, idempotencyKey, reasonCode string) error {
	_, err := p.Publish(ctx, Input{
		EventID:    StableEventID(contract.LifecyclePolicyDenied, incidentID, idempotencyKey),
		EventType:  contract.LifecyclePolicyDenied,
		IncidentID: incidentID,
		ReasonCode: reasonCode,
		OccurredAt: p.currentTime(),
	})
	return err
}

// PublishApprovalRequested records a stable pending-approval event for one
// journaled recovery command.
func (p *Publisher) PublishApprovalRequested(ctx context.Context, command contract.RecoveryCommand) error {
	_, err := p.Publish(ctx, Input{
		EventID:    StableEventID(contract.LifecycleApprovalRequested, command.IncidentID, command.CommandID),
		EventType:  contract.LifecycleApprovalRequested,
		IncidentID: command.IncidentID,
		ReasonCode: "approval_required",
		OccurredAt: command.IssuedAt,
	})
	return err
}

// PublishRecoveryStarted records a stable pre-Docker recovery event for one
// already journaled recovery command.
func (p *Publisher) PublishRecoveryStarted(ctx context.Context, command contract.RecoveryCommand) error {
	_, err := p.Publish(ctx, Input{
		EventID:    StableEventID(contract.LifecycleRecoveryStarted, command.IncidentID, command.CommandID),
		EventType:  contract.LifecycleRecoveryStarted,
		IncidentID: command.IncidentID,
		ReasonCode: "recovery_started",
		OccurredAt: p.currentTime(),
	})
	return err
}

// StableEventID derives an opaque, stable lifecycle event ID from one event
// type, incident, and caller-owned idempotency key without retaining its input.
func StableEventID(eventType contract.LifecycleEventType, incidentID, idempotencyKey string) string {
	sum := sha256.Sum256([]byte(string(eventType) + "\x00" + incidentID + "\x00" + idempotencyKey))
	return "lifecycle-" + hex.EncodeToString(sum[:])
}

func (p *Publisher) event(input Input) (contract.LifecycleEvent, error) {
	if !validIdentifier(input.EventID, maxEventIDLength) || !validIdentifier(input.IncidentID, maxEventIDLength) || !validReasonCode(input.ReasonCode) || input.OccurredAt.IsZero() || !validEvidenceRefs(input.EvidenceRefs) {
		return contract.LifecycleEvent{}, ErrInvalidEvent
	}
	event := contract.LifecycleEvent{
		SchemaVersion: contract.SchemaVersionV1,
		EventID:       input.EventID,
		EventType:     input.EventType,
		IncidentID:    input.IncidentID,
		OccurredAt:    input.OccurredAt.UTC(),
		ReasonCode:    input.ReasonCode,
		EvidenceRefs:  append([]string(nil), input.EvidenceRefs...),
	}
	if event.Validate() != nil {
		return contract.LifecycleEvent{}, ErrInvalidEvent
	}
	return event, nil
}

func (p *Publisher) load(eventID string) (contract.LifecycleEvent, bool, error) {
	var (
		document []byte
		found    bool
	)
	err := p.state.View(func(transaction *store.Tx) error {
		var readErr error
		document, found, readErr = transaction.Get(store.BucketLifecycleEvents, recordKey(eventID))
		return readErr
	})
	if err != nil {
		return contract.LifecycleEvent{}, false, fmt.Errorf("load lifecycle event: %w", err)
	}
	if !found {
		return contract.LifecycleEvent{}, false, nil
	}
	event, err := decodeEvent(document)
	if err != nil || event.EventID != eventID {
		return contract.LifecycleEvent{}, false, ErrCorruptPayload
	}
	return event, true, nil
}

func (p *Publisher) currentTime() time.Time {
	if p == nil || p.clock == nil {
		return time.Time{}
	}
	return p.clock.Now().UTC()
}

func decodeEvent(document []byte) (contract.LifecycleEvent, error) {
	event, err := contract.Decode(document, contract.DecodeOptions[contract.LifecycleEvent]{
		MaxBytes:      contract.MaxDocumentBytes,
		SchemaVersion: contract.SchemaVersionV1,
		Validate:      func(value contract.LifecycleEvent) error { return value.Validate() },
	})
	if err != nil || !validIdentifier(event.EventID, maxEventIDLength) || !validIdentifier(event.IncidentID, maxEventIDLength) || !validReasonCode(event.ReasonCode) || !validEvidenceRefs(event.EvidenceRefs) {
		return contract.LifecycleEvent{}, ErrCorruptPayload
	}
	return event, nil
}

func recordKey(eventID string) string {
	sum := sha256.Sum256([]byte(eventID))
	return lifecycleRecordPrefix + hex.EncodeToString(sum[:])
}

func validIdentifier(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00') && !redaction.ContainsSensitive(value)
}

func validReasonCode(value string) bool {
	if value == "" || len(value) > maxReasonCodeLength || redaction.ContainsSensitive(value) {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '_' && character != '-' && character != '.' {
			return false
		}
	}
	return true
}

func validEvidenceRefs(references []string) bool {
	if len(references) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(references))
	for _, reference := range references {
		if !validIdentifier(reference, maxEvidenceRefLength) {
			return false
		}
		for _, character := range reference {
			if !(unicode.IsLetter(character) || unicode.IsDigit(character) || character == '-' || character == '_' || character == '.' || character == ':') {
				return false
			}
		}
		if _, duplicate := seen[reference]; duplicate {
			return false
		}
		seen[reference] = struct{}{}
	}
	return true
}

func sameEvent(left, right contract.LifecycleEvent) bool {
	if left.SchemaVersion != right.SchemaVersion || left.EventID != right.EventID || left.EventType != right.EventType || left.IncidentID != right.IncidentID || !left.OccurredAt.Equal(right.OccurredAt) || left.ReasonCode != right.ReasonCode || len(left.EvidenceRefs) != len(right.EvidenceRefs) {
		return false
	}
	for index := range left.EvidenceRefs {
		if left.EvidenceRefs[index] != right.EvidenceRefs[index] {
			return false
		}
	}
	return true
}
