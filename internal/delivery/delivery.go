// Package delivery persists and sends secret-free Standard Webhooks payload references.
package delivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"pulse-agent/internal/audit"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
	"pulse-agent/internal/webhook"
)

const (
	maxDestinationRefLength = 128
	maxPayloadRefLength     = 256
	maxQueueItems           = 10_000
	maxAttempts             = 32
	maxPayloadBytes         = 1 << 20
	queueKeyPrefix          = "delivery/"
)

var (
	// ErrInvalidOptions indicates that a delivery dispatcher dependency is missing or unsafe.
	ErrInvalidOptions = errors.New("invalid delivery options")
	// ErrInvalidRequest indicates a queue request outside the shared delivery contract.
	ErrInvalidRequest = errors.New("invalid delivery request")
	// ErrQueueFull indicates that accepting another pending delivery would exceed the queue bound.
	ErrQueueFull = errors.New("delivery queue is full")
	// ErrDeliveryConflict indicates an ID generator repeated an existing delivery identity.
	ErrDeliveryConflict = errors.New("delivery identity conflict")
	// ErrCorruptQueue indicates an invalid durable delivery queue entry.
	ErrCorruptQueue = errors.New("corrupt delivery queue entry")
)

// Clock supplies deterministic enqueue, retry, and expiry timestamps.
type Clock interface {
	// Now returns the current delivery time.
	Now() time.Time
}

// HTTPClient is the bounded HTTP surface used for outbound webhook delivery.
type HTTPClient interface {
	// Do sends one request and returns the remote HTTP response.
	Do(*http.Request) (*http.Response, error)
}

// PayloadSource returns the exact immutable JSON bytes for a queued payload
// reference. It must not return secrets or raw evidence.
type PayloadSource interface {
	// Load returns the body to sign and send for one typed payload reference.
	Load(context.Context, contract.DeliveryPayloadType, string) ([]byte, error)
}

// Options configures one daemon-owned bounded delivery dispatcher.
type Options struct {
	// State owns the durable delivery queue.
	State *store.Store
	// Client sends HTTPS requests under the dispatcher-owned deadline.
	Client HTTPClient
	// Payloads loads exact secret-free JSON bytes when a queue item is due.
	Payloads PayloadSource
	// Keyring signs each exact body with current and optional previous secrets.
	Keyring *webhook.Keyring
	// Clock supplies deterministic current time.
	Clock Clock
	// NewDeliveryID creates a unique durable queue identifier.
	NewDeliveryID func() (string, error)
	// NewWebhookID creates the stable logical Standard Webhooks identifier.
	NewWebhookID func() (string, error)
	// NewAuditEventID creates expiry and terminal-failure audit event identifiers.
	NewAuditEventID func() (string, error)
	// Destinations maps a durable destination reference to a fixed HTTPS endpoint.
	Destinations map[string]string
	// MaxQueueItems bounds pending entries retained in the local store.
	MaxQueueItems int
	// MaxAttempts bounds total send attempts, including the first delivery.
	MaxAttempts int
	// InitialBackoff is the delay after the first failed attempt.
	InitialBackoff time.Duration
	// MaxBackoff caps exponential retry delay.
	MaxBackoff time.Duration
	// RequestTimeout bounds one HTTPS request and payload-source call context.
	RequestTimeout time.Duration
	// MaxPayloadBytes bounds exact JSON bytes loaded for one delivery.
	MaxPayloadBytes int
}

// Dispatcher owns durable queue mutation and outbound delivery. Its methods are
// safe for concurrent callers in one daemon process; deliveries are serialized
// so a due queue item is not sent twice by concurrent callers.
type Dispatcher struct {
	state           *store.Store
	client          HTTPClient
	payloads        PayloadSource
	keyring         *webhook.Keyring
	clock           Clock
	newDeliveryID   func() (string, error)
	newWebhookID    func() (string, error)
	newAuditEventID func() (string, error)
	destinations    map[string]string
	maxQueueItems   int
	maxAttempts     int
	initialBackoff  time.Duration
	maxBackoff      time.Duration
	requestTimeout  time.Duration
	maxPayloadBytes int

	mu sync.Mutex
}

// EnqueueRequest identifies the secret-free payload reference to deliver.
type EnqueueRequest struct {
	// PayloadType must be lifecycle_event or incident_report.
	PayloadType contract.DeliveryPayloadType
	// PayloadRef identifies immutable payload bytes outside the delivery queue.
	PayloadRef string
	// DestinationRef selects one configured HTTPS destination.
	DestinationRef string
	// ExpiresAt bounds how long delivery may remain pending.
	ExpiresAt time.Time
}

// Result records the durable outcome of one attempted delivery.
type Result struct {
	// Item is the current durable queue item after processing.
	Item contract.DeliveryQueueItem
	// Sent reports that one 2xx response marked the item delivered.
	Sent bool
	// Retrying reports that a bounded future retry was recorded.
	Retrying bool
	// ReasonCode is a stable, secret-free result reason.
	ReasonCode string
}

type storedItem struct {
	key  string
	item contract.DeliveryQueueItem
}

// New validates dependencies and creates a bounded delivery dispatcher.
func New(options Options) (*Dispatcher, error) {
	if options.State == nil || options.Client == nil || options.Payloads == nil || options.Keyring == nil || options.Clock == nil || options.NewDeliveryID == nil || options.NewWebhookID == nil || options.NewAuditEventID == nil || options.MaxQueueItems < 1 || options.MaxQueueItems > maxQueueItems || options.MaxAttempts < 1 || options.MaxAttempts > maxAttempts || options.InitialBackoff < time.Millisecond || options.MaxBackoff < options.InitialBackoff || options.RequestTimeout < time.Millisecond || options.RequestTimeout > 2*time.Minute || options.MaxPayloadBytes < 1 || options.MaxPayloadBytes > maxPayloadBytes {
		return nil, ErrInvalidOptions
	}
	destinations, err := validatedDestinations(options.Destinations)
	if err != nil {
		return nil, err
	}
	return &Dispatcher{
		state:           options.State,
		client:          options.Client,
		payloads:        options.Payloads,
		keyring:         options.Keyring,
		clock:           options.Clock,
		newDeliveryID:   options.NewDeliveryID,
		newWebhookID:    options.NewWebhookID,
		newAuditEventID: options.NewAuditEventID,
		destinations:    destinations,
		maxQueueItems:   options.MaxQueueItems,
		maxAttempts:     options.MaxAttempts,
		initialBackoff:  options.InitialBackoff,
		maxBackoff:      options.MaxBackoff,
		requestTimeout:  options.RequestTimeout,
		maxPayloadBytes: options.MaxPayloadBytes,
	}, nil
}

// Enqueue records one typed payload reference before it may be sent. It stores
// no payload bytes, endpoint, or secret, and returns a stable webhook ID that
// is reused for every retry of the same logical delivery.
func (d *Dispatcher) Enqueue(request EnqueueRequest) (contract.DeliveryQueueItem, error) {
	if d == nil || validateEnqueueRequest(request, d.destinations) != nil {
		return contract.DeliveryQueueItem{}, ErrInvalidRequest
	}
	now, err := d.now()
	if err != nil {
		return contract.DeliveryQueueItem{}, err
	}
	if !now.Before(request.ExpiresAt) {
		return contract.DeliveryQueueItem{}, ErrInvalidRequest
	}
	deliveryID, err := d.newDeliveryID()
	if err != nil || !validToken(deliveryID, maxPayloadRefLength) {
		return contract.DeliveryQueueItem{}, ErrInvalidRequest
	}
	webhookID, err := d.newWebhookID()
	if err != nil {
		return contract.DeliveryQueueItem{}, ErrInvalidRequest
	}
	if _, err := d.keyring.Sign(webhookID, now, nil); err != nil {
		return contract.DeliveryQueueItem{}, ErrInvalidRequest
	}
	item := contract.DeliveryQueueItem{
		SchemaVersion:  contract.SchemaVersionV1,
		DeliveryID:     deliveryID,
		PayloadType:    request.PayloadType,
		PayloadRef:     request.PayloadRef,
		WebhookID:      webhookID,
		DestinationRef: request.DestinationRef,
		AttemptCount:   0,
		NextAttemptAt:  now,
		ExpiresAt:      request.ExpiresAt.UTC(),
		State:          contract.DeliveryPending,
	}
	if err := d.state.Update(func(transaction *store.Tx) error {
		pending, err := countPending(transaction)
		if err != nil {
			return err
		}
		if pending >= d.maxQueueItems {
			return ErrQueueFull
		}
		key := itemKey(item.DeliveryID)
		if _, found, err := transaction.Get(store.BucketDeliveryQueue, key); err != nil {
			return err
		} else if found {
			return ErrDeliveryConflict
		}
		return putItem(transaction, key, item)
	}); err != nil {
		return contract.DeliveryQueueItem{}, fmt.Errorf("enqueue delivery: %w", err)
	}
	return item, nil
}

// DeliverDue sends every pending entry due at the injected clock time. A 2xx
// response is terminal and idempotent; endpoint, payload, and timeout failures
// record bounded retry state without storing raw errors or payload bytes.
func (d *Dispatcher) DeliverDue(ctx context.Context) ([]Result, error) {
	if d == nil || ctx == nil {
		return nil, ErrInvalidRequest
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now, err := d.now()
	if err != nil {
		return nil, err
	}
	items, err := d.pendingItems()
	if err != nil {
		return nil, err
	}
	results := make([]Result, 0, len(items))
	for _, stored := range items {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		if !now.Before(stored.item.ExpiresAt) {
			result, err := d.expire(stored, now, "expired")
			if err != nil {
				return results, err
			}
			results = append(results, result)
			continue
		}
		if now.Before(stored.item.NextAttemptAt) {
			continue
		}
		result, err := d.deliverOne(ctx, stored, now)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (d *Dispatcher) deliverOne(ctx context.Context, stored storedItem, now time.Time) (Result, error) {
	requestCtx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()
	body, err := d.payloads.Load(requestCtx, stored.item.PayloadType, stored.item.PayloadRef)
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if err != nil || len(body) == 0 || len(body) > d.maxPayloadBytes || !json.Valid(body) {
		return d.retryOrFail(stored, now, "payload_unavailable")
	}
	headers, err := d.keyring.Sign(stored.item.WebhookID, now, body)
	if err != nil {
		return Result{}, fmt.Errorf("sign delivery payload: %w", err)
	}
	endpoint := d.destinations[stored.item.DestinationRef]
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("create delivery request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(webhook.HeaderID, headers.ID)
	request.Header.Set(webhook.HeaderTimestamp, headers.Timestamp)
	request.Header.Set(webhook.HeaderSignature, headers.Signature)
	response, requestErr := d.client.Do(request)
	closeErr := closeResponse(response)
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if requestErr != nil || closeErr != nil || response == nil || response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return d.retryOrFail(stored, now, "endpoint_failed")
	}
	return d.markDelivered(stored, now)
}

func closeResponse(response *http.Response) error {
	if response == nil || response.Body == nil {
		return nil
	}
	if err := response.Body.Close(); err != nil {
		return fmt.Errorf("close delivery response: %w", err)
	}
	return nil
}

func (d *Dispatcher) markDelivered(stored storedItem, now time.Time) (Result, error) {
	var updated contract.DeliveryQueueItem
	err := d.state.Update(func(transaction *store.Tx) error {
		current, err := loadItem(transaction, stored.key)
		if err != nil {
			return err
		}
		if current.State == contract.DeliveryDelivered {
			updated = current
			return nil
		}
		if current.State != contract.DeliveryPending || !now.Before(current.ExpiresAt) {
			return ErrCorruptQueue
		}
		current.AttemptCount++
		current.State = contract.DeliveryDelivered
		if err := putItem(transaction, stored.key, current); err != nil {
			return err
		}
		updated = current
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("mark delivery delivered: %w", err)
	}
	return Result{Item: updated, Sent: true, ReasonCode: "delivered"}, nil
}

func (d *Dispatcher) retryOrFail(stored storedItem, now time.Time, reason string) (Result, error) {
	if stored.item.AttemptCount+1 >= d.maxAttempts {
		return d.fail(stored, now, "attempts_exhausted")
	}
	nextAttempt := stored.item.AttemptCount + 1
	nextAt := now.Add(d.backoff(nextAttempt))
	if !nextAt.Before(stored.item.ExpiresAt) {
		return d.expire(stored, now, "expired")
	}
	var updated contract.DeliveryQueueItem
	err := d.state.Update(func(transaction *store.Tx) error {
		current, err := loadItem(transaction, stored.key)
		if err != nil {
			return err
		}
		if current.State != contract.DeliveryPending {
			return ErrCorruptQueue
		}
		current.AttemptCount = nextAttempt
		current.NextAttemptAt = nextAt
		if err := putItem(transaction, stored.key, current); err != nil {
			return err
		}
		updated = current
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("schedule delivery retry: %w", err)
	}
	return Result{Item: updated, Retrying: true, ReasonCode: reason}, nil
}

func (d *Dispatcher) fail(stored storedItem, now time.Time, reason string) (Result, error) {
	return d.markTerminal(stored, now, contract.DeliveryFailed, reason)
}

func (d *Dispatcher) expire(stored storedItem, now time.Time, reason string) (Result, error) {
	return d.markTerminal(stored, now, contract.DeliveryExpired, reason)
}

func (d *Dispatcher) markTerminal(stored storedItem, now time.Time, state contract.DeliveryState, reason string) (Result, error) {
	auditID, err := d.newAuditEventID()
	if err != nil || !validToken(auditID, maxPayloadRefLength) {
		return Result{}, ErrInvalidRequest
	}
	var updated contract.DeliveryQueueItem
	err = d.state.Update(func(transaction *store.Tx) error {
		current, err := loadItem(transaction, stored.key)
		if err != nil {
			return err
		}
		if current.State == state {
			updated = current
			return nil
		}
		if current.State != contract.DeliveryPending {
			return ErrCorruptQueue
		}
		current.State = state
		if err := auditDeliveryFailure(transaction, auditID, current, now, reason, func(transaction *store.Tx) error {
			return putItem(transaction, stored.key, current)
		}); err != nil {
			return err
		}
		updated = current
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("mark delivery terminal: %w", err)
	}
	return Result{Item: updated, ReasonCode: reason}, nil
}

func (d *Dispatcher) pendingItems() ([]storedItem, error) {
	items := make([]storedItem, 0)
	err := d.state.View(func(transaction *store.Tx) error {
		return transaction.ForEach(store.BucketDeliveryQueue, func(key string, document []byte) error {
			item, err := decodeItem(document)
			if err != nil {
				return err
			}
			if itemKey(item.DeliveryID) != key {
				return ErrCorruptQueue
			}
			if item.State == contract.DeliveryPending {
				items = append(items, storedItem{key: key, item: item})
			}
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("load delivery queue: %w", err)
	}
	return items, nil
}

func (d *Dispatcher) now() (time.Time, error) {
	if d.clock == nil {
		return time.Time{}, ErrInvalidOptions
	}
	now := d.clock.Now().UTC()
	if now.IsZero() {
		return time.Time{}, ErrInvalidOptions
	}
	return now, nil
}

func (d *Dispatcher) backoff(attempt int) time.Duration {
	if attempt < 1 {
		return d.initialBackoff
	}
	backoff := d.initialBackoff
	for retry := 1; retry < attempt && backoff < d.maxBackoff; retry++ {
		if backoff > d.maxBackoff/2 {
			return d.maxBackoff
		}
		backoff *= 2
	}
	return min(backoff, d.maxBackoff)
}

func validatedDestinations(destinations map[string]string) (map[string]string, error) {
	if len(destinations) == 0 || len(destinations) > maxQueueItems {
		return nil, ErrInvalidOptions
	}
	validated := make(map[string]string, len(destinations))
	for reference, endpoint := range destinations {
		if !validToken(reference, maxDestinationRefLength) {
			return nil, ErrInvalidOptions
		}
		parsed, err := url.ParseRequestURI(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, ErrInvalidOptions
		}
		validated[reference] = parsed.String()
	}
	return validated, nil
}

func validateEnqueueRequest(request EnqueueRequest, destinations map[string]string) error {
	if (request.PayloadType != contract.DeliveryPayloadLifecycleEvent && request.PayloadType != contract.DeliveryPayloadIncidentReport) || !validToken(request.PayloadRef, maxPayloadRefLength) || !validToken(request.DestinationRef, maxDestinationRefLength) || request.ExpiresAt.IsZero() {
		return ErrInvalidRequest
	}
	if _, found := destinations[request.DestinationRef]; !found {
		return ErrInvalidRequest
	}
	return nil
}

func countPending(transaction *store.Tx) (int, error) {
	pending := 0
	err := transaction.ForEach(store.BucketDeliveryQueue, func(_ string, document []byte) error {
		item, err := decodeItem(document)
		if err != nil {
			return err
		}
		if item.State == contract.DeliveryPending {
			pending++
		}
		return nil
	})
	return pending, err
}

func loadItem(transaction *store.Tx, key string) (contract.DeliveryQueueItem, error) {
	document, found, err := transaction.Get(store.BucketDeliveryQueue, key)
	if err != nil {
		return contract.DeliveryQueueItem{}, err
	}
	if !found {
		return contract.DeliveryQueueItem{}, ErrCorruptQueue
	}
	item, err := decodeItem(document)
	if err != nil {
		return contract.DeliveryQueueItem{}, err
	}
	return item, nil
}

func putItem(transaction *store.Tx, key string, item contract.DeliveryQueueItem) error {
	if itemKey(item.DeliveryID) != key || item.Validate() != nil {
		return ErrCorruptQueue
	}
	document, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("encode delivery queue item: %w", err)
	}
	return transaction.Put(store.BucketDeliveryQueue, key, document)
}

func decodeItem(document []byte) (contract.DeliveryQueueItem, error) {
	item, err := contract.Decode(document, contract.DecodeOptions[contract.DeliveryQueueItem]{
		MaxBytes:      contract.MaxDocumentBytes,
		SchemaVersion: contract.SchemaVersionV1,
		Validate:      func(value contract.DeliveryQueueItem) error { return value.Validate() },
	})
	if err != nil {
		return contract.DeliveryQueueItem{}, ErrCorruptQueue
	}
	return item, nil
}

func auditDeliveryFailure(transaction *store.Tx, auditID string, item contract.DeliveryQueueItem, now time.Time, reason string, change audit.Mutation) error {
	_, err := audit.Append(transaction, contract.AuditEvent{
		SchemaVersion: contract.SchemaVersionV1,
		EventID:       auditID,
		AggregateType: "delivery",
		AggregateID:   item.DeliveryID,
		ActorIdentity: "system",
		Action:        "delivery.failed",
		Result:        "failed",
		ReasonCode:    reason,
		OccurredAt:    now,
	}, change)
	return err
}

func itemKey(deliveryID string) string {
	sum := sha256.Sum256([]byte(deliveryID))
	return queueKeyPrefix + hex.EncodeToString(sum[:])
}

func validToken(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}
