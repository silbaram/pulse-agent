// Package report composes and persists secret-free terminal incident reports.
package report

import (
	"context"
	"errors"
	"fmt"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
)

var (
	// ErrInvalidOptions indicates a missing or unsafe report dependency.
	ErrInvalidOptions = errors.New("invalid incident report options")
	// ErrInvalidInput indicates a terminal report input outside the safe boundary.
	ErrInvalidInput = errors.New("invalid incident report input")
	// ErrPayloadNotFound indicates a delivery queue reference without a report payload.
	ErrPayloadNotFound = errors.New("incident report payload not found")
	// ErrCorruptPayload indicates a persisted report outside the public contract.
	ErrCorruptPayload = errors.New("corrupt incident report payload")
	errReportExists   = errors.New("incident report already exists")
)

// Source loads exact incident-report JSON bytes for the shared delivery dispatcher.
// Its zero value is invalid; construct it with NewSource.
type Source struct{ state *store.Store }

// NewSource returns an incident-report payload source backed by daemon-owned state.
func NewSource(state *store.Store) (*Source, error) {
	if state == nil {
		return nil, ErrInvalidOptions
	}
	return &Source{state: state}, nil
}

// Load returns the exact persisted JSON body for an incident-report queue item.
func (s *Source) Load(ctx context.Context, payloadType contract.DeliveryPayloadType, payloadRef string) ([]byte, error) {
	if s == nil || s.state == nil || ctx == nil || payloadType != contract.DeliveryPayloadIncidentReport || !validIdentifier(payloadRef, maxReportIDLength) {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var (
		document []byte
		found    bool
	)
	err := s.state.View(func(transaction *store.Tx) error {
		var readErr error
		document, found, readErr = transaction.Get(store.BucketIncidentReports, reportRecordKey(payloadRef))
		return readErr
	})
	if err != nil {
		return nil, fmt.Errorf("load incident report payload: %w", err)
	}
	if !found {
		return nil, ErrPayloadNotFound
	}
	report, err := decodeReport(document)
	if err != nil || report.ReportID != payloadRef {
		return nil, ErrCorruptPayload
	}
	return append([]byte(nil), document...), nil
}
