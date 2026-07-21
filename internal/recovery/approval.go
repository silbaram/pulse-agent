package recovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"pulse-agent/internal/audit"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
	"pulse-agent/internal/telemetry"
)

const (
	approvalRecordPrefix  = "record/"
	approvalCommandPrefix = "command/"

	maxApprovalReasonLength = 96

	approvalAuditAggregateType = "recovery_approval"
	approvalAuditAction        = "approval.decide"
	approvalAuditAccepted      = "accepted"
	approvalAuditRejected      = "rejected"
	approvalAuditInvalid       = "invalid_approval"
	approvalAuditNotFound      = "command_not_found"
	approvalAuditConflict      = "decision_conflict"
	approvalAuditExpired       = "command_expired"
)

var (
	// ErrInvalidApprovalOptions indicates an approval manager dependency that
	// cannot enforce the durable local approval boundary.
	ErrInvalidApprovalOptions = errors.New("invalid approval manager options")
	// ErrInvalidApprovalDecision indicates malformed approval input from an
	// otherwise authenticated local administrative request.
	ErrInvalidApprovalDecision = errors.New("invalid approval decision")
	// ErrApprovalCommandNotFound indicates a command ID outside the durable
	// recovery journal.
	ErrApprovalCommandNotFound = errors.New("approval command not found")
	// ErrApprovalConflict indicates that a command already has an immutable
	// local grant or denial decision.
	ErrApprovalConflict = errors.New("approval decision conflict")
	// ErrApprovalCommandExpired indicates a command that expired before a local
	// administrator supplied a decision.
	ErrApprovalCommandExpired = errors.New("approval command expired")
)

// ClockFunc adapts a function to the Clock interface for production assembly
// and deterministic tests.
type ClockFunc func() time.Time

// Now returns the time supplied by f.
func (f ClockFunc) Now() time.Time {
	return f()
}

// ApprovalOptions configures one daemon-owned approval manager.
type ApprovalOptions struct {
	// State owns both the recovery journal and approval records.
	State *store.Store
	// Clock supplies deterministic approval and audit timestamps.
	Clock Clock
	// NewApprovalID creates an immutable local approval identifier.
	NewApprovalID func() (string, error)
	// NewAuditEventID creates a unique event ID for every decision result.
	NewAuditEventID func() (string, error)
	// Telemetry records only the bounded approval decision outcome.
	Telemetry *telemetry.Recorder
}

// ApprovalManager records exactly one immutable local decision for a pending
// high-risk recovery command. It never executes Docker actions.
type ApprovalManager struct {
	state           *store.Store
	clock           Clock
	newApprovalID   func() (string, error)
	newAuditEventID func() (string, error)
	telemetry       *telemetry.Recorder
}

// ApprovalDecisionRequest is the daemon-owned context for one local grant or
// denial. ActorIdentity must come from authenticated Unix peer credentials,
// never from command-line input.
type ApprovalDecisionRequest struct {
	// CommandID identifies exactly one recovery command awaiting approval.
	CommandID string
	// Decision is grant or deny and must match the local IPC operation.
	Decision contract.ApprovalDecision
	// ActorIdentity is the authenticated local peer identity.
	ActorIdentity string
	// RequestID correlates the administrative request and audit aggregate.
	RequestID string
	// ReasonCode is a bounded, audit-safe administrative reason.
	ReasonCode string
	// ExpiresAt bounds a grant and is recorded for both decisions.
	ExpiresAt time.Time
}

// ApprovalDecisionResult is the durable result of one accepted local decision.
// A grant leaves the command awaiting execution-time revalidation; only a
// coordinator may later invoke its typed Docker action.
type ApprovalDecisionResult struct {
	// Approval is the immutable decision persisted for the command.
	Approval contract.Approval
	// Command is the command after its denial or approval association update.
	Command contract.RecoveryCommand
}

// NewApprovalManager validates dependencies and returns a durable approval
// manager. Its zero value is invalid.
func NewApprovalManager(options ApprovalOptions) (*ApprovalManager, error) {
	if options.State == nil || options.Clock == nil || options.NewApprovalID == nil || options.NewAuditEventID == nil {
		return nil, ErrInvalidApprovalOptions
	}
	return &ApprovalManager{
		state:           options.State,
		clock:           options.Clock,
		newApprovalID:   options.NewApprovalID,
		newAuditEventID: options.NewAuditEventID,
		telemetry:       options.Telemetry,
	}, nil
}

// Decide records one local grant or denial and its audit event in one store
// transaction. A replay or conflicting decision never changes the command.
func (m *ApprovalManager) Decide(request ApprovalDecisionRequest) (result ApprovalDecisionResult, err error) {
	startedAt := time.Now()
	defer func() { m.recordDecision(startedAt, result, err) }()
	if m == nil || !validApprovalDecisionRequest(request) {
		if m != nil {
			if err := m.recordRejected(request, approvalAuditInvalid); err != nil {
				return ApprovalDecisionResult{}, err
			}
		}
		return ApprovalDecisionResult{}, ErrInvalidApprovalDecision
	}
	now, err := m.now()
	if err != nil {
		return ApprovalDecisionResult{}, err
	}
	approvalID, err := m.newApprovalID()
	if err != nil || !validToken(approvalID, maxCommandIDLength) {
		return ApprovalDecisionResult{}, ErrInvalidApprovalOptions
	}

	var (
		decisionResult ApprovalDecisionResult
		decisionErr    error
	)
	err = m.state.Update(func(transaction *store.Tx) error {
		stored, found, err := findRecordByCommandID(transaction, request.CommandID)
		if err != nil {
			return err
		}
		if !found {
			decisionErr = ErrApprovalCommandNotFound
			return m.appendAudit(transaction, request, approvalAuditRejected, approvalAuditNotFound, nil)
		}
		record := stored.record
		if record.Phase != phaseAwaitingApproval || record.Command.State != contract.RecoveryPending || record.Command.ApprovalID != "" {
			decisionErr = ErrApprovalConflict
			return m.appendAudit(transaction, request, approvalAuditRejected, approvalAuditConflict, nil)
		}
		if !now.Before(record.Command.ExpiresAt) || !now.Before(request.ExpiresAt) {
			if err := transitionToExpired(&record); err != nil {
				return err
			}
			decisionErr = ErrApprovalCommandExpired
			return m.appendAudit(transaction, request, approvalAuditRejected, approvalAuditExpired, func(transaction *store.Tx) error {
				return putRecord(transaction, stored.key, record)
			})
		}
		if request.ExpiresAt.After(record.Command.ExpiresAt) {
			decisionErr = ErrInvalidApprovalDecision
			return m.appendAudit(transaction, request, approvalAuditRejected, approvalAuditInvalid, nil)
		}
		if _, exists, err := transaction.Get(store.BucketApprovals, approvalRecordKey(approvalID)); err != nil {
			return err
		} else if exists {
			return ErrInvalidApprovalOptions
		}
		if _, exists, err := transaction.Get(store.BucketApprovals, approvalCommandKey(request.CommandID)); err != nil {
			return err
		} else if exists {
			decisionErr = ErrApprovalConflict
			return m.appendAudit(transaction, request, approvalAuditRejected, approvalAuditConflict, nil)
		}

		approval := contract.Approval{
			SchemaVersion:    contract.SchemaVersionV1,
			ApprovalID:       approvalID,
			CommandID:        record.Command.CommandID,
			Decision:         request.Decision,
			ApproverIdentity: request.ActorIdentity,
			Reason:           request.ReasonCode,
			CreatedAt:        now,
			ExpiresAt:        request.ExpiresAt.UTC(),
		}
		if err := validateApproval(approval); err != nil {
			return ErrInvalidApprovalDecision
		}
		record.Command.ApprovalID = approval.ApprovalID
		if approval.Decision == contract.ApprovalDenied {
			if err := transitionToDenied(&record); err != nil {
				return err
			}
		}
		document, err := json.Marshal(approval)
		if err != nil {
			return fmt.Errorf("encode approval: %w", err)
		}
		return m.appendAudit(transaction, request, approvalAuditAccepted, request.ReasonCode, func(transaction *store.Tx) error {
			if err := transaction.Put(store.BucketApprovals, approvalRecordKey(approval.ApprovalID), document); err != nil {
				return err
			}
			if err := transaction.Put(store.BucketApprovals, approvalCommandKey(approval.CommandID), []byte(approval.ApprovalID)); err != nil {
				return err
			}
			if err := putRecord(transaction, stored.key, record); err != nil {
				return err
			}
			decisionResult = ApprovalDecisionResult{Approval: approval, Command: record.Command}
			return nil
		})
	})
	if err != nil {
		return ApprovalDecisionResult{}, err
	}
	if decisionErr != nil {
		return ApprovalDecisionResult{}, decisionErr
	}
	return decisionResult, nil
}

func (m *ApprovalManager) recordDecision(startedAt time.Time, result ApprovalDecisionResult, decisionErr error) {
	if m == nil || m.telemetry == nil {
		return
	}
	telemetryResult, reason := telemetry.ResultSuccess, telemetry.ReasonAccepted
	if decisionErr != nil {
		switch {
		case errors.Is(decisionErr, ErrInvalidApprovalDecision):
			telemetryResult, reason = telemetry.ResultRejected, telemetry.ReasonInvalid
		case errors.Is(decisionErr, ErrApprovalConflict):
			telemetryResult, reason = telemetry.ResultRejected, telemetry.ReasonConflict
		case errors.Is(decisionErr, ErrApprovalCommandExpired):
			telemetryResult, reason = telemetry.ResultRejected, telemetry.ReasonExpired
		case errors.Is(decisionErr, ErrApprovalCommandNotFound):
			telemetryResult, reason = telemetry.ResultRejected, telemetry.ReasonInvalid
		default:
			telemetryResult, reason = telemetry.ResultFailure, telemetry.ReasonInternal
		}
	} else if result.Approval.Decision == contract.ApprovalDenied {
		telemetryResult, reason = telemetry.ResultRejected, telemetry.ReasonDenied
	}
	event, eventErr := telemetry.NewEvent(telemetry.ComponentApproval, telemetry.OperationDecide, telemetryResult, reason, time.Since(startedAt))
	if eventErr == nil {
		m.telemetry.RecordBestEffort(context.Background(), event)
	}
}

// LoadApproval returns the immutable decision associated with commandID. It
// is intended for an execution-time StateSource, which must still check its
// current authorized-approver policy before allowing execution.
func (m *ApprovalManager) LoadApproval(commandID string) (contract.Approval, bool, error) {
	if m == nil || !validToken(commandID, maxCommandIDLength) {
		return contract.Approval{}, false, ErrInvalidApprovalDecision
	}
	var approval contract.Approval
	found := false
	err := m.state.View(func(transaction *store.Tx) error {
		approvalID, indexed, err := transaction.Get(store.BucketApprovals, approvalCommandKey(commandID))
		if err != nil || !indexed {
			return err
		}
		document, present, err := transaction.Get(store.BucketApprovals, approvalRecordKey(string(approvalID)))
		if err != nil {
			return err
		}
		if !present {
			return ErrCorruptJournal
		}
		decoded, err := contract.Decode(document, contract.DecodeOptions[contract.Approval]{
			MaxBytes:      contract.MaxDocumentBytes,
			SchemaVersion: contract.SchemaVersionV1,
			Validate:      validateApproval,
		})
		if err != nil || decoded.CommandID != commandID || decoded.ApprovalID != string(approvalID) {
			return ErrCorruptJournal
		}
		approval = decoded
		found = true
		return nil
	})
	if err != nil {
		return contract.Approval{}, false, err
	}
	return approval, found, nil
}

// ApprovalStateSource decorates a current daemon state source with the durable
// local approval associated with a command. A missing or mismatched approval
// fails closed as a revoked approval; the wrapped source remains authoritative
// for current policy and approver authorization.
type ApprovalStateSource struct {
	Source    StateSource
	Approvals *ApprovalManager
}

// Load returns one current execution state with the command's durable approval
// attached for policy evaluation.
func (s ApprovalStateSource) Load(ctx context.Context, command contract.RecoveryCommand) (ExecutionState, error) {
	if s.Source == nil || s.Approvals == nil {
		return ExecutionState{}, ErrInvalidApprovalOptions
	}
	state, err := s.Source.Load(ctx, command)
	if err != nil || command.ApprovalID == "" {
		return state, err
	}
	approval, found, err := s.Approvals.LoadApproval(command.CommandID)
	if err != nil {
		return ExecutionState{}, err
	}
	if !found || approval.ApprovalID != command.ApprovalID || approval.CommandID != command.CommandID {
		state.PolicyInput.Approval = &contract.Approval{}
		state.PolicyInput.ApprovalRevoked = true
		return state, nil
	}
	state.PolicyInput.Approval = &approval
	return state, nil
}

// NewApprovalID returns a random, audit-safe approval ID for production use.
func NewApprovalID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "approval-" + hex.EncodeToString(random[:]), nil
}

func (m *ApprovalManager) now() (time.Time, error) {
	if m == nil || m.clock == nil {
		return time.Time{}, ErrInvalidApprovalOptions
	}
	now := m.clock.Now().UTC()
	if now.IsZero() {
		return time.Time{}, ErrInvalidApprovalOptions
	}
	return now, nil
}

func (m *ApprovalManager) recordRejected(request ApprovalDecisionRequest, reason string) error {
	if !validAuditRequest(request) {
		return nil
	}
	return m.state.Update(func(transaction *store.Tx) error {
		return m.appendAudit(transaction, request, approvalAuditRejected, reason, nil)
	})
}

func (m *ApprovalManager) appendAudit(transaction *store.Tx, request ApprovalDecisionRequest, result, reason string, mutation audit.Mutation) error {
	eventID, err := m.newAuditEventID()
	if err != nil || !validToken(eventID, maxCommandIDLength) {
		return ErrInvalidApprovalOptions
	}
	now, err := m.now()
	if err != nil {
		return err
	}
	_, err = audit.Append(transaction, contract.AuditEvent{
		SchemaVersion: contract.SchemaVersionV1,
		EventID:       eventID,
		AggregateType: approvalAuditAggregateType,
		AggregateID:   approvalAggregateID(request.CommandID),
		ActorIdentity: request.ActorIdentity,
		Action:        approvalAuditAction,
		Result:        result,
		ReasonCode:    reason,
		OccurredAt:    now,
	}, mutation)
	return err
}

func findRecordByCommandID(transaction *store.Tx, commandID string) (storedRecord, bool, error) {
	var found storedRecord
	matched := false
	err := transaction.ForEach(store.BucketCommandJournal, func(key string, document []byte) error {
		if !strings.HasPrefix(key, journalRecordPrefix) {
			return nil
		}
		record, err := decodeRecord(document)
		if err != nil {
			return err
		}
		if recordKey(record.Command) != key {
			return ErrCorruptJournal
		}
		if record.Command.CommandID != commandID {
			return nil
		}
		if matched {
			return ErrCorruptJournal
		}
		matched = true
		found = storedRecord{key: key, record: record}
		return nil
	})
	if err != nil {
		return storedRecord{}, false, err
	}
	return found, matched, nil
}

func transitionToDenied(record *journalRecord) error {
	if (record.Phase != phasePending && record.Phase != phaseAwaitingApproval) || record.Command.State != contract.RecoveryPending {
		return errCommandNotExecutable
	}
	if err := record.Command.State.ValidateTransition(contract.RecoveryDenied); err != nil {
		return err
	}
	record.Command.State = contract.RecoveryDenied
	record.Phase = phaseCompleted
	return nil
}

func transitionToExpired(record *journalRecord) error {
	if (record.Phase != phasePending && record.Phase != phaseAwaitingApproval) || record.Command.State != contract.RecoveryPending {
		return errCommandNotExecutable
	}
	if err := record.Command.State.ValidateTransition(contract.RecoveryExpired); err != nil {
		return err
	}
	record.Command.State = contract.RecoveryExpired
	record.Phase = phaseCompleted
	return nil
}

func approvalRecordKey(approvalID string) string {
	return approvalRecordPrefix + approvalID
}

func approvalCommandKey(commandID string) string {
	return approvalCommandPrefix + commandID
}

func approvalAggregateID(commandID string) string {
	sum := sha256.Sum256([]byte(commandID))
	return "command-" + hex.EncodeToString(sum[:])
}

func validApprovalDecisionRequest(request ApprovalDecisionRequest) bool {
	return validAuditRequest(request) &&
		(request.Decision == contract.ApprovalGranted || request.Decision == contract.ApprovalDenied) &&
		!request.ExpiresAt.IsZero()
}

func validAuditRequest(request ApprovalDecisionRequest) bool {
	return validToken(request.CommandID, maxCommandIDLength) &&
		validToken(request.ActorIdentity, maxCommandIDLength) &&
		validToken(request.RequestID, maxCommandIDLength) &&
		validApprovalReason(request.ReasonCode)
}

func validApprovalReason(value string) bool {
	if value == "" || len(value) > maxApprovalReasonLength {
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

func validateApproval(approval contract.Approval) error {
	if approval.SchemaVersion != contract.SchemaVersionV1 || !validToken(approval.ApprovalID, maxCommandIDLength) || !validToken(approval.CommandID, maxCommandIDLength) || (approval.Decision != contract.ApprovalGranted && approval.Decision != contract.ApprovalDenied) || !validToken(approval.ApproverIdentity, maxCommandIDLength) || !validApprovalReason(approval.Reason) || approval.CreatedAt.IsZero() || approval.ExpiresAt.IsZero() || !approval.ExpiresAt.After(approval.CreatedAt) {
		return ErrInvalidApprovalDecision
	}
	return nil
}
