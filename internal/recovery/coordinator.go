// Package recovery coordinates one bounded, policy-authorized recovery action.
package recovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/docker"
	"pulse-agent/internal/policy"
	"pulse-agent/internal/store"
)

const (
	maxCommandIDLength      = 128
	maxIdempotencyKeyLength = 256
)

var (
	// ErrInvalidOptions indicates a coordinator dependency is missing or unsafe.
	ErrInvalidOptions = errors.New("invalid recovery coordinator options")
	// ErrInvalidRequest indicates a recovery request cannot safely create a command.
	ErrInvalidRequest = errors.New("invalid recovery request")
	// ErrCorruptJournal indicates a persisted recovery journal record is invalid.
	ErrCorruptJournal = errors.New("corrupt recovery journal")
	// ErrIdempotencyConflict indicates one idempotency key was reused for different recovery effects.
	ErrIdempotencyConflict = errors.New("recovery idempotency conflict")
)

// Adapter is the minimal Docker action surface the coordinator consumes.
// ValidateAction must recheck the current target selector and replica count
// immediately before an action. Execute must remain limited to the supplied
// typed action, and Verify must return only bounded Docker state.
type Adapter interface {
	// ValidateAction rechecks the current target and action before execution.
	ValidateAction(context.Context, contract.ServiceTarget, contract.TypedAction) error
	// Execute applies only the supplied already-validated typed action.
	Execute(context.Context, contract.ServiceTarget, contract.TypedAction) error
	// Verify returns bounded Docker state for one registered target.
	Verify(context.Context, contract.ServiceTarget) (docker.Snapshot, error)
}

// Clock supplies coordinator timestamps. Implementations must return a non-zero time.
type Clock interface {
	// Now returns the current coordinator time.
	Now() time.Time
}

// Options configures one daemon-owned recovery coordinator.
type Options struct {
	// State is the daemon-owned store holding the command journal.
	State *store.Store
	// Adapter applies only already-validated Docker actions.
	Adapter Adapter
	// Clock supplies deterministic issuance, expiry, and reconciliation times.
	Clock Clock
	// NewCommandID creates an immutable identifier for a new recovery command.
	NewCommandID func() (string, error)
}

// Coordinator persists a recovery command before invoking a Docker adapter.
// Its zero value is invalid; callers must construct it with New.
type Coordinator struct {
	state        *store.Store
	adapter      Adapter
	clock        Clock
	newCommandID func() (string, error)
}

// Request is the current local authorization context for one recovery effect.
// PolicyInput.CommandID must be empty because Coordinator creates the durable
// command ID. Callers must supply a current target and precondition snapshot
// for every Submit call; the coordinator evaluates them again just before I/O.
type Request struct {
	// IncidentID identifies the incident that owns this recovery effect.
	IncidentID string
	// Target is the current registered Docker target.
	Target contract.ServiceTarget
	// PolicySnapshot is the current immutable registered-runbook snapshot.
	PolicySnapshot policy.Snapshot
	// PolicyInput contains the current dynamic authorization facts.
	PolicyInput policy.Input
	// ExpiresAt bounds how long this command may be executed.
	ExpiresAt time.Time
	// IdempotencyKey identifies one delivery of this recovery request.
	IdempotencyKey string
}

// Outcome identifies the durable result of a coordinator operation.
type Outcome string

const (
	// OutcomeExecuted identifies an adapter action that returned successfully.
	OutcomeExecuted Outcome = "executed"
	// OutcomeDenied identifies an action rejected before adapter execution.
	OutcomeDenied Outcome = "denied"
	// OutcomeExpired identifies a command that expired before adapter execution.
	OutcomeExpired Outcome = "expired"
	// OutcomeAwaitApproval identifies a durable command that waits for a later approval flow.
	OutcomeAwaitApproval Outcome = "await_approval"
	// OutcomeDuplicate identifies a delivery already represented by the journal.
	OutcomeDuplicate Outcome = "duplicate"
	// OutcomeVerifyAndNotify identifies an uncertain command held for later verification and notification.
	OutcomeVerifyAndNotify Outcome = "verify_and_notify"
)

// Result is the outcome of submitting one recovery request.
type Result struct {
	// Command is the durable command when the request reached the journal.
	Command contract.RecoveryCommand
	// Outcome is the bounded coordinator result.
	Outcome Outcome
	// Decision is the policy evaluation that selected the outcome when applicable.
	Decision policy.Decision
	// Duplicate reports that an existing journal entry prevented a new effect.
	Duplicate bool
}

// ReconciliationResult records how one interrupted command was fail-closed.
type ReconciliationResult struct {
	// Command is the command moved to verify_and_notify.
	Command contract.RecoveryCommand
	// Outcome is always OutcomeVerifyAndNotify for a reconciled command.
	Outcome Outcome
	// Verified reports whether the bounded Docker state could be read.
	Verified bool
	// Snapshot is present only when Verified is true.
	Snapshot docker.Snapshot
}

// New validates dependencies and constructs a recovery coordinator.
func New(options Options) (*Coordinator, error) {
	if options.State == nil || options.Adapter == nil || options.Clock == nil || options.NewCommandID == nil {
		return nil, ErrInvalidOptions
	}
	return &Coordinator{
		state:        options.State,
		adapter:      options.Adapter,
		clock:        options.Clock,
		newCommandID: options.NewCommandID,
	}, nil
}

// Submit records a policy-permitted command before executing it. Duplicate
// deliveries never invoke Adapter.Execute. A policy denial is a normal result;
// adapter and store failures are returned as errors after durable state is updated.
func (c *Coordinator) Submit(ctx context.Context, request Request) (Result, error) {
	if c == nil || ctx == nil {
		return Result{}, ErrInvalidRequest
	}
	if err := validateRequest(request); err != nil {
		return Result{}, err
	}
	now, err := c.now()
	if err != nil {
		return Result{}, err
	}
	if !now.Before(request.ExpiresAt) {
		return Result{Outcome: OutcomeExpired}, nil
	}

	record, duplicate, decision, err := c.prepare(request, now)
	if err != nil {
		return Result{}, err
	}
	if decision.Verdict == policy.VerdictDeny {
		return Result{Outcome: OutcomeDenied, Decision: decision}, nil
	}
	if duplicate {
		return Result{
			Command:   record.Command,
			Outcome:   existingOutcome(record),
			Decision:  decision,
			Duplicate: true,
		}, nil
	}
	if decision.Verdict == policy.VerdictAwaitApproval {
		return Result{Command: record.Command, Outcome: OutcomeAwaitApproval, Decision: decision}, nil
	}
	if decision.Verdict != policy.VerdictAllow {
		return Result{}, ErrInvalidRequest
	}
	return c.execute(ctx, request, record)
}

// Reconcile reads interrupted executable commands after process restart. It
// never calls Adapter.Execute: every unresolved command is retained in the
// verify_and_notify phase even when Docker state cannot be read.
func (c *Coordinator) Reconcile(ctx context.Context) ([]ReconciliationResult, error) {
	if c == nil || ctx == nil {
		return nil, ErrInvalidRequest
	}
	records, err := c.reconcilableRecords()
	if err != nil {
		return nil, err
	}
	results := make([]ReconciliationResult, 0, len(records))
	for _, stored := range records {
		now, err := c.now()
		if err != nil {
			return nil, err
		}
		snapshot, verifyErr := c.adapter.Verify(ctx, stored.record.Target)
		verified := verifyErr == nil && snapshot.TargetID == stored.record.Command.TargetID
		if !verified {
			snapshot = docker.Snapshot{}
		}
		updated, err := c.markVerifyAndNotify(stored.key, snapshot, verified, now)
		if err != nil {
			return nil, err
		}
		result := ReconciliationResult{
			Command:  updated.Command,
			Outcome:  OutcomeVerifyAndNotify,
			Verified: updated.Reconciliation.Verified,
		}
		if result.Verified {
			result.Snapshot = updated.Reconciliation.Snapshot
		}
		results = append(results, result)
	}
	return results, nil
}

func (c *Coordinator) prepare(request Request, now time.Time) (journalRecord, bool, policy.Decision, error) {
	commandID, err := c.newCommandID()
	if err != nil {
		return journalRecord{}, false, policy.Decision{}, fmt.Errorf("create recovery command ID: %w", err)
	}
	if !validToken(commandID, maxCommandIDLength) {
		return journalRecord{}, false, policy.Decision{}, ErrInvalidOptions
	}
	input := policyInput(request, commandID, now)
	decision := policy.Evaluate(request.PolicySnapshot, input)
	if decision.Verdict == policy.VerdictDeny {
		return journalRecord{}, false, decision, nil
	}
	registered, found := registeredRunbook(request.PolicySnapshot, input.RunbookID)
	if !found || input.ActionIndex < 0 || input.ActionIndex >= len(registered.Runbook.TypedActions) {
		return journalRecord{}, false, policy.Decision{}, ErrInvalidRequest
	}
	approvalID := ""
	if input.Approval != nil {
		approvalID = input.Approval.ApprovalID
	}
	phase := phasePending
	if decision.Verdict == policy.VerdictAwaitApproval {
		phase = phaseAwaitingApproval
	}
	record := journalRecord{
		SchemaVersion: contract.SchemaVersionV1,
		Command: contract.RecoveryCommand{
			SchemaVersion:  contract.SchemaVersionV1,
			CommandID:      commandID,
			IncidentID:     request.IncidentID,
			RunbookID:      input.RunbookID,
			RunbookDigest:  input.RunbookDigest,
			TargetID:       request.Target.TargetID,
			ActionIndex:    input.ActionIndex,
			RiskTier:       registered.Runbook.RiskTier,
			ApprovalID:     approvalID,
			IssuedAt:       now,
			ExpiresAt:      request.ExpiresAt.UTC(),
			IdempotencyKey: request.IdempotencyKey,
			State:          contract.RecoveryPending,
		},
		Target: cloneTarget(request.Target),
		Action: registered.Runbook.TypedActions[input.ActionIndex],
		Phase:  phase,
	}
	persisted, duplicate, err := c.persistPending(record)
	if err != nil {
		return journalRecord{}, false, policy.Decision{}, err
	}
	return persisted, duplicate, decision, nil
}

func (c *Coordinator) execute(ctx context.Context, request Request, record journalRecord) (Result, error) {
	now, err := c.now()
	if err != nil {
		return Result{}, err
	}
	if !now.Before(record.Command.ExpiresAt) {
		updated, updateErr := c.expire(recordKey(record.Command))
		if updateErr != nil {
			return Result{}, updateErr
		}
		return Result{Command: updated.Command, Outcome: OutcomeExpired}, nil
	}

	decision := c.revalidate(request, record, now)
	if decision.Verdict != policy.VerdictAllow {
		updated, updateErr := c.deny(recordKey(record.Command))
		if updateErr != nil {
			return Result{}, updateErr
		}
		return Result{Command: updated.Command, Outcome: OutcomeDenied, Decision: decision}, nil
	}
	if err := c.adapter.ValidateAction(ctx, record.Target, record.Action); err != nil {
		updated, updateErr := c.deny(recordKey(record.Command))
		if updateErr != nil {
			return Result{}, updateErr
		}
		return Result{Command: updated.Command, Outcome: OutcomeDenied, Decision: decision}, fmt.Errorf("validate recovery action: %w", err)
	}

	if _, err := c.approve(recordKey(record.Command)); err != nil {
		return Result{}, err
	}
	executing, err := c.startExecution(recordKey(record.Command))
	if err != nil {
		return Result{}, err
	}
	if err := c.adapter.Execute(ctx, executing.Target, executing.Action); err != nil {
		uncertain, updateErr := c.markVerifyAndNotify(recordKey(record.Command), docker.Snapshot{}, false, now)
		if updateErr != nil {
			return Result{}, updateErr
		}
		return Result{Command: uncertain.Command, Outcome: OutcomeVerifyAndNotify, Decision: decision}, fmt.Errorf("execute recovery action: %w", err)
	}
	succeeded, err := c.finishExecution(recordKey(record.Command), contract.RecoverySucceeded)
	if err != nil {
		return Result{}, err
	}
	return Result{Command: succeeded.Command, Outcome: OutcomeExecuted, Decision: decision}, nil
}

func (c *Coordinator) revalidate(request Request, record journalRecord, now time.Time) policy.Decision {
	command := record.Command
	if request.PolicyInput.RunbookID != command.RunbookID || request.PolicyInput.RunbookDigest != command.RunbookDigest || request.PolicyInput.TargetID != command.TargetID || request.PolicyInput.ActionIndex != command.ActionIndex || !sameExecutionTarget(request.Target, record.Target) {
		return policy.Decision{Verdict: policy.VerdictDeny, ReasonCode: policy.ReasonInvalidPolicy}
	}
	registered, found := registeredRunbook(request.PolicySnapshot, command.RunbookID)
	if !found || command.ActionIndex < 0 || command.ActionIndex >= len(registered.Runbook.TypedActions) || registered.Runbook.TypedActions[command.ActionIndex] != record.Action {
		return policy.Decision{Verdict: policy.VerdictDeny, ReasonCode: policy.ReasonInvalidPolicy}
	}
	return policy.Evaluate(request.PolicySnapshot, policyInput(request, command.CommandID, now))
}

func sameExecutionTarget(current, recorded contract.ServiceTarget) bool {
	return current.SchemaVersion == recorded.SchemaVersion && current.TargetID == recorded.TargetID && current.AdapterType == recorded.AdapterType && current.Selector == recorded.Selector && current.Enabled == recorded.Enabled
}

func policyInput(request Request, commandID string, now time.Time) policy.Input {
	input := request.PolicyInput
	input.CommandID = commandID
	input.Now = now
	return input
}

func registeredRunbook(snapshot policy.Snapshot, runbookID string) (policy.RegisteredRunbook, bool) {
	for _, registered := range snapshot.Runbooks {
		if registered.Runbook.RunbookID == runbookID {
			return registered, true
		}
	}
	return policy.RegisteredRunbook{}, false
}

func existingOutcome(record journalRecord) Outcome {
	if record.Phase == phaseAwaitingApproval {
		return OutcomeAwaitApproval
	}
	if record.Phase == phaseVerifyAndNotify {
		return OutcomeVerifyAndNotify
	}
	return OutcomeDuplicate
}

func (c *Coordinator) now() (time.Time, error) {
	if c == nil || c.clock == nil {
		return time.Time{}, ErrInvalidOptions
	}
	now := c.clock.Now().UTC()
	if now.IsZero() {
		return time.Time{}, ErrInvalidOptions
	}
	return now, nil
}

func validateRequest(request Request) error {
	input := request.PolicyInput
	if !validToken(request.IncidentID, maxCommandIDLength) || !validToken(request.IdempotencyKey, maxIdempotencyKeyLength) || !validToken(input.RunbookID, maxCommandIDLength) || !validToken(input.RunbookDigest, maxIdempotencyKeyLength) || !validToken(input.TargetID, maxCommandIDLength) || input.ActionIndex < 0 || input.CommandID != "" || request.ExpiresAt.IsZero() {
		return ErrInvalidRequest
	}
	if request.Target.SchemaVersion != contract.SchemaVersionV1 || request.Target.TargetID != input.TargetID || request.Target.AdapterType != docker.AdapterType || !request.Target.Enabled || !validToken(request.Target.Selector, maxIdempotencyKeyLength) {
		return ErrInvalidRequest
	}
	return nil
}

func validToken(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

func cloneTarget(target contract.ServiceTarget) contract.ServiceTarget {
	clone := target
	clone.ProbeRules = append([]contract.ProbeRule(nil), target.ProbeRules...)
	return clone
}
