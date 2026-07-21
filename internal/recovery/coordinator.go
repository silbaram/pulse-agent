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
// before an action. Execute must repeat adapter-owned dynamic target checks in
// its bounded operation, remain limited to the supplied typed action, and
// Verify must return only bounded Docker state.
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

// StateSource loads the daemon-owned current execution facts for one command.
// Each Load call must return a fresh immutable snapshot; a request's initial
// policy and target fields are never authoritative for Adapter.Execute.
type StateSource interface {
	// Load returns the current target, registered policy, and dynamic policy facts.
	Load(context.Context, contract.RecoveryCommand) (ExecutionState, error)
}

// LifecyclePublisher records required lifecycle events before recovery may
// advance. It must durably enqueue each event but must not perform HTTP I/O.
type LifecyclePublisher interface {
	// PublishAnalysisUnavailable records a model-unavailable event for one request.
	PublishAnalysisUnavailable(context.Context, string, string, string) error
	// PublishPolicyDenied records a policy denial for one request.
	PublishPolicyDenied(context.Context, string, string, string) error
	// PublishApprovalRequested records a pending approval for a durable command.
	PublishApprovalRequested(context.Context, contract.RecoveryCommand) error
	// PublishRecoveryStarted records a durable pre-Docker event for a command.
	PublishRecoveryStarted(context.Context, contract.RecoveryCommand) error
}

// ExecutionState is the current daemon-owned authorization context for one
// persisted recovery command. Its fields are read-only at the coordinator
// boundary and must describe the same runbook, target, and action as Command.
type ExecutionState struct {
	// Target is the latest registered Docker target.
	Target contract.ServiceTarget
	// PolicySnapshot is the latest registered policy and runbook view.
	PolicySnapshot policy.Snapshot
	// PolicyInput contains the latest dynamic preconditions and retry facts.
	PolicyInput policy.Input
}

// Options configures one daemon-owned recovery coordinator.
type Options struct {
	// State is the daemon-owned store holding the command journal.
	State *store.Store
	// Adapter applies only already-validated Docker actions.
	Adapter Adapter
	// StateSource reloads the latest daemon-owned execution facts before an action.
	StateSource StateSource
	// Clock supplies deterministic issuance, expiry, and reconciliation times.
	Clock Clock
	// NewCommandID creates an immutable identifier for a new recovery command.
	NewCommandID func() (string, error)
	// LifecyclePublisher records durable events before recovery advances. Nil
	// preserves the coordinator-only embedding used before notification wiring.
	LifecyclePublisher LifecyclePublisher
}

// Coordinator persists a recovery command before invoking a Docker adapter.
// Its zero value is invalid; callers must construct it with New.
type Coordinator struct {
	state        *store.Store
	adapter      Adapter
	stateSource  StateSource
	clock        Clock
	newCommandID func() (string, error)
	publisher    LifecyclePublisher
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
	// PolicySnapshot is the initial registered-runbook snapshot used to prepare
	// the pending command. StateSource supplies the authoritative execution view.
	PolicySnapshot policy.Snapshot
	// PolicyInput contains the initial dynamic authorization facts used to prepare
	// the pending command. StateSource supplies the authoritative execution view.
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
	// OutcomeStabilizing identifies a command that now waits for post-recovery verification.
	OutcomeStabilizing Outcome = "stabilizing"
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
	if options.State == nil || options.Adapter == nil || options.StateSource == nil || options.Clock == nil || options.NewCommandID == nil {
		return nil, ErrInvalidOptions
	}
	return &Coordinator{
		state:        options.State,
		adapter:      options.Adapter,
		stateSource:  options.StateSource,
		clock:        options.Clock,
		newCommandID: options.NewCommandID,
		publisher:    options.LifecyclePublisher,
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
	if !request.PolicyInput.AnalysisAvailable {
		if err := c.publishAnalysisUnavailable(ctx, request); err != nil {
			return Result{}, err
		}
	}

	record, duplicate, decision, err := c.prepare(request, now)
	if err != nil {
		return Result{}, err
	}
	if decision.Verdict == policy.VerdictDeny {
		if err := c.publishPolicyDenied(ctx, request, decision); err != nil {
			return Result{}, err
		}
		return Result{Outcome: OutcomeDenied, Decision: decision}, nil
	}
	if duplicate {
		if decision.Verdict == policy.VerdictAwaitApproval {
			if err := c.publishApprovalRequested(ctx, record.Command); err != nil {
				return Result{}, err
			}
		}
		return Result{
			Command:   record.Command,
			Outcome:   existingOutcome(record),
			Decision:  decision,
			Duplicate: true,
		}, nil
	}
	if decision.Verdict == policy.VerdictAwaitApproval {
		if err := c.publishApprovalRequested(ctx, record.Command); err != nil {
			return Result{}, err
		}
		return Result{Command: record.Command, Outcome: OutcomeAwaitApproval, Decision: decision}, nil
	}
	if decision.Verdict != policy.VerdictAllow {
		return Result{}, ErrInvalidRequest
	}
	return c.execute(ctx, record)
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

// Resume executes one locally granted command after loading the current
// daemon-owned state. A command without a durable local grant remains in the
// approval wait state and never reaches the Docker adapter.
func (c *Coordinator) Resume(ctx context.Context, commandID string) (Result, error) {
	if c == nil || ctx == nil || !validToken(commandID, maxCommandIDLength) {
		return Result{}, ErrInvalidRequest
	}
	var stored storedRecord
	found := false
	err := c.state.View(func(transaction *store.Tx) error {
		var err error
		stored, found, err = findRecordByCommandID(transaction, commandID)
		return err
	})
	if err != nil {
		return Result{}, fmt.Errorf("read recovery command: %w", err)
	}
	if !found {
		return Result{}, ErrInvalidRequest
	}
	if stored.record.Phase == phaseAwaitingApproval && stored.record.Command.State == contract.RecoveryPending {
		if stored.record.Command.ApprovalID == "" {
			return Result{Command: stored.record.Command, Outcome: OutcomeAwaitApproval}, nil
		}
		return c.execute(ctx, stored.record)
	}
	return Result{Command: stored.record.Command, Outcome: existingOutcome(stored.record), Duplicate: true}, nil
}

func (c *Coordinator) prepare(request Request, now time.Time) (journalRecord, bool, policy.Decision, error) {
	commandID, err := c.newCommandID()
	if err != nil {
		return journalRecord{}, false, policy.Decision{}, fmt.Errorf("create recovery command ID: %w", err)
	}
	if !validToken(commandID, maxCommandIDLength) {
		return journalRecord{}, false, policy.Decision{}, ErrInvalidOptions
	}
	input := policyInput(request.PolicyInput, commandID, now)
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

func (c *Coordinator) execute(ctx context.Context, record journalRecord) (Result, error) {
	decision, now, expired, err := c.revalidate(ctx, record)
	if err != nil {
		return c.denyAfterRevalidation(record, decision, err)
	}
	if expired {
		updated, updateErr := c.expire(recordKey(record.Command))
		if updateErr != nil {
			return Result{}, updateErr
		}
		return Result{Command: updated.Command, Outcome: OutcomeExpired}, nil
	}
	if decision.Verdict != policy.VerdictAllow {
		return c.denyAfterRevalidation(record, decision, nil)
	}
	if err := c.adapter.ValidateAction(ctx, record.Target, record.Action); err != nil {
		return c.denyAfterRevalidation(record, decision, fmt.Errorf("validate recovery action: %w", err))
	}

	decision, now, expired, err = c.revalidate(ctx, record)
	if err != nil {
		return c.denyAfterRevalidation(record, decision, err)
	}
	if expired {
		updated, updateErr := c.expire(recordKey(record.Command))
		if updateErr != nil {
			return Result{}, updateErr
		}
		return Result{Command: updated.Command, Outcome: OutcomeExpired}, nil
	}
	if decision.Verdict != policy.VerdictAllow {
		return c.denyAfterRevalidation(record, decision, nil)
	}
	if err := c.publishRecoveryStarted(ctx, record.Command); err != nil {
		return Result{Command: record.Command, Decision: decision}, fmt.Errorf("publish recovery started: %w", err)
	}

	if record.Phase != phaseApproved {
		if _, err := c.approve(recordKey(record.Command)); err != nil {
			return Result{}, err
		}
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
	stabilizing, err := c.finishExecution(recordKey(record.Command), contract.RecoveryStabilizing)
	if err != nil {
		return Result{}, err
	}
	return Result{Command: stabilizing.Command, Outcome: OutcomeStabilizing, Decision: decision}, nil
}

func (c *Coordinator) publishAnalysisUnavailable(ctx context.Context, request Request) error {
	if c.publisher == nil {
		return nil
	}
	if err := c.publisher.PublishAnalysisUnavailable(ctx, request.IncidentID, request.IdempotencyKey, "analysis_unavailable"); err != nil {
		return fmt.Errorf("publish analysis unavailable: %w", err)
	}
	return nil
}

func (c *Coordinator) publishPolicyDenied(ctx context.Context, request Request, decision policy.Decision) error {
	if c.publisher == nil {
		return nil
	}
	if err := c.publisher.PublishPolicyDenied(ctx, request.IncidentID, request.IdempotencyKey, string(decision.ReasonCode)); err != nil {
		return fmt.Errorf("publish policy denied: %w", err)
	}
	return nil
}

func (c *Coordinator) publishApprovalRequested(ctx context.Context, command contract.RecoveryCommand) error {
	if c.publisher == nil {
		return nil
	}
	if err := c.publisher.PublishApprovalRequested(ctx, command); err != nil {
		return fmt.Errorf("publish approval requested: %w", err)
	}
	return nil
}

func (c *Coordinator) publishRecoveryStarted(ctx context.Context, command contract.RecoveryCommand) error {
	if c.publisher == nil {
		return nil
	}
	if err := c.publisher.PublishRecoveryStarted(ctx, command); err != nil {
		return fmt.Errorf("publish recovery started: %w", err)
	}
	return nil
}

// CompleteStabilization records the terminal result of a separate post-recovery
// verifier. Repeating the same terminal result is idempotent so a verifier can
// recover from a persistence failure without changing the recovery outcome.
// A successful Docker API response alone cannot complete a command.
func (c *Coordinator) CompleteStabilization(commandID string, succeeded bool) (contract.RecoveryCommand, error) {
	if c == nil || !validToken(commandID, maxCommandIDLength) {
		return contract.RecoveryCommand{}, ErrInvalidRequest
	}
	var stored storedRecord
	found := false
	err := c.state.View(func(transaction *store.Tx) error {
		var findErr error
		stored, found, findErr = findRecordByCommandID(transaction, commandID)
		return findErr
	})
	if err != nil {
		return contract.RecoveryCommand{}, fmt.Errorf("read recovery command: %w", err)
	}
	if !found {
		return contract.RecoveryCommand{}, ErrInvalidRequest
	}
	next := contract.RecoveryFailed
	if succeeded {
		next = contract.RecoverySucceeded
	}
	if stored.record.Phase == phaseCompleted && stored.record.Command.State == next {
		return stored.record.Command, nil
	}
	completed, err := c.completeStabilization(stored.key, next)
	if err != nil {
		return contract.RecoveryCommand{}, err
	}
	return completed.Command, nil
}

func (c *Coordinator) denyAfterRevalidation(record journalRecord, decision policy.Decision, cause error) (Result, error) {
	updated, updateErr := c.deny(recordKey(record.Command))
	if updateErr != nil {
		return Result{}, updateErr
	}
	result := Result{Command: updated.Command, Outcome: OutcomeDenied, Decision: decision}
	return result, cause
}

func (c *Coordinator) revalidate(ctx context.Context, record journalRecord) (policy.Decision, time.Time, bool, error) {
	state, err := c.stateSource.Load(ctx, record.Command)
	if err != nil {
		return policy.Decision{Verdict: policy.VerdictDeny, ReasonCode: policy.ReasonInvalidPolicy}, time.Time{}, false, fmt.Errorf("load current recovery state: %w", err)
	}
	now, err := c.now()
	if err != nil {
		return policy.Decision{}, time.Time{}, false, err
	}
	if !now.Before(record.Command.ExpiresAt) {
		return policy.Decision{}, now, true, nil
	}
	return revalidateState(state, record, now), now, false, nil
}

func revalidateState(state ExecutionState, record journalRecord, now time.Time) policy.Decision {
	command := record.Command
	if state.PolicyInput.RunbookID != command.RunbookID || state.PolicyInput.RunbookDigest != command.RunbookDigest || state.PolicyInput.TargetID != command.TargetID || state.PolicyInput.ActionIndex != command.ActionIndex || !sameExecutionTarget(state.Target, record.Target) {
		return policy.Decision{Verdict: policy.VerdictDeny, ReasonCode: policy.ReasonInvalidPolicy}
	}
	registered, found := registeredRunbook(state.PolicySnapshot, command.RunbookID)
	if !found || command.ActionIndex < 0 || command.ActionIndex >= len(registered.Runbook.TypedActions) || registered.Runbook.TypedActions[command.ActionIndex] != record.Action {
		return policy.Decision{Verdict: policy.VerdictDeny, ReasonCode: policy.ReasonInvalidPolicy}
	}
	return policy.Evaluate(state.PolicySnapshot, policyInput(state.PolicyInput, command.CommandID, now))
}

func sameExecutionTarget(current, recorded contract.ServiceTarget) bool {
	return current.SchemaVersion == recorded.SchemaVersion && current.TargetID == recorded.TargetID && current.AdapterType == recorded.AdapterType && current.Selector == recorded.Selector && current.Enabled == recorded.Enabled
}

func policyInput(input policy.Input, commandID string, now time.Time) policy.Input {
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
	if record.Phase == phaseStabilizing {
		return OutcomeStabilizing
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
