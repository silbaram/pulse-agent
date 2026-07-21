package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/docker"
	"pulse-agent/internal/policy"
	"pulse-agent/internal/store"
)

const approvalTestActor = "uid:1000/gid:1000"

func TestApprovalManager_GrantIsAuditedAndReplayIsRejected(t *testing.T) {
	now := testNow()
	state := openState(t)
	manager := newApprovalManager(t, state, ClockFunc(func() time.Time { return now }))
	request, coordinator, _ := waitingApprovalCommand(t, state, manager, now)

	granted, err := manager.Decide(ApprovalDecisionRequest{
		CommandID:     request.CommandID,
		Decision:      contract.ApprovalGranted,
		ActorIdentity: approvalTestActor,
		RequestID:     "request-grant-1",
		ReasonCode:    "operator_requested",
		ExpiresAt:     now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Decide(grant) error = %v", err)
	}
	if granted.Approval.Decision != contract.ApprovalGranted || granted.Command.ApprovalID != granted.Approval.ApprovalID || granted.Command.State != contract.RecoveryPending {
		t.Fatalf("grant result = %#v, want durable waiting command with matching approval", granted)
	}
	stored := readRecord(t, state, request)
	if stored.Phase != phaseAwaitingApproval || stored.Command.ApprovalID != granted.Approval.ApprovalID {
		t.Fatalf("stored command = %#v, want awaiting approval with durable grant", stored)
	}

	_, err = manager.Decide(ApprovalDecisionRequest{
		CommandID:     request.CommandID,
		Decision:      contract.ApprovalDenied,
		ActorIdentity: approvalTestActor,
		RequestID:     "request-deny-replay",
		ReasonCode:    "operator_requested",
		ExpiresAt:     now.Add(time.Minute),
	})
	if !errors.Is(err, ErrApprovalConflict) {
		t.Fatalf("Decide(replay) error = %v, want %v", err, ErrApprovalConflict)
	}
	if result, err := coordinator.Resume(context.Background(), request.CommandID); err != nil || result.Outcome != OutcomeStabilizing {
		t.Fatalf("Resume() = %#v, %v, want stabilizing after one local grant", result, err)
	}

	events := readApprovalAuditEvents(t, state)
	if len(events) != 2 {
		t.Fatalf("approval audit event count = %d, want 2", len(events))
	}
	if events[0].ActorIdentity != approvalTestActor || events[0].Action != approvalAuditAction || events[0].Result != approvalAuditAccepted || events[0].ReasonCode != "operator_requested" || events[0].OccurredAt.IsZero() {
		t.Fatalf("grant audit event = %#v, want authenticated actor, reason, time, and accepted result", events[0])
	}
	if events[1].ActorIdentity != approvalTestActor || events[1].Result != approvalAuditRejected || events[1].ReasonCode != approvalAuditConflict {
		t.Fatalf("replay audit event = %#v, want rejected conflict", events[1])
	}
}

func TestApprovalManager_ExpiredDecisionExpiresWaitingCommand(t *testing.T) {
	now := testNow()
	state := openState(t)
	manager := newApprovalManager(t, state, ClockFunc(func() time.Time { return now }))
	command, _, adapter := waitingApprovalCommand(t, state, manager, now)

	_, err := manager.Decide(ApprovalDecisionRequest{
		CommandID:     command.CommandID,
		Decision:      contract.ApprovalGranted,
		ActorIdentity: approvalTestActor,
		RequestID:     "request-expired",
		ReasonCode:    "operator_requested",
		ExpiresAt:     now,
	})
	if !errors.Is(err, ErrApprovalCommandExpired) {
		t.Fatalf("Decide(expired) error = %v, want %v", err, ErrApprovalCommandExpired)
	}
	stored := readRecord(t, state, command)
	if stored.Phase != phaseCompleted || stored.Command.State != contract.RecoveryExpired || adapter.executeCalls != 0 {
		t.Fatalf("stored command = %#v, execute calls=%d, want expired with no execution", stored, adapter.executeCalls)
	}
}

func TestCoordinator_ResumeRejectsRevokedAndForeignApprovals(t *testing.T) {
	now := testNow()
	t.Run("authorized approver revoked after grant", func(t *testing.T) {
		state := openState(t)
		manager := newApprovalManager(t, state, ClockFunc(func() time.Time { return now }))
		command, coordinator, adapter := waitingApprovalCommand(t, state, manager, now)
		if _, err := grantApproval(manager, command.CommandID, now, "request-grant-revoked"); err != nil {
			t.Fatalf("grant approval: %v", err)
		}
		decorated, ok := coordinator.stateSource.(ApprovalStateSource)
		if !ok {
			t.Fatalf("StateSource type = %T, want ApprovalStateSource", coordinator.stateSource)
		}
		source, ok := decorated.Source.(*fakeStateSource)
		if !ok {
			t.Fatalf("wrapped source type = %T, want *fakeStateSource", decorated.Source)
		}
		source.state.PolicySnapshot.AuthorizedApprovers = []string{"uid:2000/gid:2000"}

		result, err := coordinator.Resume(context.Background(), command.CommandID)
		if err != nil || result.Outcome != OutcomeDenied || result.Decision.ReasonCode != policy.ReasonApprovalRevoked || adapter.executeCalls != 0 {
			t.Fatalf("Resume() = %#v, %v, execute calls=%d; want revoked denial without execution", result, err, adapter.executeCalls)
		}
	})

	t.Run("approval ID from another command", func(t *testing.T) {
		state := openState(t)
		manager := newApprovalManager(t, state, ClockFunc(func() time.Time { return now }))
		first, coordinator, adapter := waitingApprovalCommand(t, state, manager, now)
		secondRequest := highRiskRequest(now)
		secondRequest.IncidentID = "incident-2"
		secondRequest.IdempotencyKey = "delivery-2"
		second, err := coordinator.Submit(context.Background(), secondRequest)
		if err != nil || second.Outcome != OutcomeAwaitApproval {
			t.Fatalf("Submit(second) = %#v, %v, want waiting approval", second, err)
		}
		granted, err := grantApproval(manager, first.CommandID, now, "request-grant-first")
		if err != nil {
			t.Fatalf("grant first approval: %v", err)
		}
		if _, err := coordinator.updateRecord(recordKey(second.Command), func(record *journalRecord) error {
			record.Command.ApprovalID = granted.ApprovalID
			return nil
		}); err != nil {
			t.Fatalf("inject foreign approval ID: %v", err)
		}

		result, err := coordinator.Resume(context.Background(), second.Command.CommandID)
		if err != nil || result.Outcome != OutcomeDenied || result.Decision.ReasonCode != policy.ReasonApprovalRevoked || adapter.executeCalls != 0 {
			t.Fatalf("Resume(foreign approval) = %#v, %v, execute calls=%d; want denied without execution", result, err, adapter.executeCalls)
		}
	})
}

func TestApprovalManager_ConcurrentRequestsPersistOneDecision(t *testing.T) {
	now := testNow()
	state := openState(t)
	manager := newApprovalManager(t, state, ClockFunc(func() time.Time { return now }))
	command, _, _ := waitingApprovalCommand(t, state, manager, now)

	const requests = 12
	var group sync.WaitGroup
	results := make(chan error, requests)
	for index := 0; index < requests; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			decision := contract.ApprovalGranted
			if index%2 == 1 {
				decision = contract.ApprovalDenied
			}
			_, err := manager.Decide(ApprovalDecisionRequest{
				CommandID:     command.CommandID,
				Decision:      decision,
				ActorIdentity: approvalTestActor,
				RequestID:     fmt.Sprintf("request-concurrent-%d", index),
				ReasonCode:    "operator_requested",
				ExpiresAt:     now.Add(time.Minute),
			})
			results <- err
		}(index)
	}
	group.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, ErrApprovalConflict) {
			t.Fatalf("concurrent Decide() error = %v, want conflict", err)
		}
	}
	if successes != 1 {
		t.Fatalf("accepted concurrent decisions = %d, want 1", successes)
	}
	approval, found, err := manager.LoadApproval(command.CommandID)
	if err != nil || !found || (approval.Decision != contract.ApprovalGranted && approval.Decision != contract.ApprovalDenied) {
		t.Fatalf("LoadApproval() = %#v, found=%t, err=%v, want one valid decision", approval, found, err)
	}
	if events := readApprovalAuditEvents(t, state); len(events) != requests {
		t.Fatalf("approval audit event count = %d, want %d", len(events), requests)
	}
}

func waitingApprovalCommand(t *testing.T, state *store.Store, manager *ApprovalManager, now time.Time) (contract.RecoveryCommand, *Coordinator, *fakeAdapter) {
	t.Helper()
	request := highRiskRequest(now)
	source := &fakeStateSource{state: executionState(request)}
	source.state.PolicySnapshot.AuthorizedApprovers = []string{approvalTestActor}
	adapter := &fakeAdapter{snapshot: docker.Snapshot{TargetID: request.Target.TargetID, Running: true, Healthy: true}}
	coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now, now, now}}, ApprovalStateSource{Source: source, Approvals: manager})
	result, err := coordinator.Submit(context.Background(), request)
	if err != nil || result.Outcome != OutcomeAwaitApproval {
		t.Fatalf("Submit() = %#v, %v, want waiting approval", result, err)
	}
	return result.Command, coordinator, adapter
}

func highRiskRequest(now time.Time) Request {
	request := testRequest(now)
	request.PolicySnapshot.Runbooks[0].Runbook.RiskTier = contract.RiskHigh
	request.PolicySnapshot.Runbooks[0].Runbook.AutoExecute = false
	return request
}

func grantApproval(manager *ApprovalManager, commandID string, now time.Time, requestID string) (contract.Approval, error) {
	result, err := manager.Decide(ApprovalDecisionRequest{
		CommandID:     commandID,
		Decision:      contract.ApprovalGranted,
		ActorIdentity: approvalTestActor,
		RequestID:     requestID,
		ReasonCode:    "operator_requested",
		ExpiresAt:     now.Add(time.Minute),
	})
	return result.Approval, err
}

func newApprovalManager(t *testing.T, state *store.Store, clock Clock) *ApprovalManager {
	t.Helper()
	manager, err := NewApprovalManager(ApprovalOptions{
		State:           state,
		Clock:           clock,
		NewApprovalID:   newApprovalTestIDGenerator("approval"),
		NewAuditEventID: newApprovalTestIDGenerator("approval-audit"),
	})
	if err != nil {
		t.Fatalf("NewApprovalManager() error = %v", err)
	}
	return manager
}

func newApprovalTestIDGenerator(prefix string) func() (string, error) {
	var mu sync.Mutex
	sequence := 0
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		sequence++
		return fmt.Sprintf("%s-%d", prefix, sequence), nil
	}
}

func readApprovalAuditEvents(t *testing.T, state *store.Store) []contract.AuditEvent {
	t.Helper()
	events := []contract.AuditEvent{}
	err := state.View(func(transaction *store.Tx) error {
		return transaction.ForEach(store.BucketAudit, func(_ string, document []byte) error {
			var event contract.AuditEvent
			if err := json.Unmarshal(document, &event); err != nil {
				return err
			}
			events = append(events, event)
			return nil
		})
	})
	if err != nil {
		t.Fatalf("read approval audit events: %v", err)
	}
	return events
}
