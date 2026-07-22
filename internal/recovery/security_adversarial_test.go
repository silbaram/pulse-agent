package recovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/policy"
	"pulse-agent/internal/store"
)

const (
	recoveryPolicyAuthorizationCorpusSize = 18
	recoveryApprovalReplayCorpusSize      = 4
	recoveryForeignApprovalCorpusSize     = 1
	recoveryAuthorizationCorpusSize       = recoveryPolicyAuthorizationCorpusSize + recoveryApprovalReplayCorpusSize + recoveryForeignApprovalCorpusSize
)

func TestCoordinator_AuthorizationCorpusDeniesBeforeJournalAndDocker(t *testing.T) {
	now := testNow()
	tests := []struct {
		name       string
		mutate     func(*Request)
		wantReason policy.ReasonCode
	}{
		{name: "forged requested runbook digest", mutate: func(request *Request) { request.PolicyInput.RunbookDigest = "forged-digest" }, wantReason: policy.ReasonForgedDigest},
		{name: "forged registered runbook digest", mutate: func(request *Request) { request.PolicySnapshot.Runbooks[0].Runbook.Digest = "forged-digest" }, wantReason: policy.ReasonForgedDigest},
		{name: "forged requested target", mutate: func(request *Request) {
			request.Target.TargetID = "target-other"
			request.PolicyInput.TargetID = "target-other"
		}, wantReason: policy.ReasonTargetMismatch},
		{name: "forged registered target", mutate: func(request *Request) { request.PolicySnapshot.Runbooks[0].TargetID = "target-other" }, wantReason: policy.ReasonTargetMismatch},
		{name: "unregistered runbook", mutate: func(request *Request) { request.PolicyInput.RunbookID = "restart-unregistered" }, wantReason: policy.ReasonUnregisteredRunbook},
		{name: "out of range action", mutate: func(request *Request) { request.PolicyInput.ActionIndex = 1 }, wantReason: policy.ReasonActionInvalid},
		{name: "exec action in snapshot", mutate: func(request *Request) {
			request.PolicySnapshot.Runbooks[0].Runbook.TypedActions[0].ActionType = "docker.container.exec"
		}, wantReason: policy.ReasonInvalidPolicy},
		{name: "duplicate authorized approver", mutate: func(request *Request) {
			request.PolicySnapshot.AuthorizedApprovers = []string{"operator-1", "operator-1"}
		}, wantReason: policy.ReasonInvalidPolicy},
		{name: "analysis runbook mismatch", mutate: func(request *Request) {
			request.PolicySnapshot.Runbooks[0].AnalysisRequired = true
			request.PolicyInput.AnalysisAvailable = true
			request.PolicyInput.AnalysisCandidateIDs = []string{"restart-other"}
		}, wantReason: policy.ReasonAnalysisMismatch},
		{name: "failed precondition", mutate: func(request *Request) { request.PolicyInput.Preconditions["docker_healthy"] = false }, wantReason: policy.ReasonPreconditionFailed},
		{name: "retry budget exhausted", mutate: func(request *Request) {
			request.PolicyInput.AttemptCount = request.PolicySnapshot.Runbooks[0].Runbook.RetryPolicy.MaxAttempts
		}, wantReason: policy.ReasonRetryExhausted},
		{name: "invalid stabilization", mutate: func(request *Request) {
			request.PolicySnapshot.Runbooks[0].Runbook.StabilizationPolicy.Window = contract.NewDuration(0)
		}, wantReason: policy.ReasonStabilizationInvalid},
		{name: "approval for another command", mutate: func(request *Request) {
			requireSecurityApproval(request, securityApproval(now, "command-other", contract.ApprovalGranted, approvalTestActor))
		}, wantReason: policy.ReasonApprovalExpired},
		{name: "approval by unauthorized actor", mutate: func(request *Request) {
			requireSecurityApproval(request, securityApproval(now, "command-1", contract.ApprovalGranted, "uid:2000/gid:2000"))
		}, wantReason: policy.ReasonApprovalRevoked},
		{name: "revoked approval", mutate: func(request *Request) {
			requireSecurityApproval(request, securityApproval(now, "command-1", contract.ApprovalGranted, approvalTestActor))
			request.PolicyInput.ApprovalRevoked = true
		}, wantReason: policy.ReasonApprovalRevoked},
		{name: "denied approval", mutate: func(request *Request) {
			requireSecurityApproval(request, securityApproval(now, "command-1", contract.ApprovalDenied, approvalTestActor))
		}, wantReason: policy.ReasonApprovalDenied},
		{name: "expired approval", mutate: func(request *Request) {
			approval := securityApproval(now, "command-1", contract.ApprovalGranted, approvalTestActor)
			approval.ExpiresAt = now
			requireSecurityApproval(request, approval)
		}, wantReason: policy.ReasonApprovalExpired},
		{name: "unsupported approval schema", mutate: func(request *Request) {
			approval := securityApproval(now, "command-1", contract.ApprovalGranted, approvalTestActor)
			approval.SchemaVersion = "v2"
			requireSecurityApproval(request, approval)
		}, wantReason: policy.ReasonApprovalExpired},
	}
	if got := len(tests); got != recoveryPolicyAuthorizationCorpusSize {
		t.Fatalf("recovery policy authorization corpus size = %d, want %d", got, recoveryPolicyAuthorizationCorpusSize)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := openState(t)
			adapter := &fakeAdapter{}
			publisher := &securityLifecyclePublisher{}
			coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now}})
			coordinator.publisher = publisher
			request := testRequest(now)
			test.mutate(&request)

			result, err := coordinator.Submit(context.Background(), request)
			if err != nil {
				t.Fatalf("Submit() error = %v", err)
			}
			if result.Outcome != OutcomeDenied || result.Decision.ReasonCode != test.wantReason {
				t.Fatalf("Submit() = %#v, want denied reason %q", result, test.wantReason)
			}
			if adapter.validateCalls != 0 || adapter.executeCalls != 0 {
				t.Fatalf("adapter calls = validate %d execute %d, want 0/0 for reason %q", adapter.validateCalls, adapter.executeCalls, test.wantReason)
			}
			if got := countSecurityRecords(t, state, store.BucketCommandJournal); got != 0 {
				t.Fatalf("command journal records = %d, want 0 before authorized state mutation", got)
			}
			if len(publisher.deniedReasons) != 1 || publisher.deniedReasons[0] != string(test.wantReason) {
				t.Fatalf("published policy reasons = %#v, want [%q]", publisher.deniedReasons, test.wantReason)
			}
		})
	}
}

func TestApprovalManager_ReplayCorpusIsAuditedWithoutDocker(t *testing.T) {
	now := testNow()
	tests := []struct {
		name   string
		first  contract.ApprovalDecision
		replay contract.ApprovalDecision
	}{
		{name: "grant then grant", first: contract.ApprovalGranted, replay: contract.ApprovalGranted},
		{name: "grant then deny", first: contract.ApprovalGranted, replay: contract.ApprovalDenied},
		{name: "deny then deny", first: contract.ApprovalDenied, replay: contract.ApprovalDenied},
		{name: "deny then grant", first: contract.ApprovalDenied, replay: contract.ApprovalGranted},
	}
	if got := len(tests); got != recoveryApprovalReplayCorpusSize || recoveryAuthorizationCorpusSize != 23 {
		t.Fatalf("approval replay corpus size = %d, total = %d; want %d and 23", got, recoveryAuthorizationCorpusSize, recoveryApprovalReplayCorpusSize)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := openState(t)
			manager := newApprovalManager(t, state, ClockFunc(func() time.Time { return now }))
			command, _, adapter := waitingApprovalCommand(t, state, manager, now)
			first, err := manager.Decide(securityDecisionRequest(command.CommandID, test.first, now, "request-first"))
			if err != nil {
				t.Fatalf("Decide(first) error = %v", err)
			}
			if _, err := manager.Decide(securityDecisionRequest(command.CommandID, test.replay, now, "request-replay")); !errors.Is(err, ErrApprovalConflict) {
				t.Fatalf("Decide(replay) error = %v, want %v", err, ErrApprovalConflict)
			}
			persisted, found, err := manager.LoadApproval(command.CommandID)
			if err != nil || !found || persisted.ApprovalID != first.Approval.ApprovalID || persisted.Decision != test.first {
				t.Fatalf("LoadApproval() = %#v, found=%t, error=%v; want immutable first decision %#v", persisted, found, err, first.Approval)
			}
			if adapter.executeCalls != 0 {
				t.Fatalf("Docker Execute() calls = %d, want 0 for replay", adapter.executeCalls)
			}
			events := readApprovalAuditEvents(t, state)
			if len(events) != 2 || events[1].Result != approvalAuditRejected || events[1].ReasonCode != approvalAuditConflict {
				t.Fatalf("approval audit events = %#v, want replay reason %q", events, approvalAuditConflict)
			}
		})
	}
}

func TestCoordinator_ForeignApprovalIDIsDeniedBeforeDocker(t *testing.T) {
	if recoveryForeignApprovalCorpusSize != 1 {
		t.Fatalf("foreign approval corpus size = %d, want 1", recoveryForeignApprovalCorpusSize)
	}
	now := testNow()
	state := openState(t)
	manager := newApprovalManager(t, state, ClockFunc(func() time.Time { return now }))
	first, coordinator, adapter := waitingApprovalCommand(t, state, manager, now)
	secondRequest := highRiskRequest(now)
	secondRequest.IncidentID = "incident-security-second"
	secondRequest.IdempotencyKey = "delivery-security-second"
	second, err := coordinator.Submit(context.Background(), secondRequest)
	if err != nil || second.Outcome != OutcomeAwaitApproval {
		t.Fatalf("Submit(second) = %#v, %v, want approval wait", second, err)
	}
	granted, err := grantApproval(manager, first.CommandID, now, "request-security-first")
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
	if err != nil || result.Outcome != OutcomeDenied || result.Decision.ReasonCode != policy.ReasonApprovalRevoked {
		t.Fatalf("Resume(foreign approval) = %#v, %v, want denied reason %q", result, err, policy.ReasonApprovalRevoked)
	}
	if adapter.executeCalls != 0 {
		t.Fatalf("Docker Execute() calls = %d, want 0 for foreign approval", adapter.executeCalls)
	}
}

type securityLifecyclePublisher struct {
	deniedReasons []string
}

func (p *securityLifecyclePublisher) PublishAnalysisUnavailable(context.Context, string, string, string) error {
	return nil
}

func (p *securityLifecyclePublisher) PublishPolicyDenied(_ context.Context, _, _ string, reason string) error {
	p.deniedReasons = append(p.deniedReasons, reason)
	return nil
}

func (p *securityLifecyclePublisher) PublishApprovalRequested(context.Context, contract.RecoveryCommand) error {
	return nil
}

func (p *securityLifecyclePublisher) PublishRecoveryStarted(context.Context, contract.RecoveryCommand) error {
	return nil
}

func securityApproval(now time.Time, commandID string, decision contract.ApprovalDecision, actor string) contract.Approval {
	return contract.Approval{
		SchemaVersion:    contract.SchemaVersionV1,
		ApprovalID:       "approval-security",
		CommandID:        commandID,
		Decision:         decision,
		ApproverIdentity: actor,
		CreatedAt:        now.Add(-time.Minute),
		ExpiresAt:        now.Add(time.Minute),
	}
}

func requireSecurityApproval(request *Request, approval contract.Approval) {
	request.PolicySnapshot.Runbooks[0].Runbook.RiskTier = contract.RiskHigh
	request.PolicySnapshot.Runbooks[0].Runbook.AutoExecute = false
	request.PolicySnapshot.AuthorizedApprovers = []string{approvalTestActor}
	request.PolicyInput.Approval = &approval
}

func securityDecisionRequest(commandID string, decision contract.ApprovalDecision, now time.Time, requestID string) ApprovalDecisionRequest {
	return ApprovalDecisionRequest{
		CommandID:     commandID,
		Decision:      decision,
		ActorIdentity: approvalTestActor,
		RequestID:     requestID,
		ReasonCode:    "operator_requested",
		ExpiresAt:     now.Add(time.Minute),
	}
}

func countSecurityRecords(t *testing.T, state *store.Store, bucket store.Bucket) int {
	t.Helper()
	count := 0
	if err := state.View(func(tx *store.Tx) error {
		return tx.ForEach(bucket, func(string, []byte) error {
			count++
			return nil
		})
	}); err != nil {
		t.Fatalf("count %s records: %v", bucket, err)
	}
	return count
}
