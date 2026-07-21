package adminipc

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/docker"
	"pulse-agent/internal/policy"
	"pulse-agent/internal/recovery"
	"pulse-agent/internal/store"
)

func TestClient_DecideApprovalUsesAuthenticatedLocalPeer(t *testing.T) {
	now := time.Date(2026, time.July, 21, 10, 0, 0, 0, time.UTC)
	state := openTestStore(t)
	manager, command := newWaitingApprovalForIPC(t, state, now)
	server, socketPath, stop := startApprovalTestServer(t, state, manager, time.Second, func(*net.UnixConn) (Actor, error) {
		return authorizedTestActor, nil
	})
	defer stop()
	client := newTestClient(t, time.Second)

	result, err := client.DecideApproval(context.Background(), socketPath, "operator_requested", command.CommandID, contract.ApprovalGranted, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("DecideApproval() error = %v", err)
	}
	if result.Decision != contract.ApprovalGranted || result.CommandID != command.CommandID || result.CommandState != contract.RecoveryPending {
		t.Fatalf("approval result = %#v, want durable local grant for waiting command", result)
	}
	approval, found, err := manager.LoadApproval(command.CommandID)
	if err != nil || !found || approval.ApproverIdentity != authorizedTestActor.Identity() || approval.Reason != "operator_requested" {
		t.Fatalf("LoadApproval() = %#v, found=%t, err=%v; want authenticated actor and reason", approval, found, err)
	}
	if _, err := client.DecideApproval(context.Background(), socketPath, "operator_requested", command.CommandID, contract.ApprovalDenied, now.Add(time.Minute)); !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("replayed DecideApproval() error = %v, want %v", err, ErrRequestRejected)
	}
	if !server.socketIsCurrent() {
		t.Fatal("approval server lost protected local socket ownership")
	}
}

func TestClient_DecideApprovalRejectsUnauthorizedPeer(t *testing.T) {
	now := time.Date(2026, time.July, 21, 10, 0, 0, 0, time.UTC)
	state := openTestStore(t)
	manager, command := newWaitingApprovalForIPC(t, state, now)
	unauthorized := Actor{UID: authorizedTestActor.UID + 1, GID: authorizedTestActor.GID}
	_, socketPath, stop := startApprovalTestServer(t, state, manager, time.Second, func(*net.UnixConn) (Actor, error) {
		return unauthorized, nil
	})
	defer stop()

	_, err := newTestClient(t, time.Second).DecideApproval(context.Background(), socketPath, "operator_requested", command.CommandID, contract.ApprovalGranted, now.Add(time.Minute))
	if !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("DecideApproval() error = %v, want %v", err, ErrRequestRejected)
	}
	if _, found, err := manager.LoadApproval(command.CommandID); err != nil || found {
		t.Fatalf("LoadApproval() found=%t err=%v, want no unauthorized state change", found, err)
	}
	events := readAuditEvents(t, state)
	if len(events) != 1 || events[0].ActorIdentity != unauthorized.Identity() || events[0].Result != auditResultRejected || events[0].ReasonCode != auditReasonUnauthorized {
		t.Fatalf("unauthorized approval audit = %#v, want authenticated peer rejection", events)
	}
}

func newWaitingApprovalForIPC(t *testing.T, state *store.Store, now time.Time) (*recovery.ApprovalManager, contract.RecoveryCommand) {
	t.Helper()
	target := testServiceTarget()
	runbook := testRunbook(t)
	runbook.RiskTier = contract.RiskHigh
	runbook.AutoExecute = false
	snapshot := policy.Snapshot{
		Runbooks:            []policy.RegisteredRunbook{{Runbook: runbook, TargetID: target.TargetID}},
		AuthorizedApprovers: []string{authorizedTestActor.Identity()},
	}
	input := policy.Input{
		RunbookID:     runbook.RunbookID,
		RunbookDigest: runbook.Digest,
		TargetID:      target.TargetID,
		ActionIndex:   0,
		Preconditions: map[string]bool{},
		AttemptCount:  0,
	}
	manager, err := recovery.NewApprovalManager(recovery.ApprovalOptions{
		State:           state,
		Clock:           recovery.ClockFunc(func() time.Time { return now }),
		NewApprovalID:   newTestIDGenerator("approval"),
		NewAuditEventID: newTestIDGenerator("approval-audit"),
	})
	if err != nil {
		t.Fatalf("NewApprovalManager() error = %v", err)
	}
	coordinator, err := recovery.New(recovery.Options{
		State:       state,
		Adapter:     approvalTestAdapter{},
		StateSource: approvalTestStateSource{state: recovery.ExecutionState{Target: target, PolicySnapshot: snapshot, PolicyInput: input}},
		Clock:       recovery.ClockFunc(func() time.Time { return now }),
		NewCommandID: func() (string, error) {
			return "command-approval-test", nil
		},
	})
	if err != nil {
		t.Fatalf("recovery.New() error = %v", err)
	}
	result, err := coordinator.Submit(context.Background(), recovery.Request{
		IncidentID:     "incident-approval-test",
		Target:         target,
		PolicySnapshot: snapshot,
		PolicyInput:    input,
		ExpiresAt:      now.Add(5 * time.Minute),
		IdempotencyKey: "delivery-approval-test",
	})
	if err != nil || result.Outcome != recovery.OutcomeAwaitApproval {
		t.Fatalf("Submit() = %#v, %v, want awaiting approval", result, err)
	}
	return manager, result.Command
}

type approvalTestAdapter struct{}

func (approvalTestAdapter) ValidateAction(context.Context, contract.ServiceTarget, contract.TypedAction) error {
	return nil
}

func (approvalTestAdapter) Execute(context.Context, contract.ServiceTarget, contract.TypedAction) error {
	return nil
}

func (approvalTestAdapter) Verify(context.Context, contract.ServiceTarget) (docker.Snapshot, error) {
	return docker.Snapshot{}, nil
}

type approvalTestStateSource struct {
	state recovery.ExecutionState
}

func (s approvalTestStateSource) Load(context.Context, contract.RecoveryCommand) (recovery.ExecutionState, error) {
	return s.state, nil
}

func startApprovalTestServer(t *testing.T, state *store.Store, manager *recovery.ApprovalManager, timeout time.Duration, credentials PeerCredentials) (*Server, string, func()) {
	t.Helper()
	socketPath := testSocketPath(t)
	clock := time.Now()
	server, err := NewServer(Options{
		SocketPath:      socketPath,
		AllowedUIDs:     []uint32{authorizedTestActor.UID},
		AllowedGIDs:     []uint32{authorizedTestActor.GID},
		State:           state,
		Approvals:       manager,
		RequestTimeout:  timeout,
		PeerCredentials: credentials,
		Clock:           func() time.Time { return clock },
		NewAuditID:      newTestIDGenerator("admin-test"),
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx) }()
	waitForSocket(t, server, socketPath, result)
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-result:
				if err != nil {
					t.Errorf("Server.Serve() error = %v", err)
				}
			case <-time.After(time.Second):
				t.Error("Server.Serve() did not stop")
			}
		})
	}
	t.Cleanup(stop)
	return server, socketPath, stop
}
