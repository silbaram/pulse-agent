package recovery

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"pulse-agent/internal/audit"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/docker"
	"pulse-agent/internal/store"
)

func TestCoordinator_ProcessStopMatrixPreservesAtMostOneDockerEffect(t *testing.T) {
	now := testNow()
	tests := []struct {
		name                     string
		fault                    func(t *testing.T, coordinator *Coordinator, adapter *fakeAdapter, record journalRecord)
		wantEffectsBeforeRestart int
		wantReconciliations      int
		wantState                contract.RecoveryCommandState
		wantRetryOutcome         Outcome
		wantRetryDuplicate       bool
		wantRetryEffects         int
	}{
		{
			name:             "before pending journal write",
			fault:            func(_ *testing.T, _ *Coordinator, _ *fakeAdapter, _ journalRecord) {},
			wantRetryOutcome: OutcomeStabilizing,
			wantRetryEffects: 1,
		},
		{
			name: "after pending journal write",
			fault: func(t *testing.T, coordinator *Coordinator, _ *fakeAdapter, record journalRecord) {
				t.Helper()
				persistResilienceRecord(t, coordinator, record)
			},
			wantReconciliations: 1,
			wantState:           contract.RecoveryPending,
			wantRetryOutcome:    OutcomeVerifyAndNotify,
			wantRetryDuplicate:  true,
		},
		{
			name: "before Docker response",
			fault: func(t *testing.T, coordinator *Coordinator, _ *fakeAdapter, record journalRecord) {
				t.Helper()
				persistResilienceRecord(t, coordinator, record)
				startResilienceExecution(t, coordinator, record)
			},
			wantReconciliations: 1,
			wantState:           contract.RecoveryExecuting,
			wantRetryOutcome:    OutcomeVerifyAndNotify,
			wantRetryDuplicate:  true,
		},
		{
			name: "after Docker response before durable result",
			fault: func(t *testing.T, coordinator *Coordinator, adapter *fakeAdapter, record journalRecord) {
				t.Helper()
				persistResilienceRecord(t, coordinator, record)
				executing := startResilienceExecution(t, coordinator, record)
				if err := adapter.Execute(context.Background(), executing.Target, executing.Action); err != nil {
					t.Fatalf("fake Docker Execute() error = %v", err)
				}
			},
			wantEffectsBeforeRestart: 1,
			wantReconciliations:      1,
			wantState:                contract.RecoveryExecuting,
			wantRetryOutcome:         OutcomeVerifyAndNotify,
			wantRetryDuplicate:       true,
		},
		{
			name: "after Docker result enters stabilization",
			fault: func(t *testing.T, coordinator *Coordinator, adapter *fakeAdapter, record journalRecord) {
				t.Helper()
				persistResilienceRecord(t, coordinator, record)
				executing := startResilienceExecution(t, coordinator, record)
				if err := adapter.Execute(context.Background(), executing.Target, executing.Action); err != nil {
					t.Fatalf("fake Docker Execute() error = %v", err)
				}
				if _, err := coordinator.finishExecution(recordKey(record.Command), contract.RecoveryStabilizing); err != nil {
					t.Fatalf("finishExecution() error = %v", err)
				}
			},
			wantEffectsBeforeRestart: 1,
			wantState:                contract.RecoveryStabilizing,
			wantRetryOutcome:         OutcomeStabilizing,
			wantRetryDuplicate:       true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			state := openResilienceState(t, path)
			adapter := &fakeAdapter{snapshot: docker.Snapshot{TargetID: "target-web", Running: true, Healthy: true}}
			request := testRequest(now)
			record := resilienceRecord(request, now)
			coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now}})
			persistResilienceSupportState(t, state, now)
			before := resilienceSupportSnapshot(t, state)

			test.fault(t, coordinator, adapter, record)
			if adapter.executeCalls != test.wantEffectsBeforeRestart {
				t.Fatalf("Docker effects before restart = %d, want %d", adapter.executeCalls, test.wantEffectsBeforeRestart)
			}
			if err := state.Close(); err != nil {
				t.Fatalf("close interrupted store: %v", err)
			}

			state = openResilienceState(t, path)
			t.Cleanup(func() {
				if err := state.Close(); err != nil {
					t.Errorf("close restarted store: %v", err)
				}
			})
			restarted := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now.Add(time.Minute)}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			results, err := restarted.Reconcile(ctx)
			if err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}
			if len(results) != test.wantReconciliations {
				t.Fatalf("Reconcile() results = %#v, want %d entries", results, test.wantReconciliations)
			}
			if len(results) == 1 {
				if results[0].Outcome != OutcomeVerifyAndNotify || !results[0].Verified || results[0].Command.State != test.wantState {
					t.Fatalf("Reconcile() result = %#v, want verified fail-closed state %q", results[0], test.wantState)
				}
				stored := readRecord(t, state, record.Command)
				if stored.Phase != phaseVerifyAndNotify || stored.Reconciliation == nil || !stored.Reconciliation.Verified {
					t.Fatalf("reconciled journal = %#v, want durable verify_and_notify", stored)
				}
			}
			if adapter.executeCalls != test.wantEffectsBeforeRestart {
				t.Fatalf("Docker effects after reconciliation = %d, want unchanged %d", adapter.executeCalls, test.wantEffectsBeforeRestart)
			}

			effectsBeforeRetry := adapter.executeCalls
			retry, err := restarted.Submit(ctx, request)
			if err != nil {
				t.Fatalf("Submit() after restart error = %v", err)
			}
			if retry.Outcome != test.wantRetryOutcome {
				t.Fatalf("Submit() after restart outcome = %q, want %q", retry.Outcome, test.wantRetryOutcome)
			}
			if retry.Duplicate != test.wantRetryDuplicate {
				t.Fatalf("Submit() after restart duplicate = %t, want %t", retry.Duplicate, test.wantRetryDuplicate)
			}
			if got := adapter.executeCalls - effectsBeforeRetry; got != test.wantRetryEffects {
				t.Fatalf("additional Docker effects after restart = %d, want %d", got, test.wantRetryEffects)
			}
			if adapter.executeCalls > 1 {
				t.Fatalf("total Docker effects = %d, want at most one", adapter.executeCalls)
			}

			after := resilienceSupportSnapshot(t, state)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("supporting transaction state changed across restart\nbefore=%#v\nafter=%#v", before, after)
			}
			validateResilienceSupportSnapshot(t, after)
			if err := state.View(audit.ValidateChain); err != nil {
				t.Fatalf("audit chain after restart = %v", err)
			}
		})
	}
}

func resilienceRecord(request Request, now time.Time) journalRecord {
	runbook := request.PolicySnapshot.Runbooks[0].Runbook
	return journalRecord{
		SchemaVersion: contract.SchemaVersionV1,
		Command: contract.RecoveryCommand{
			SchemaVersion:  contract.SchemaVersionV1,
			CommandID:      "command-1",
			IncidentID:     request.IncidentID,
			RunbookID:      runbook.RunbookID,
			RunbookDigest:  runbook.Digest,
			TargetID:       request.Target.TargetID,
			ActionIndex:    request.PolicyInput.ActionIndex,
			RiskTier:       runbook.RiskTier,
			IssuedAt:       now,
			ExpiresAt:      request.ExpiresAt,
			IdempotencyKey: request.IdempotencyKey,
			State:          contract.RecoveryPending,
		},
		Target: request.Target,
		Action: runbook.TypedActions[request.PolicyInput.ActionIndex],
		Phase:  phasePending,
	}
}

func persistResilienceRecord(t *testing.T, coordinator *Coordinator, record journalRecord) {
	t.Helper()
	if _, duplicate, err := coordinator.persistPending(record); err != nil || duplicate {
		t.Fatalf("persistPending() duplicate=%t error=%v, want new record", duplicate, err)
	}
}

func startResilienceExecution(t *testing.T, coordinator *Coordinator, record journalRecord) journalRecord {
	t.Helper()
	if _, err := coordinator.approve(recordKey(record.Command)); err != nil {
		t.Fatalf("approve() error = %v", err)
	}
	executing, err := coordinator.startExecution(recordKey(record.Command))
	if err != nil {
		t.Fatalf("startExecution() error = %v", err)
	}
	return executing
}

func openResilienceState(t *testing.T, path string) *store.Store {
	t.Helper()
	state, err := store.Open(store.Options{Path: path, LockTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("store.Open(%q) error = %v", path, err)
	}
	return state
}

var resilienceSupportBuckets = []store.Bucket{
	store.BucketIncidents,
	store.BucketApprovals,
	store.BucketAudit,
	store.BucketStabilizationResults,
	store.BucketDeliveryQueue,
	store.BucketLifecycleEvents,
	store.BucketIncidentReports,
}

func persistResilienceSupportState(t *testing.T, state *store.Store, now time.Time) {
	t.Helper()
	incident := contract.Incident{
		SchemaVersion: contract.SchemaVersionV1,
		IncidentID:    "active-incident",
		DedupeKey:     "active-dedupe",
		TargetID:      "target-web",
		RuleIDs:       []string{"health"},
		State:         contract.IncidentStabilizing,
		Severity:      contract.SeverityCritical,
		OpenedAt:      now.Add(-time.Minute),
	}
	approval := contract.Approval{
		SchemaVersion:    contract.SchemaVersionV1,
		ApprovalID:       "approval-support",
		CommandID:        "command-support",
		Decision:         contract.ApprovalGranted,
		ApproverIdentity: "uid:1000",
		Reason:           "approved",
		CreatedAt:        now,
		ExpiresAt:        now.Add(time.Hour),
	}
	event := contract.LifecycleEvent{
		SchemaVersion: contract.SchemaVersionV1,
		EventID:       "event-support",
		EventType:     contract.LifecycleIncidentClosed,
		IncidentID:    "closed-incident",
		OccurredAt:    now,
		ReasonCode:    "terminal_closed",
		EvidenceRefs:  []string{},
	}
	report := contract.IncidentReport{
		SchemaVersion:                 contract.SchemaVersionV1,
		ReportID:                      "report-support",
		IncidentID:                    "closed-incident",
		Hypotheses:                    []contract.Hypothesis{{Summary: "bounded cause", EvidenceRefs: []string{"evidence-1"}}},
		EvidenceRefs:                  []string{"evidence-1"},
		Actions:                       []contract.ReportAction{{CommandID: "command-support", ActionType: contract.ActionDockerContainerRestart, Result: "succeeded"}},
		Approvals:                     []string{approval.ApprovalID},
		VerificationResult:            "healthy",
		PreventionRecommendations:     []string{"retain deterministic probes"},
		PostmortemDraft:               "Synthetic restart recovery fixture.",
		RunbookImprovementSuggestions: []string{"retain bounded stabilization"},
		DeliveryStatus:                contract.DeliveryPending,
	}
	deliveries := []contract.DeliveryQueueItem{
		{
			SchemaVersion: contract.SchemaVersionV1, DeliveryID: "delivery-event", PayloadType: contract.DeliveryPayloadLifecycleEvent,
			PayloadRef: event.EventID, WebhookID: "webhook-event", DestinationRef: "operations", NextAttemptAt: now, ExpiresAt: now.Add(time.Hour), State: contract.DeliveryPending,
		},
		{
			SchemaVersion: contract.SchemaVersionV1, DeliveryID: "delivery-report", PayloadType: contract.DeliveryPayloadIncidentReport,
			PayloadRef: report.ReportID, WebhookID: "webhook-report", DestinationRef: "operations", NextAttemptAt: now, ExpiresAt: now.Add(time.Hour), State: contract.DeliveryPending,
		},
	}
	if err := incident.Validate(); err != nil {
		t.Fatalf("fixture incident invalid: %v", err)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("fixture lifecycle event invalid: %v", err)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("fixture report invalid: %v", err)
	}
	for _, item := range deliveries {
		if err := item.Validate(); err != nil {
			t.Fatalf("fixture delivery %q invalid: %v", item.DeliveryID, err)
		}
	}

	documents := map[store.Bucket]map[string][]byte{
		store.BucketIncidents:            {incident.IncidentID: resilienceJSON(t, incident)},
		store.BucketApprovals:            {approval.ApprovalID: resilienceJSON(t, approval)},
		store.BucketStabilizationResults: {"command-support/0": []byte(`{"schema_version":"v1","command_id":"command-support","execution_succeeded":true,"attempt":0,"started_at":"2026-07-21T09:00:00Z","healthy_samples":1,"outcome":"pending","next_attempt":-1}`)},
		store.BucketDeliveryQueue: {
			deliveries[0].DeliveryID: resilienceJSON(t, deliveries[0]),
			deliveries[1].DeliveryID: resilienceJSON(t, deliveries[1]),
		},
		store.BucketLifecycleEvents: {event.EventID: resilienceJSON(t, event)},
		store.BucketIncidentReports: {report.ReportID: resilienceJSON(t, report)},
	}
	err := state.Update(func(transaction *store.Tx) error {
		_, err := audit.Append(transaction, contract.AuditEvent{
			SchemaVersion: contract.SchemaVersionV1,
			EventID:       "audit-support",
			AggregateType: "recovery",
			AggregateID:   "command-support",
			ActorIdentity: "system",
			Action:        "recovery.verify",
			Result:        "pending",
			ReasonCode:    "process_restart_fixture",
			OccurredAt:    now,
		}, func(transaction *store.Tx) error {
			for bucket, entries := range documents {
				for key, document := range entries {
					if err := transaction.Put(bucket, key, document); err != nil {
						return err
					}
				}
			}
			return nil
		})
		return err
	})
	if err != nil {
		t.Fatalf("persist supporting transaction state: %v", err)
	}
}

func resilienceSupportSnapshot(t *testing.T, state *store.Store) map[store.Bucket]map[string]string {
	t.Helper()
	snapshot := make(map[store.Bucket]map[string]string, len(resilienceSupportBuckets))
	err := state.View(func(transaction *store.Tx) error {
		for _, bucket := range resilienceSupportBuckets {
			entries := make(map[string]string)
			if err := transaction.ForEach(bucket, func(key string, document []byte) error {
				entries[key] = string(document)
				return nil
			}); err != nil {
				return err
			}
			snapshot[bucket] = entries
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read supporting transaction state: %v", err)
	}
	return snapshot
}

func validateResilienceSupportSnapshot(t *testing.T, snapshot map[store.Bucket]map[string]string) {
	t.Helper()
	var incident contract.Incident
	resilienceDecode(t, snapshot[store.BucketIncidents]["active-incident"], &incident)
	if err := incident.Validate(); err != nil || incident.State != contract.IncidentStabilizing {
		t.Fatalf("reopened incident = %#v, error=%v, want valid stabilizing incident", incident, err)
	}

	var approval contract.Approval
	resilienceDecode(t, snapshot[store.BucketApprovals]["approval-support"], &approval)
	if approval.ApprovalID != "approval-support" || approval.CommandID != "command-support" || approval.Decision != contract.ApprovalGranted {
		t.Fatalf("reopened approval = %#v, want immutable command-support grant", approval)
	}

	var event contract.LifecycleEvent
	resilienceDecode(t, snapshot[store.BucketLifecycleEvents]["event-support"], &event)
	if err := event.Validate(); err != nil {
		t.Fatalf("reopened lifecycle event = %#v, error=%v", event, err)
	}
	var report contract.IncidentReport
	resilienceDecode(t, snapshot[store.BucketIncidentReports]["report-support"], &report)
	if err := report.Validate(); err != nil || report.IncidentID != event.IncidentID {
		t.Fatalf("reopened report = %#v, error=%v, lifecycle incident=%q", report, err, event.IncidentID)
	}

	for _, deliveryID := range []string{"delivery-event", "delivery-report"} {
		var item contract.DeliveryQueueItem
		resilienceDecode(t, snapshot[store.BucketDeliveryQueue][deliveryID], &item)
		if err := item.Validate(); err != nil || item.State != contract.DeliveryPending {
			t.Fatalf("reopened delivery %q = %#v, error=%v", deliveryID, item, err)
		}
		switch item.PayloadType {
		case contract.DeliveryPayloadLifecycleEvent:
			if item.PayloadRef != event.EventID {
				t.Fatalf("lifecycle delivery payload_ref = %q, want %q", item.PayloadRef, event.EventID)
			}
		case contract.DeliveryPayloadIncidentReport:
			if item.PayloadRef != report.ReportID {
				t.Fatalf("report delivery payload_ref = %q, want %q", item.PayloadRef, report.ReportID)
			}
		}
	}

	var stabilization struct {
		CommandID          string `json:"command_id"`
		ExecutionSucceeded bool   `json:"execution_succeeded"`
		Outcome            string `json:"outcome"`
	}
	resilienceDecode(t, snapshot[store.BucketStabilizationResults]["command-support/0"], &stabilization)
	if stabilization.CommandID != "command-support" || !stabilization.ExecutionSucceeded || stabilization.Outcome != "pending" {
		t.Fatalf("reopened stabilization = %#v, want pending result for successful execution", stabilization)
	}
}

func resilienceDecode(t *testing.T, document string, destination any) {
	t.Helper()
	if document == "" {
		t.Fatal("reopened fixture document is missing")
	}
	if err := json.Unmarshal([]byte(document), destination); err != nil {
		t.Fatalf("json.Unmarshal(%T) error = %v", destination, err)
	}
}

func resilienceJSON(t *testing.T, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T) error = %v", value, err)
	}
	return document
}
