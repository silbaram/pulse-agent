package recovery

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"pulse-agent/internal/analysis"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/docker"
	"pulse-agent/internal/llm"
	"pulse-agent/internal/policy"
)

func TestModelDisconnectResilience_RequiredAnalysisHoldsWhilePrevalidatedLowRiskContinues(t *testing.T) {
	outcome := disconnectedAnalysisOutcome(t)
	if outcome.Status != analysis.StatusUnavailable || outcome.UnavailableCode != "model_unavailable" || outcome.Notification != contract.NotificationNotify {
		t.Fatalf("Analyze() = %#v, want model-unavailable notification fallback", outcome)
	}

	tests := []struct {
		name                string
		analysisRequired    bool
		wantOutcome         Outcome
		wantReason          policy.ReasonCode
		wantExecuteCalls    int
		wantLifecycleEvents []string
	}{
		{
			name:                "required analysis holds and notifies",
			analysisRequired:    true,
			wantOutcome:         OutcomeDenied,
			wantReason:          policy.ReasonAnalysisUnavailable,
			wantExecuteCalls:    0,
			wantLifecycleEvents: []string{"analysis.unavailable", "policy.denied"},
		},
		{
			name:                "prevalidated low risk continues",
			analysisRequired:    false,
			wantOutcome:         OutcomeStabilizing,
			wantReason:          policy.ReasonAllowed,
			wantExecuteCalls:    1,
			wantLifecycleEvents: []string{"analysis.unavailable", "recovery.started"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := testNow()
			request := testRequest(now)
			request.PolicySnapshot.Runbooks[0].AnalysisRequired = test.analysisRequired
			request.PolicyInput.AnalysisAvailable = outcome.Status == analysis.StatusComplete
			request.PolicyInput.NotificationSuggestion = outcome.Notification
			adapter := &fakeAdapter{snapshot: docker.Snapshot{TargetID: request.Target.TargetID, Running: true, Healthy: true}}
			publisher := &fakeLifecyclePublisher{}
			coordinator := newModelResilienceCoordinator(t, request, adapter, publisher, now)

			result, err := coordinator.Submit(context.Background(), request)
			if err != nil {
				t.Fatalf("Submit() error = %v", err)
			}
			if result.Outcome != test.wantOutcome || result.Decision.ReasonCode != test.wantReason {
				t.Fatalf("Submit() = outcome %q, decision %#v; want outcome %q, reason %q", result.Outcome, result.Decision, test.wantOutcome, test.wantReason)
			}
			if adapter.executeCalls != test.wantExecuteCalls {
				t.Fatalf("Docker Execute() calls = %d, want %d", adapter.executeCalls, test.wantExecuteCalls)
			}
			if !slices.Equal(publisher.calls, test.wantLifecycleEvents) {
				t.Fatalf("lifecycle events = %#v, want %#v", publisher.calls, test.wantLifecycleEvents)
			}
		})
	}
}

func disconnectedAnalysisOutcome(t *testing.T) analysis.Outcome {
	t.Helper()
	model, err := llm.NewFake("disconnected-model", []llm.FakeEvent{{Err: errors.New("model connection unavailable")}})
	if err != nil {
		t.Fatalf("llm.NewFake() error = %v", err)
	}
	graph, err := analysis.NewGraph(analysis.Options{Model: model, Timeout: time.Second, MaxAttempts: 2, MaxEvidenceBytes: 1024})
	if err != nil {
		t.Fatalf("analysis.NewGraph() error = %v", err)
	}
	now := testNow()
	content := "health=failed"
	return graph.Analyze(context.Background(), analysis.Input{
		IncidentID: "incident-1",
		Evidence: []analysis.Evidence{{
			Reference: contract.EvidenceRef{
				SchemaVersion:    contract.SchemaVersionV1,
				EvidenceID:       "evidence-1",
				SourceType:       "docker",
				CollectorID:      "local",
				Start:            now,
				End:              now,
				RedactionProfile: "default",
				Digest:           "digest",
				ByteCount:        len(content),
				RetentionUntil:   now.Add(time.Hour),
			},
			Content: content,
		}},
		Runbooks: []analysis.RunbookDescription{{RunbookID: "restart-web", Description: "Restart the registered web service."}},
	})
}

func newModelResilienceCoordinator(t *testing.T, request Request, adapter Adapter, publisher LifecyclePublisher, now time.Time) *Coordinator {
	t.Helper()
	nextID := 0
	coordinator, err := New(Options{
		State:              openState(t),
		Adapter:            adapter,
		StateSource:        &fakeStateSource{state: executionState(request)},
		Clock:              &sequenceClock{times: []time.Time{now, now, now, now}},
		LifecyclePublisher: publisher,
		NewCommandID: func() (string, error) {
			nextID++
			return fmt.Sprintf("model-resilience-command-%d", nextID), nil
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return coordinator
}
