package recovery

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/adk/v2/model"
	"google.golang.org/genai"

	"pulse-agent/internal/analysis"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/llm"
	"pulse-agent/internal/policy"
	"pulse-agent/internal/store"
)

const invalidAnalysisExecutionCorpusSize = 4

func TestCoordinator_InvalidAnalysisCorpusCannotReachDocker(t *testing.T) {
	base := contract.AnalysisResult{
		SchemaVersion:              contract.SchemaVersionV1,
		IncidentID:                 "incident-1",
		Hypotheses:                 []contract.Hypothesis{{Summary: "bounded failure", EvidenceRefs: []string{"evidence-1"}}},
		EvidenceRefs:               []string{"evidence-1"},
		ConfidenceLabels:           []contract.ConfidenceLabel{contract.ConfidenceLow},
		NotificationRecommendation: contract.NotificationNotify,
		CandidateRunbookIDs:        []string{"restart-web"},
		MissingEvidence:            []string{},
	}
	valid := recoveryAnalysisJSON(t, base)
	command := base
	command.Hypotheses = []contract.Hypothesis{{Summary: "run docker restart web", EvidenceRefs: []string{"evidence-1"}}}
	unregistered := base
	unregistered.CandidateRunbookIDs = []string{"restart-unregistered"}
	forgedEvidence := base
	forgedEvidence.EvidenceRefs = []string{"evidence-forged"}
	tests := []struct {
		name     string
		document string
	}{
		{name: "command string", document: recoveryAnalysisJSON(t, command)},
		{name: "unregistered runbook", document: recoveryAnalysisJSON(t, unregistered)},
		{name: "forged evidence reference", document: recoveryAnalysisJSON(t, forgedEvidence)},
		{name: "schema escape", document: strings.TrimSuffix(valid, "}") + `,"command":"docker restart web"}`},
	}
	if got := len(tests); got != invalidAnalysisExecutionCorpusSize {
		t.Fatalf("invalid analysis execution corpus size = %d, want %d", got, invalidAnalysisExecutionCorpusSize)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outcome := analyzeSecurityDocument(t, test.document)
			if outcome.Status != analysis.StatusUnavailable || outcome.UnavailableCode != "invalid_result" {
				t.Fatalf("Analyze() = %#v, want invalid_result", outcome)
			}

			now := testNow()
			state := openState(t)
			adapter := &fakeAdapter{}
			coordinator := newCoordinator(t, state, adapter, &sequenceClock{times: []time.Time{now}})
			request := testRequest(now)
			request.PolicySnapshot.Runbooks[0].AnalysisRequired = true
			request.PolicyInput.AnalysisAvailable = outcome.Status == analysis.StatusComplete
			request.PolicyInput.AnalysisCandidateIDs = append([]string(nil), outcome.Result.CandidateRunbookIDs...)

			result, err := coordinator.Submit(context.Background(), request)
			if err != nil || result.Outcome != OutcomeDenied || result.Decision.ReasonCode != policy.ReasonAnalysisUnavailable {
				t.Fatalf("Submit() = %#v, %v, want denied reason %q", result, err, policy.ReasonAnalysisUnavailable)
			}
			if adapter.validateCalls != 0 || adapter.executeCalls != 0 {
				t.Fatalf("adapter calls = validate %d execute %d, want 0/0", adapter.validateCalls, adapter.executeCalls)
			}
			if got := countSecurityRecords(t, state, store.BucketCommandJournal); got != 0 {
				t.Fatalf("command journal records = %d, want 0", got)
			}
		})
	}
}

func analyzeSecurityDocument(t *testing.T, document string) analysis.Outcome {
	t.Helper()
	fake, err := llm.NewFake("security-fake", []llm.FakeEvent{{Response: &model.LLMResponse{Content: genai.NewContentFromText(document, "model")}}})
	if err != nil {
		t.Fatalf("llm.NewFake() error = %v", err)
	}
	graph, err := analysis.NewGraph(analysis.Options{Model: fake, Timeout: time.Second, MaxAttempts: 1, MaxEvidenceBytes: 1024})
	if err != nil {
		t.Fatalf("analysis.NewGraph() error = %v", err)
	}
	now := testNow()
	content := "health=failed"
	return graph.Analyze(context.Background(), analysis.Input{
		IncidentID: "incident-1",
		Evidence: []analysis.Evidence{{
			Reference: contract.EvidenceRef{SchemaVersion: contract.SchemaVersionV1, EvidenceID: "evidence-1", SourceType: "docker", CollectorID: "local", Start: now, End: now, RedactionProfile: "strict", Digest: "digest", ByteCount: len(content), RetentionUntil: now.Add(time.Hour)},
			Content:   content,
		}},
		Runbooks: []analysis.RunbookDescription{{RunbookID: "restart-web", Description: "Restart the registered web service."}},
	})
}

func recoveryAnalysisJSON(t *testing.T, result contract.AnalysisResult) string {
	t.Helper()
	document, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(document)
}
