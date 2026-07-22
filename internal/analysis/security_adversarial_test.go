package analysis

import (
	"context"
	"strings"
	"testing"
	"time"

	"pulse-agent/internal/contract"
)

const (
	analysisSensitiveInputCorpusSize = 15
	analysisModelOutputCorpusSize    = 15
	analysisAdversarialCorpusSize    = analysisSensitiveInputCorpusSize + analysisModelOutputCorpusSize
)

type analysisDisposition string

const (
	dispositionInvalidInput  analysisDisposition = "invalid_input"
	dispositionInvalidResult analysisDisposition = "invalid_result"
)

func TestGraph_SensitiveInputCorpusNeverReachesLLM(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		mutate func(*Input, string)
		want   analysisDisposition
	}{
		{name: "API key label", raw: "api-key-synthetic", mutate: setSecurityEvidence("api_key="), want: dispositionInvalidInput},
		{name: "token label", raw: "token-synthetic", mutate: setSecurityEvidence("token="), want: dispositionInvalidInput},
		{name: "password label", raw: "password-synthetic", mutate: setSecurityEvidence("password="), want: dispositionInvalidInput},
		{name: "customer name", raw: "Alice-Synthetic", mutate: setSecurityEvidence("customer_name="), want: dispositionInvalidInput},
		{name: "email PII", raw: "alice@example.test", mutate: setSecurityEvidence("owner="), want: dispositionInvalidInput},
		{name: "phone PII", raw: "010-1234-5678", mutate: setSecurityEvidence("owner="), want: dispositionInvalidInput},
		{name: "GitHub classic PAT", raw: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", mutate: setSecurityEvidence(""), want: dispositionInvalidInput},
		{name: "GitHub fine grained PAT", raw: "github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", mutate: setSecurityEvidence(""), want: dispositionInvalidInput},
		{name: "Slack bot token", raw: "xoxb-redaction-fixture", mutate: setSecurityEvidence(""), want: dispositionInvalidInput},
		{name: "live secret key", raw: "sk_fixture_opaque", mutate: setSecurityEvidence(""), want: dispositionInvalidInput},
		{name: "AWS access key", raw: "AKIAABCDEFGHIJKLMNOP", mutate: setSecurityEvidence(""), want: dispositionInvalidInput},
		{name: "Google API key", raw: "AIzaABCDEFGHIJKLMNOPQRSTUVWXYZ012345", mutate: setSecurityEvidence(""), want: dispositionInvalidInput},
		{name: "webhook secret in incident ID", raw: "whsec_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", mutate: func(input *Input, raw string) { input.IncidentID = raw }, want: dispositionInvalidInput},
		{name: "PAT in runbook description", raw: "ghp_9876543210ABCDEFGHIJKLMNOPQRSTUVWXYZ", mutate: func(input *Input, raw string) { input.Runbooks[0].Description = "diagnostic " + raw }, want: dispositionInvalidInput},
		{name: "new opaque token form", raw: "sessionv2~ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", mutate: setSecurityEvidence(""), want: dispositionInvalidInput},
	}
	if got := len(tests); got != analysisSensitiveInputCorpusSize {
		t.Fatalf("analysis sensitive-input corpus size = %d, want %d", got, analysisSensitiveInputCorpusSize)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spy := &spyModel{}
			input := goldenInput()
			test.mutate(&input, test.raw)
			outcome := newSecurityGraph(t, spy).Analyze(context.Background(), input)
			if outcome.Status != StatusUnavailable || outcome.UnavailableCode != string(test.want) || outcome.Result.IncidentID != "" || len(outcome.Result.Hypotheses) != 0 {
				t.Fatalf("Analyze() = %#v, want disposition %q", outcome, test.want)
			}
			if spy.calls != 0 || spy.tools != 0 || strings.Contains(spy.prompt, test.raw) {
				t.Fatalf("LLM boundary calls=%d tools=%d prompt-bytes=%d, want no transmission", spy.calls, spy.tools, len(spy.prompt))
			}
		})
	}
}

func TestGraph_ModelOutputCorpusCannotProduceExecutableAnalysis(t *testing.T) {
	base := contract.AnalysisResult{
		SchemaVersion:              contract.SchemaVersionV1,
		IncidentID:                 "incident-1",
		Hypotheses:                 []contract.Hypothesis{{Summary: "bounded health failure", EvidenceRefs: []string{"evidence-1"}}},
		EvidenceRefs:               []string{"evidence-1"},
		ConfidenceLabels:           []contract.ConfidenceLabel{contract.ConfidenceLow},
		NotificationRecommendation: contract.NotificationNotify,
		CandidateRunbookIDs:        []string{"restart-web"},
		MissingEvidence:            []string{},
	}
	valid := analysisJSON(t, base)
	tests := []struct {
		name     string
		document string
		want     analysisDisposition
	}{
		{name: "Docker command summary", document: analysisJSON(t, withSummary(base, "run docker restart web")), want: dispositionInvalidResult},
		{name: "shell command summary", document: analysisJSON(t, withSummary(base, "run sh -c restart")), want: dispositionInvalidResult},
		{name: "Bash command summary", document: analysisJSON(t, withSummary(base, "run bash -c restart")), want: dispositionInvalidResult},
		{name: "kubectl command summary", document: analysisJSON(t, withSummary(base, "run kubectl delete pod")), want: dispositionInvalidResult},
		{name: "curl command summary", document: analysisJSON(t, withSummary(base, "run curl https://example.test")), want: dispositionInvalidResult},
		{name: "remove command summary", document: analysisJSON(t, withSummary(base, "run rm -rf service")), want: dispositionInvalidResult},
		{name: "exec command summary", document: analysisJSON(t, withSummary(base, "exec container command")), want: dispositionInvalidResult},
		{name: "command in missing evidence", document: analysisJSON(t, withMissingEvidence(base, "docker exec web")), want: dispositionInvalidResult},
		{name: "unregistered runbook", document: analysisJSON(t, withRunbook(base, "restart-unregistered")), want: dispositionInvalidResult},
		{name: "forged top-level evidence reference", document: analysisJSON(t, withEvidence(base, "evidence-forged")), want: dispositionInvalidResult},
		{name: "forged hypothesis evidence reference", document: analysisJSON(t, withHypothesisEvidence(base, "evidence-forged")), want: dispositionInvalidResult},
		{name: "unsupported schema escape", document: strings.Replace(valid, `"schema_version":"v1"`, `"schema_version":"v2"`, 1), want: dispositionInvalidResult},
		{name: "unknown command field escape", document: strings.TrimSuffix(valid, "}") + `,"command":"docker restart web"}`, want: dispositionInvalidResult},
		{name: "duplicate field escape", document: strings.Replace(valid, "{", `{"schema_version":"v1",`, 1), want: dispositionInvalidResult},
		{name: "duplicate runbook recommendation", document: analysisJSON(t, withDuplicateRunbook(base)), want: dispositionInvalidResult},
	}
	if got := len(tests); got != analysisModelOutputCorpusSize || analysisAdversarialCorpusSize != 30 {
		t.Fatalf("analysis model-output corpus size = %d, total = %d; want %d and 30", got, analysisAdversarialCorpusSize, analysisModelOutputCorpusSize)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spy := &spyModel{response: llmResponse(test.document)}
			outcome := newSecurityGraph(t, spy).Analyze(context.Background(), goldenInput())
			if outcome.Status != StatusUnavailable || outcome.UnavailableCode != string(test.want) || outcome.Result.IncidentID != "" || len(outcome.Result.Hypotheses) != 0 {
				t.Fatalf("Analyze() = %#v, want disposition %q", outcome, test.want)
			}
			if spy.calls != 1 || spy.tools != 0 {
				t.Fatalf("LLM calls=%d tools=%d, want one tool-free contract evaluation", spy.calls, spy.tools)
			}
		})
	}
}

func setSecurityEvidence(prefix string) func(*Input, string) {
	return func(input *Input, raw string) {
		input.Evidence[0].Content = prefix + raw
		input.Evidence[0].Reference.ByteCount = len(input.Evidence[0].Content)
	}
}

func newSecurityGraph(t *testing.T, candidate *spyModel) *Graph {
	t.Helper()
	graph, err := NewGraph(Options{Model: candidate, Timeout: time.Second, MaxAttempts: 1, MaxEvidenceBytes: 1024})
	if err != nil {
		t.Fatalf("NewGraph() error = %v", err)
	}
	return graph
}

func withMissingEvidence(result contract.AnalysisResult, value string) contract.AnalysisResult {
	result.MissingEvidence = []string{value}
	return result
}

func withHypothesisEvidence(result contract.AnalysisResult, value string) contract.AnalysisResult {
	result.Hypotheses = []contract.Hypothesis{{Summary: result.Hypotheses[0].Summary, EvidenceRefs: []string{value}}}
	return result
}

func withDuplicateRunbook(result contract.AnalysisResult) contract.AnalysisResult {
	result.CandidateRunbookIDs = []string{"restart-web", "restart-web"}
	return result
}
