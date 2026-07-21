package policy

import (
	"testing"
	"time"

	"pulse-agent/internal/contract"
)

func TestEvaluate_DeterministicForSameSnapshotAndInput(t *testing.T) {
	snapshot := testSnapshot()
	input := validInput()
	first := Evaluate(snapshot, input)
	for index := 0; index < 100; index++ {
		if got := Evaluate(snapshot, input); got != first {
			t.Fatalf("Evaluate() = %#v, want deterministic %#v", got, first)
		}
	}
	if first != (Decision{Verdict: VerdictAllow, ReasonCode: ReasonAllowed}) {
		t.Fatalf("Evaluate() = %#v, want allow", first)
	}
}

func TestEvaluate_DenyPriorityAndApproval(t *testing.T) {
	now := fixedNow()
	approved := contract.Approval{SchemaVersion: contract.SchemaVersionV1, ApprovalID: "approval-1", CommandID: "command-1", Decision: contract.ApprovalGranted, ApproverIdentity: "operator-1", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	tests := []struct {
		name   string
		mutate func(*Snapshot, *Input)
		want   Decision
	}{
		{name: "forged digest wins", mutate: func(_ *Snapshot, input *Input) { input.RunbookDigest = "forged" }, want: deny(ReasonForgedDigest)},
		{name: "target mismatch", mutate: func(_ *Snapshot, input *Input) { input.TargetID = "other" }, want: deny(ReasonTargetMismatch)},
		{name: "analysis unavailable", mutate: func(snapshot *Snapshot, input *Input) {
			snapshot.Runbooks[0].AnalysisRequired = true
			input.AnalysisAvailable = false
		}, want: deny(ReasonAnalysisUnavailable)},
		{name: "analysis candidate mismatch", mutate: func(snapshot *Snapshot, input *Input) {
			snapshot.Runbooks[0].AnalysisRequired = true
			input.AnalysisAvailable = true
			input.AnalysisCandidateIDs = []string{"other"}
		}, want: deny(ReasonAnalysisMismatch)},
		{name: "precondition", mutate: func(_ *Snapshot, input *Input) { input.Preconditions["docker_healthy"] = false }, want: deny(ReasonPreconditionFailed)},
		{name: "cooldown", mutate: func(_ *Snapshot, input *Input) { input.LastAttemptAt = now.Add(-10 * time.Second) }, want: deny(ReasonCooldownActive)},
		{name: "retry", mutate: func(_ *Snapshot, input *Input) { input.AttemptCount = 2 }, want: deny(ReasonRetryExhausted)},
		{name: "expired approval", mutate: func(snapshot *Snapshot, input *Input) {
			snapshot.Runbooks[0].Runbook.RiskTier = contract.RiskHigh
			input.Approval = &contract.Approval{SchemaVersion: contract.SchemaVersionV1, ApprovalID: "approval-1", CommandID: input.CommandID, Decision: contract.ApprovalGranted, ApproverIdentity: "operator-1", CreatedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(-time.Minute)}
		}, want: deny(ReasonApprovalExpired)},
		{name: "revoked approval", mutate: func(snapshot *Snapshot, input *Input) {
			snapshot.Runbooks[0].Runbook.RiskTier = contract.RiskHigh
			input.Approval = &approved
			input.ApprovalRevoked = true
		}, want: deny(ReasonApprovalRevoked)},
		{name: "high risk awaits approval", mutate: func(snapshot *Snapshot, _ *Input) { snapshot.Runbooks[0].Runbook.RiskTier = contract.RiskHigh }, want: Decision{Verdict: VerdictAwaitApproval, ReasonCode: ReasonApprovalRequired}},
		{name: "valid approval allows high risk", mutate: func(snapshot *Snapshot, input *Input) {
			snapshot.Runbooks[0].Runbook.RiskTier = contract.RiskHigh
			input.Approval = &approved
		}, want: Decision{Verdict: VerdictAllow, ReasonCode: ReasonAllowed}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot, input := testSnapshot(), validInput()
			test.mutate(&snapshot, &input)
			if got := Evaluate(snapshot, input); got != test.want {
				t.Fatalf("Evaluate() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestEvaluate_AllowRequiresEveryInvariantAcrossCombinations(t *testing.T) {
	for _, risk := range []contract.RiskTier{contract.RiskLow, contract.RiskMedium, contract.RiskHigh} {
		for _, autoExecute := range []bool{false, true} {
			for _, analysisRequired := range []bool{false, true} {
				for _, analysisAvailable := range []bool{false, true} {
					for _, candidateMatches := range []bool{false, true} {
						for _, precondition := range []bool{false, true} {
							for _, cooldownElapsed := range []bool{false, true} {
								for _, retryAvailable := range []bool{false, true} {
									snapshot, input := testSnapshot(), validInput()
									snapshot.Runbooks[0].Runbook.RiskTier = risk
									snapshot.Runbooks[0].Runbook.AutoExecute = autoExecute
									snapshot.Runbooks[0].AnalysisRequired = analysisRequired
									input.AnalysisAvailable = analysisAvailable
									if !candidateMatches {
										input.AnalysisCandidateIDs = []string{"other"}
									}
									input.Preconditions["docker_healthy"] = precondition
									if !cooldownElapsed {
										input.LastAttemptAt = input.Now.Add(-time.Second)
									}
									if !retryAvailable {
										input.AttemptCount = snapshot.Runbooks[0].Runbook.RetryPolicy.MaxAttempts
									}
									decision := Evaluate(snapshot, input)
									if decision.Verdict != VerdictAllow {
										continue
									}
									if risk != contract.RiskLow || !autoExecute || (analysisRequired && (!analysisAvailable || !candidateMatches)) || !precondition || !cooldownElapsed || !retryAvailable {
										t.Fatalf("allow violated invariant: risk=%q auto=%t analysisRequired=%t analysisAvailable=%t candidate=%t precondition=%t cooldown=%t retry=%t", risk, autoExecute, analysisRequired, analysisAvailable, candidateMatches, precondition, cooldownElapsed, retryAvailable)
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestEvaluate_ModelSignalsCannotAuthorizeRecovery(t *testing.T) {
	snapshot, input := testSnapshot(), validInput()
	snapshot.Runbooks[0].Runbook.AutoExecute = false
	input.AnalysisConfidence = []contract.ConfidenceLabel{contract.ConfidenceHigh}
	input.NotificationSuggestion = contract.NotificationPage
	if got := Evaluate(snapshot, input); got != (Decision{Verdict: VerdictAwaitApproval, ReasonCode: ReasonApprovalRequired}) {
		t.Fatalf("Evaluate() = %#v, want approval wait despite model signals", got)
	}
}

func testSnapshot() Snapshot {
	return Snapshot{Runbooks: []RegisteredRunbook{{Runbook: contract.Runbook{SchemaVersion: contract.SchemaVersionV1, RunbookID: "restart-web", Digest: "digest-web", AdapterType: "docker", TypedActions: []contract.TypedAction{{ActionType: contract.ActionDockerContainerRestart, TargetSelector: "container:web", StopTimeout: contract.NewDuration(time.Second), Cooldown: contract.NewDuration(time.Minute)}}, RiskTier: contract.RiskLow, AutoExecute: true, Preconditions: []string{"docker_healthy"}, RetryPolicy: contract.RetryPolicy{MaxAttempts: 2}, StabilizationPolicy: contract.StabilizationPolicy{RecoverySamples: 2, Window: contract.NewDuration(time.Minute)}}, TargetID: "target-web"}}, AuthorizedApprovers: []string{"operator-1"}}
}

func validInput() Input {
	now := fixedNow()
	return Input{RunbookID: "restart-web", RunbookDigest: "digest-web", TargetID: "target-web", ActionIndex: 0, CommandID: "command-1", Preconditions: map[string]bool{"docker_healthy": true}, Now: now, AttemptCount: 0}
}

func fixedNow() time.Time { return time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC) }
