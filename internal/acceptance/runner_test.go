package acceptance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRun_WritesPassedMachineAndHumanReports(t *testing.T) {
	output := t.TempDir()
	result, err := Run(context.Background(), Options{
		OutputDir:   output,
		ProjectRoot: t.TempDir(),
		Now:         func() time.Time { return time.Date(2026, time.July, 22, 3, 0, 0, 0, time.UTC) },
		RunGate: func(_ context.Context, gate QualityGate) QualityGateResult {
			return QualityGateResult{Name: gate.Name, Passed: true}
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.Report.Passed || result.Report.Detection.ScenarioCount != 100 || result.Report.Recovery.Succeeded != 98 {
		t.Fatalf("result report = %#v, want passing baseline", result.Report)
	}
	if result.Report.Detection.RecallPercent < 99 || result.Report.Detection.FalsePositiveRatePercent > 1 {
		t.Fatalf("detection metrics = %#v, want threshold pass", result.Report.Detection)
	}
	if result.Report.Safety.SecurityBlockedCount != 100 || result.Report.Safety.SecretExposureCount != 0 {
		t.Fatalf("safety metrics = %#v, want full block and no secret exposure", result.Report.Safety)
	}

	document, err := os.ReadFile(result.JSONPath)
	if err != nil {
		t.Fatalf("ReadFile(JSON report): %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("Unmarshal(JSON report): %v", err)
	}
	if decoded.SchemaVersion != SchemaVersion || decoded.FixtureVersion != FixtureVersion || decoded.Seed != Seed {
		t.Fatalf("decoded report identity = %#v", decoded)
	}
	if decoded.FailureReasons == nil {
		t.Fatal("decoded report failure reasons = nil, want an empty JSON array")
	}
	if strings.Contains(string(document), "fixture-secret-must-not-appear") {
		t.Fatal("machine-readable report contains a secret fixture marker")
	}
	summary, err := os.ReadFile(result.SummaryPath)
	if err != nil {
		t.Fatalf("ReadFile(Markdown summary): %v", err)
	}
	if !strings.Contains(string(summary), "not a production SLO commitment") || !strings.Contains(string(summary), "go_test_race") {
		t.Fatalf("summary = %q, want baseline notice and quality gates", summary)
	}
}

func TestRun_WritesFailureReportWhenQualityGateFails(t *testing.T) {
	output := t.TempDir()
	result, err := Run(context.Background(), Options{
		OutputDir: output,
		RunGate: func(_ context.Context, gate QualityGate) QualityGateResult {
			return QualityGateResult{Name: gate.Name, Passed: gate.Name != "go_test_race"}
		},
	})
	if err == nil {
		t.Fatalf("Run() error = %v, want failed acceptance", err)
	}
	if result.Report.Passed || !strings.Contains(strings.Join(result.Report.FailureReasons, ","), "go_test_race") {
		t.Fatalf("failure report = %#v, want failed race quality gate", result.Report)
	}
	if _, readErr := os.Stat(filepath.Join(output, "mvp-acceptance.json")); readErr != nil {
		t.Fatalf("failure report was not written: %v", readErr)
	}
}

func TestAssess_RejectsThresholdRegression(t *testing.T) {
	report := Report{
		Detection:      DetectionMetrics{ScenarioCount: 100, FaultScenarioCount: 80, NormalScenarioCount: 20, TruePositives: 79, ProbeIntervalSeconds: 20, MaxDetectionLatencySecond: 40},
		Recovery:       RecoveryMetrics{RunCount: 100, Succeeded: 95, StabilizationLimitSeconds: 180, MaxStabilizationSeconds: 180, UnsupportedReplicaExecutions: map[string]int{"0": 0, "2": 0, "3": 0}},
		Safety:         SafetyMetrics{MaximumDockerStateChanges: 1, SecurityCorpusCount: 100, SecurityBlockedCount: 100, RestartRecoveryCount: 100, RestartRecoveredCount: 100},
		Reporting:      ReportingMetrics{TerminalReportCount: 100, RequiredFieldsComplete: 100, DeliveredWithinLimit: 100, DeliveryLimitSeconds: 60, MaximumDeliverySeconds: 60},
		ContractChecks: []ContractCheck{{Name: "all", Passed: true}},
		QualityGates:   []QualityGateResult{{Name: "all", Passed: true}},
	}
	failures := assess(report)
	if !strings.Contains(strings.Join(failures, ","), "detection recall") {
		t.Fatalf("assess() failures = %#v, want recall regression", failures)
	}
}
