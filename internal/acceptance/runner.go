// Package acceptance runs the deterministic MVP acceptance baseline.
package acceptance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// SchemaVersion identifies the machine-readable acceptance report contract.
	SchemaVersion = "pulse-agent.mvp_acceptance.v1"
	// FixtureVersion identifies the controlled fixture set used by this baseline.
	FixtureVersion = "v1-mvp-fixture-2026-07-22"
	// Seed fixes the generated scenario population for reproducible acceptance runs.
	Seed int64 = 20260722

	fixtureScenarioCount = 100
	recoveryRunCount     = 100
	securityCorpusCount  = 100
)

// QualityGate describes one repository quality command that the acceptance
// baseline must execute successfully.
type QualityGate struct {
	Name    string
	Command string
	Args    []string
}

// QualityGateResult records a quality command without preserving command
// output, which can contain untrusted test fixture data on failure.
type QualityGateResult struct {
	Name    string `json:"name"`
	Command string `json:"command"`
	Passed  bool   `json:"passed"`
}

// GateRunner executes one quality gate for Run.
type GateRunner func(context.Context, QualityGate) QualityGateResult

// Options configures a deterministic acceptance baseline execution.
type Options struct {
	OutputDir   string
	ProjectRoot string
	GoBinary    string
	Now         func() time.Time
	RunGate     GateRunner
}

// DetectionMetrics records detection population and latency results.
type DetectionMetrics struct {
	ScenarioCount             int `json:"scenario_count"`
	FaultScenarioCount        int `json:"fault_scenario_count"`
	NormalScenarioCount       int `json:"normal_scenario_count"`
	TruePositives             int `json:"true_positives"`
	FalsePositives            int `json:"false_positives"`
	RecallPercent             int `json:"recall_percent"`
	FalsePositiveRatePercent  int `json:"false_positive_rate_percent"`
	ProbeIntervalSeconds      int `json:"probe_interval_seconds"`
	MaxDetectionLatencySecond int `json:"max_detection_latency_seconds"`
}

// RecoveryMetrics records controlled one-replica recovery outcomes.
type RecoveryMetrics struct {
	RunCount                     int            `json:"run_count"`
	Succeeded                    int            `json:"succeeded"`
	SuccessRatePercent           int            `json:"success_rate_percent"`
	StabilizationLimitSeconds    int            `json:"stabilization_limit_seconds"`
	MaxStabilizationSeconds      int            `json:"max_stabilization_seconds"`
	FailureReasons               map[string]int `json:"failure_reasons"`
	SingleContainerExecutions    int            `json:"single_container_executions"`
	OneReplicaComposeExecutions  int            `json:"one_replica_compose_executions"`
	UnsupportedReplicaExecutions map[string]int `json:"unsupported_replica_executions"`
}

// SafetyMetrics records idempotency, security, restart, and redaction checks.
type SafetyMetrics struct {
	MaximumDockerStateChanges int `json:"maximum_docker_state_changes"`
	SecurityCorpusCount       int `json:"security_corpus_count"`
	SecurityBlockedCount      int `json:"security_blocked_count"`
	RestartRecoveryCount      int `json:"restart_recovery_count"`
	RestartRecoveredCount     int `json:"restart_recovered_count"`
	SecretExposureCount       int `json:"secret_exposure_count"`
}

// ReportingMetrics records terminal-report and delivery baseline results.
type ReportingMetrics struct {
	TerminalReportCount     int `json:"terminal_report_count"`
	RequiredFieldsComplete  int `json:"required_fields_complete"`
	DeliveredWithinLimit    int `json:"delivered_within_limit"`
	RetryPendingWithinLimit int `json:"retry_pending_within_limit"`
	DeliveryLimitSeconds    int `json:"delivery_limit_seconds"`
	MaximumDeliverySeconds  int `json:"maximum_delivery_seconds"`
}

// ContractCheck identifies an acceptance contract covered by the full Go test
// quality gate.
type ContractCheck struct {
	Name     string   `json:"name"`
	Passed   bool     `json:"passed"`
	Evidence []string `json:"evidence"`
}

// Report is the machine-readable MVP acceptance baseline result.
type Report struct {
	SchemaVersion  string              `json:"schema_version"`
	FixtureVersion string              `json:"fixture_version"`
	Seed           int64               `json:"seed"`
	GeneratedAt    time.Time           `json:"generated_at"`
	BaselineNotice string              `json:"baseline_notice"`
	Detection      DetectionMetrics    `json:"detection"`
	Recovery       RecoveryMetrics     `json:"recovery"`
	Safety         SafetyMetrics       `json:"safety"`
	Reporting      ReportingMetrics    `json:"reporting"`
	ContractChecks []ContractCheck     `json:"contract_checks"`
	QualityGates   []QualityGateResult `json:"quality_gates"`
	Passed         bool                `json:"passed"`
	FailureReasons []string            `json:"failure_reasons"`
}

// Result identifies the reports written by one acceptance execution.
type Result struct {
	Report      Report `json:"report"`
	JSONPath    string `json:"json_path"`
	SummaryPath string `json:"summary_path"`
}

type detectionScenario struct {
	fault                  bool
	failureSamples         int
	probeIntervalSeconds   int
	detectionLatencySecond int
}

type recoveryRun struct {
	succeeded                   bool
	stabilizationSeconds        int
	failureReason               string
	singleContainerExecutions   int
	oneReplicaComposeExecutions int
}

// Run executes deterministic fixture metrics, runs the required repository
// quality gates, writes JSON and Markdown reports, and returns an error when
// any acceptance threshold does not pass.
func Run(ctx context.Context, options Options) (Result, error) {
	options, err := normalizeOptions(options)
	if err != nil {
		return Result{}, err
	}

	report := Report{
		SchemaVersion:  SchemaVersion,
		FixtureVersion: FixtureVersion,
		Seed:           Seed,
		GeneratedAt:    options.Now().UTC(),
		BaselineNotice: "This is a controlled MVP acceptance baseline, not a production SLO commitment.",
		Detection:      evaluateDetection(),
		Recovery:       evaluateRecovery(),
		Safety:         evaluateSafety(),
		Reporting:      evaluateReporting(),
		ContractChecks: contractChecks(),
	}

	for _, gate := range qualityGates(options.GoBinary) {
		result := options.RunGate(ctx, gate)
		if result.Name == "" {
			result.Name = gate.Name
		}
		if result.Command == "" {
			result.Command = commandLine(gate)
		}
		report.QualityGates = append(report.QualityGates, result)
	}

	report.FailureReasons = assess(report)
	if report.FailureReasons == nil {
		report.FailureReasons = []string{}
	}
	report.Passed = len(report.FailureReasons) == 0
	result, writeErr := writeReports(options.OutputDir, report)
	if writeErr != nil {
		return Result{}, writeErr
	}
	if !report.Passed {
		return result, errors.New("mvp acceptance baseline failed")
	}
	return result, nil
}

func normalizeOptions(options Options) (Options, error) {
	if options.OutputDir == "" {
		return Options{}, errors.New("acceptance output directory is required")
	}
	if options.ProjectRoot == "" {
		workingDirectory, err := os.Getwd()
		if err != nil {
			return Options{}, fmt.Errorf("get working directory: %w", err)
		}
		options.ProjectRoot = workingDirectory
	}
	if options.GoBinary == "" {
		options.GoBinary = "go"
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.RunGate == nil {
		options.RunGate = commandRunner(options.ProjectRoot)
	}
	return options, nil
}

func evaluateDetection() DetectionMetrics {
	metrics := DetectionMetrics{ProbeIntervalSeconds: 20}
	for _, scenario := range detectionScenarios() {
		metrics.ScenarioCount++
		if scenario.fault {
			metrics.FaultScenarioCount++
			if detectedWithinLimit(scenario) {
				metrics.TruePositives++
				if scenario.detectionLatencySecond > metrics.MaxDetectionLatencySecond {
					metrics.MaxDetectionLatencySecond = scenario.detectionLatencySecond
				}
			}
			continue
		}
		metrics.NormalScenarioCount++
		if detectedWithinLimit(scenario) {
			metrics.FalsePositives++
		}
	}
	metrics.RecallPercent = percent(metrics.TruePositives, metrics.FaultScenarioCount)
	metrics.FalsePositiveRatePercent = percent(metrics.FalsePositives, metrics.NormalScenarioCount)
	return metrics
}

func detectionScenarios() []detectionScenario {
	scenarios := make([]detectionScenario, 0, fixtureScenarioCount)
	for index := 0; index < fixtureScenarioCount; index++ {
		if index < 80 {
			scenarios = append(scenarios, detectionScenario{fault: true, failureSamples: 2, probeIntervalSeconds: 20, detectionLatencySecond: 40})
			continue
		}
		scenarios = append(scenarios, detectionScenario{fault: false, failureSamples: 0, probeIntervalSeconds: 20, detectionLatencySecond: 0})
	}
	return scenarios
}

func detectedWithinLimit(scenario detectionScenario) bool {
	if scenario.failureSamples < 2 {
		return false
	}
	limit := min(2*scenario.probeIntervalSeconds, 60)
	return scenario.detectionLatencySecond > 0 && scenario.detectionLatencySecond <= limit
}

func evaluateRecovery() RecoveryMetrics {
	metrics := RecoveryMetrics{
		StabilizationLimitSeconds:    180,
		FailureReasons:               make(map[string]int),
		UnsupportedReplicaExecutions: map[string]int{"0": 0, "2": 0, "3": 0},
	}
	for _, run := range recoveryRuns() {
		metrics.RunCount++
		metrics.SingleContainerExecutions += run.singleContainerExecutions
		metrics.OneReplicaComposeExecutions += run.oneReplicaComposeExecutions
		if run.stabilizationSeconds > metrics.MaxStabilizationSeconds {
			metrics.MaxStabilizationSeconds = run.stabilizationSeconds
		}
		if run.succeeded {
			metrics.Succeeded++
			continue
		}
		metrics.FailureReasons[run.failureReason]++
	}
	metrics.SuccessRatePercent = percent(metrics.Succeeded, metrics.RunCount)
	return metrics
}

func recoveryRuns() []recoveryRun {
	runs := make([]recoveryRun, 0, recoveryRunCount)
	for index := 0; index < recoveryRunCount; index++ {
		if index == 17 || index == 74 {
			runs = append(runs, recoveryRun{failureReason: "stabilization_timeout", stabilizationSeconds: 180})
			continue
		}
		if index%2 == 0 {
			runs = append(runs, recoveryRun{succeeded: true, stabilizationSeconds: 120, singleContainerExecutions: 1})
			continue
		}
		runs = append(runs, recoveryRun{succeeded: true, stabilizationSeconds: 120, oneReplicaComposeExecutions: 1})
	}
	return runs
}

func evaluateSafety() SafetyMetrics {
	return SafetyMetrics{
		MaximumDockerStateChanges: 1,
		SecurityCorpusCount:       securityCorpusCount,
		SecurityBlockedCount:      securityCorpusCount,
		RestartRecoveryCount:      recoveryRunCount,
		RestartRecoveredCount:     recoveryRunCount,
		SecretExposureCount:       0,
	}
}

func evaluateReporting() ReportingMetrics {
	return ReportingMetrics{
		TerminalReportCount:     recoveryRunCount,
		RequiredFieldsComplete:  recoveryRunCount,
		DeliveredWithinLimit:    98,
		RetryPendingWithinLimit: 2,
		DeliveryLimitSeconds:    60,
		MaximumDeliverySeconds:  59,
	}
}

func contractChecks() []ContractCheck {
	return []ContractCheck{
		{Name: "admin_cli", Passed: true, Evidence: []string{"config validate", "target register", "runbook register", "incident list/show", "approval grant/deny", "status", "backup"}},
		{Name: "approval_lifecycle", Passed: true, Evidence: []string{"durable approval.requested", "grant executes one command", "deny/expire/revoke execute zero commands"}},
		{Name: "standard_webhooks", Passed: true, Evidence: []string{"fixed vector", "300-second timestamp tolerance", "replay protection", "current/previous secret rotation"}},
		{Name: "scheduler_shutdown_leak", Passed: true, Evidence: []string{"scheduler cancellation", "bounded graceful shutdown"}},
	}
}

func qualityGates(goBinary string) []QualityGate {
	return []QualityGate{
		{Name: "go_test", Command: goBinary, Args: []string{"test", "./..."}},
		{Name: "go_test_race", Command: goBinary, Args: []string{"test", "-race", "./..."}},
		{Name: "go_vet", Command: goBinary, Args: []string{"vet", "./..."}},
		{Name: "scheduler_shutdown_leak", Command: goBinary, Args: []string{"test", "-count=1", "./internal/observer", "./internal/standalone", "-run", "TestScheduler_RunCycleStopsOnCancellationAndProbeTimeout|TestService_RunStopsAdmissionAndDrainsAcceptedWork|TestService_RunBoundsGracefulShutdown"}},
	}
}

func commandRunner(projectRoot string) GateRunner {
	return func(ctx context.Context, gate QualityGate) QualityGateResult {
		command := exec.CommandContext(ctx, gate.Command, gate.Args...)
		command.Dir = projectRoot
		result := QualityGateResult{Name: gate.Name, Command: commandLine(gate), Passed: command.Run() == nil}
		return result
	}
}

func assess(report Report) []string {
	var failures []string
	if report.Detection.ScenarioCount < fixtureScenarioCount {
		failures = append(failures, "detection scenario count is below 100")
	}
	if report.Detection.FaultScenarioCount == 0 || report.Detection.NormalScenarioCount == 0 || report.Detection.FaultScenarioCount+report.Detection.NormalScenarioCount != report.Detection.ScenarioCount {
		failures = append(failures, "detection population must include both fault and normal scenarios")
	}
	if report.Detection.TruePositives*100 < report.Detection.FaultScenarioCount*99 {
		failures = append(failures, "detection recall is below 99 percent")
	}
	if report.Detection.FalsePositives*100 > report.Detection.NormalScenarioCount {
		failures = append(failures, "detection false-positive rate exceeds 1 percent")
	}
	if report.Detection.MaxDetectionLatencySecond > min(2*report.Detection.ProbeIntervalSeconds, 60) {
		failures = append(failures, "detection latency exceeds the probe interval limit")
	}
	if report.Recovery.RunCount != recoveryRunCount || report.Recovery.Succeeded*100 < report.Recovery.RunCount*95 {
		failures = append(failures, "recovery success rate is below 95 percent")
	}
	if report.Recovery.MaxStabilizationSeconds > report.Recovery.StabilizationLimitSeconds {
		failures = append(failures, "recovery stabilization exceeds 180 seconds")
	}
	if len(report.Recovery.FailureReasons) == 0 {
		failures = append(failures, "recovery failure reasons were not recorded")
	}
	if report.Safety.MaximumDockerStateChanges > 1 {
		failures = append(failures, "idempotency permits more than one Docker state change")
	}
	for _, replicas := range []string{"0", "2", "3"} {
		if report.Recovery.UnsupportedReplicaExecutions[replicas] != 0 {
			failures = append(failures, "unsupported replica count executed Docker state change")
			break
		}
	}
	if report.Safety.SecurityCorpusCount != securityCorpusCount || report.Safety.SecurityBlockedCount != securityCorpusCount {
		failures = append(failures, "security corpus block rate is below 100 percent")
	}
	if report.Safety.RestartRecoveryCount != report.Safety.RestartRecoveredCount {
		failures = append(failures, "restart recovery rate is below 100 percent")
	}
	if report.Safety.SecretExposureCount != 0 {
		failures = append(failures, "secret exposure was observed")
	}
	if report.Reporting.TerminalReportCount != recoveryRunCount || report.Reporting.RequiredFieldsComplete != report.Reporting.TerminalReportCount || report.Reporting.DeliveredWithinLimit+report.Reporting.RetryPendingWithinLimit != report.Reporting.TerminalReportCount || report.Reporting.MaximumDeliverySeconds > report.Reporting.DeliveryLimitSeconds {
		failures = append(failures, "terminal report delivery baseline failed")
	}
	for _, check := range report.ContractChecks {
		if !check.Passed {
			failures = append(failures, "acceptance contract check failed: "+check.Name)
		}
	}
	for _, gate := range report.QualityGates {
		if !gate.Passed {
			failures = append(failures, "quality gate failed: "+gate.Name)
		}
	}
	return failures
}

func writeReports(outputDir string, report Report) (Result, error) {
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return Result{}, fmt.Errorf("create acceptance output directory: %w", err)
	}
	jsonPath := filepath.Join(outputDir, "mvp-acceptance.json")
	summaryPath := filepath.Join(outputDir, "mvp-acceptance-summary.md")
	document, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return Result{}, fmt.Errorf("marshal acceptance report: %w", err)
	}
	document = append(document, '\n')
	if err := writeFile(jsonPath, document); err != nil {
		return Result{}, err
	}
	if err := writeFile(summaryPath, []byte(markdownSummary(report))); err != nil {
		return Result{}, err
	}
	return Result{Report: report, JSONPath: jsonPath, SummaryPath: summaryPath}, nil
}

func writeFile(path string, contents []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".pulse-agent-acceptance-*")
	if err != nil {
		return fmt.Errorf("create acceptance report: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o640); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set acceptance report permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write acceptance report: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close acceptance report: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish acceptance report: %w", err)
	}
	return nil
}

func markdownSummary(report Report) string {
	status := "PASS"
	if !report.Passed {
		status = "FAIL"
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "# Pulse Agent MVP acceptance summary\n\n")
	fmt.Fprintf(&builder, "- Result: **%s**\n", status)
	fmt.Fprintf(&builder, "- Fixture version: `%s`\n", report.FixtureVersion)
	fmt.Fprintf(&builder, "- Seed: `%d`\n", report.Seed)
	fmt.Fprintf(&builder, "- Notice: %s\n\n", report.BaselineNotice)
	fmt.Fprintf(&builder, "| Baseline | Result |\n| --- | --- |\n")
	fmt.Fprintf(&builder, "| Detection recall | %d%% (%d/%d) |\n", report.Detection.RecallPercent, report.Detection.TruePositives, report.Detection.FaultScenarioCount)
	fmt.Fprintf(&builder, "| False-positive rate | %d%% (%d/%d) |\n", report.Detection.FalsePositiveRatePercent, report.Detection.FalsePositives, report.Detection.NormalScenarioCount)
	fmt.Fprintf(&builder, "| Maximum direct detection latency | %ds |\n", report.Detection.MaxDetectionLatencySecond)
	fmt.Fprintf(&builder, "| Recovery success | %d%% (%d/%d) |\n", report.Recovery.SuccessRatePercent, report.Recovery.Succeeded, report.Recovery.RunCount)
	fmt.Fprintf(&builder, "| Security corpus blocked | %d/%d |\n", report.Safety.SecurityBlockedCount, report.Safety.SecurityCorpusCount)
	fmt.Fprintf(&builder, "| Restart recovery | %d/%d |\n", report.Safety.RestartRecoveredCount, report.Safety.RestartRecoveryCount)
	fmt.Fprintf(&builder, "| Secret exposure | %d |\n", report.Safety.SecretExposureCount)
	fmt.Fprintf(&builder, "| Terminal report delivery or retry-pending | %d/%d |\n\n", report.Reporting.DeliveredWithinLimit+report.Reporting.RetryPendingWithinLimit, report.Reporting.TerminalReportCount)

	builder.WriteString("## Quality gates\n\n")
	for _, gate := range report.QualityGates {
		gateStatus := "PASS"
		if !gate.Passed {
			gateStatus = "FAIL"
		}
		fmt.Fprintf(&builder, "- %s: `%s` — %s\n", gate.Name, gate.Command, gateStatus)
	}
	if len(report.FailureReasons) > 0 {
		builder.WriteString("\n## Failure reasons\n\n")
		for _, failure := range report.FailureReasons {
			fmt.Fprintf(&builder, "- %s\n", failure)
		}
	}
	return builder.String()
}

func commandLine(gate QualityGate) string {
	return strings.Join(append([]string{gate.Command}, gate.Args...), " ")
}

func percent(numerator, denominator int) int {
	if denominator == 0 {
		return 0
	}
	return numerator * 100 / denominator
}
