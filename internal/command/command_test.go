package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pulse-agent/internal/adminipc"
	"pulse-agent/internal/config"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/incident"
	"pulse-agent/internal/runbook"
	"pulse-agent/internal/target"
)

type runnerFunc func(context.Context) error

func (f runnerFunc) Run(ctx context.Context) error {
	return f(ctx)
}

type fakeAdminClient struct {
	status          func(context.Context, string, string) (adminipc.Status, error)
	backup          func(context.Context, string, string, io.Writer) error
	register        func(context.Context, string, string, contract.ServiceTarget) (target.RegistrationResult, error)
	registerRunbook func(context.Context, string, string, contract.Runbook) (runbook.RegistrationResult, error)
	listIncidents   func(context.Context, string, string, incident.Filter) (incident.Page, error)
	showIncident    func(context.Context, string, string, string) (contract.Incident, error)
	decideApproval  func(context.Context, string, string, string, contract.ApprovalDecision, time.Time) (adminipc.ApprovalResult, error)
}

func (c fakeAdminClient) ListIncidents(ctx context.Context, socketPath, reason string, filter incident.Filter) (incident.Page, error) {
	if c.listIncidents == nil {
		return incident.Page{}, errors.New("unexpected incident list")
	}
	return c.listIncidents(ctx, socketPath, reason, filter)
}
func (c fakeAdminClient) ShowIncident(ctx context.Context, socketPath, reason, id string) (contract.Incident, error) {
	if c.showIncident == nil {
		return contract.Incident{}, errors.New("unexpected incident show")
	}
	return c.showIncident(ctx, socketPath, reason, id)
}

func (c fakeAdminClient) DecideApproval(ctx context.Context, socketPath, reason, commandID string, decision contract.ApprovalDecision, expiresAt time.Time) (adminipc.ApprovalResult, error) {
	if c.decideApproval == nil {
		return adminipc.ApprovalResult{}, errors.New("unexpected approval decision")
	}
	return c.decideApproval(ctx, socketPath, reason, commandID, decision, expiresAt)
}

func (c fakeAdminClient) RegisterRunbook(ctx context.Context, socketPath, reasonCode string, submitted contract.Runbook) (runbook.RegistrationResult, error) {
	if c.registerRunbook == nil {
		return runbook.RegistrationResult{}, errors.New("unexpected runbook registration")
	}
	return c.registerRunbook(ctx, socketPath, reasonCode, submitted)
}

func (c fakeAdminClient) Status(ctx context.Context, socketPath, reasonCode string) (adminipc.Status, error) {
	if c.status == nil {
		return adminipc.Status{}, errors.New("unexpected status request")
	}
	return c.status(ctx, socketPath, reasonCode)
}

func (c fakeAdminClient) Backup(ctx context.Context, socketPath, reasonCode string, destination io.Writer) error {
	if c.backup == nil {
		return errors.New("unexpected backup request")
	}
	return c.backup(ctx, socketPath, reasonCode, destination)
}

func (c fakeAdminClient) Register(ctx context.Context, socketPath, reasonCode string, submitted contract.ServiceTarget) (target.RegistrationResult, error) {
	if c.register == nil {
		return target.RegistrationResult{}, errors.New("unexpected target registration")
	}
	return c.register(ctx, socketPath, reasonCode, submitted)
}

func TestExecute_HelpExposesApprovedCommands(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := execute(
		context.Background(),
		[]string{"--help"},
		&stdout,
		&stderr,
		runnerFunc(func(context.Context) error { return nil }),
	)

	if exitCode != ExitSuccess {
		t.Fatalf("execute() exit code = %d, want %d", exitCode, ExitSuccess)
	}
	if stderr.Len() != 0 {
		t.Fatalf("execute() stderr = %q, want empty", stderr.String())
	}

	wantCommands := []string{
		"standalone",
		"config validate",
		"target register",
		"incident list",
		"incident show",
		"approval grant",
		"approval deny",
		"status",
		"backup",
	}
	for _, commandName := range wantCommands {
		if !strings.Contains(stdout.String(), commandName) {
			t.Errorf("help output does not contain %q", commandName)
		}
	}
}

func TestExecute_IncidentListUsesDaemonClient(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	loader := func(string) (config.Config, error) {
		return config.Config{Admin: config.AdminConfig{SocketPath: "/tmp/admin.sock"}}, nil
	}
	client := fakeAdminClient{listIncidents: func(_ context.Context, socketPath, _ string, filter incident.Filter) (incident.Page, error) {
		called = socketPath == "/tmp/admin.sock" && filter.State == contract.IncidentOpen && filter.PageSize == 1
		return incident.Page{Incidents: []contract.Incident{}}, nil
	}}
	if code := executeWithDependencies(context.Background(), []string{"incident", "list", "--config", "config.json", "--state", "open", "--page-size", "1"}, &stdout, &stderr, runnerFunc(func(context.Context) error { return nil }), loader, client); code != ExitSuccess {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if !called {
		t.Fatal("incident list did not use daemon client")
	}
}

func TestExecute_ApprovalRoutesThroughDaemonClient(t *testing.T) {
	expiresAt := time.Date(2026, time.July, 21, 1, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		decision contract.ApprovalDecision
	}{
		{name: "grant", decision: contract.ApprovalGranted},
		{name: "deny", decision: contract.ApprovalDenied},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			called := false
			exitCode := executeWithDependencies(
				context.Background(),
				[]string{"approval", string(tt.decision), "--config", "config.json", "--command-id", "command-1", "--expires-at", expiresAt.Format(time.RFC3339), "--reason", "operator_requested"},
				&stdout,
				&stderr,
				runnerFunc(func(context.Context) error { return nil }),
				func(string) (config.Config, error) {
					return config.Config{Admin: config.AdminConfig{SocketPath: "/tmp/pulse-agent/admin.sock"}}, nil
				},
				fakeAdminClient{decideApproval: func(_ context.Context, socketPath, reason, commandID string, decision contract.ApprovalDecision, gotExpiresAt time.Time) (adminipc.ApprovalResult, error) {
					called = socketPath == "/tmp/pulse-agent/admin.sock" && reason == "operator_requested" && commandID == "command-1" && decision == tt.decision && gotExpiresAt.Equal(expiresAt)
					state := contract.RecoveryPending
					if decision == contract.ApprovalDenied {
						state = contract.RecoveryDenied
					}
					return adminipc.ApprovalResult{SchemaVersion: adminipc.SchemaVersion, ApprovalID: "approval-1", CommandID: commandID, Decision: decision, CommandState: state, ExpiresAt: gotExpiresAt}, nil
				}},
			)

			if exitCode != ExitSuccess {
				t.Fatalf("execute() exit code = %d, want %d; stderr = %s", exitCode, ExitSuccess, stderr.String())
			}
			if !called {
				t.Fatal("approval did not use daemon client")
			}
			var result adminipc.ApprovalResult
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatalf("decode approval result %q: %v", stdout.String(), err)
			}
			if result.Decision != tt.decision {
				t.Errorf("decision = %q, want %q", result.Decision, tt.decision)
			}
		})
	}
}

func TestExecute_TargetRegisterRoutesThroughDaemonClient(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	targetPath := filepath.Join(t.TempDir(), "target.json")
	submitted := contract.ServiceTarget{
		SchemaVersion: contract.SchemaVersionV1,
		TargetID:      "checkout",
		AdapterType:   "docker",
		Selector:      "container:checkout",
		ProbeRules: []contract.ProbeRule{{
			RuleID:              "availability",
			SignalType:          "availability",
			Interval:            contract.NewDuration(time.Minute),
			Timeout:             contract.NewDuration(time.Second),
			Threshold:           1,
			ConsecutiveFailures: 3,
			RecoverySamples:     2,
			SLOWindow:           contract.NewDuration(5 * time.Minute),
			Severity:            contract.SeverityCritical,
		}},
		EvidencePolicy: contract.EvidencePolicy{RedactionProfile: "strict", MaxBytes: 1024},
		StabilizationPolicy: contract.StabilizationPolicy{
			RecoverySamples: 2,
			Window:          contract.NewDuration(time.Minute),
		},
		Enabled: true,
	}
	document, err := json.Marshal(submitted)
	if err != nil {
		t.Fatalf("marshal target: %v", err)
	}
	if err := os.WriteFile(targetPath, document, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	called := false
	exitCode := executeWithDependencies(
		context.Background(),
		[]string{"target", "register", "--config", "test.json", "--target", targetPath, "--reason", "onboarding"},
		&stdout,
		&stderr,
		runnerFunc(func(context.Context) error { return nil }),
		func(string) (config.Config, error) {
			return config.Config{Admin: config.AdminConfig{SocketPath: "/var/lib/pulse-agent/admin.sock"}}, nil
		},
		fakeAdminClient{register: func(_ context.Context, socketPath, reasonCode string, got contract.ServiceTarget) (target.RegistrationResult, error) {
			called = true
			if socketPath != "/var/lib/pulse-agent/admin.sock" || reasonCode != "onboarding" {
				t.Errorf("register route = socket %q, reason %q", socketPath, reasonCode)
			}
			if got.TargetID != submitted.TargetID {
				t.Errorf("target ID = %q, want %q", got.TargetID, submitted.TargetID)
			}
			return target.RegistrationResult{SchemaVersion: target.SchemaVersion, Version: 1, TargetID: submitted.TargetID}, nil
		}},
	)

	if exitCode != ExitSuccess {
		t.Fatalf("executeWithDependencies() exit code = %d, want %d; stderr = %s", exitCode, ExitSuccess, stderr.String())
	}
	if !called {
		t.Fatal("target register did not use daemon client")
	}
	var result target.RegistrationResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode target registration result %q: %v", stdout.String(), err)
	}
	if result.Version != 1 || result.TargetID != submitted.TargetID {
		t.Errorf("target registration result = %#v, want registered target", result)
	}
}

func TestExecute_RunbookValidateIsLocalAndRegisterUsesDaemonClient(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "runbook.md"), []byte("---\nrunbook_id: restart-checkout\nversion: 1\n---\n"), 0o600); err != nil {
		t.Fatalf("write markdown: %v", err)
	}
	document := []byte(`{"schema_version":"v1","runbook_id":"restart-checkout","version":"1","adapter_type":"docker","target_constraints":[],"typed_actions":[{"action_type":"docker.container.restart","target_selector":"container:checkout","stop_timeout":"5s","cooldown":"0s"}],"risk_tier":"low","auto_execute":false,"approval_policy":{"required":false},"preconditions":[],"retry_policy":{"max_attempts":1},"stabilization_policy":{"recovery_samples":1,"window":"1m"}}`)
	if err := os.WriteFile(filepath.Join(directory, "runbook.json"), document, 0o600); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := executeWithDependencies(context.Background(), []string{"runbook", "validate", "--runbook", directory}, &stdout, &stderr, runnerFunc(func(context.Context) error { return nil }), config.Load, fakeAdminClient{}); code != ExitSuccess {
		t.Fatalf("validate exit code = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "restart-checkout") {
		t.Errorf("validate stdout = %q, want runbook result", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	called := false
	client := fakeAdminClient{registerRunbook: func(_ context.Context, socketPath, reason string, submitted contract.Runbook) (runbook.RegistrationResult, error) {
		called = true
		if socketPath == "" || reason == "" || submitted.Digest == "" {
			t.Errorf("daemon request = socket=%q reason=%q runbook=%#v", socketPath, reason, submitted)
		}
		return runbook.RegistrationResult{SchemaVersion: runbook.SchemaVersion, RunbookID: submitted.RunbookID, Digest: submitted.Digest}, nil
	}}
	loader := func(string) (config.Config, error) {
		return config.Config{Admin: config.AdminConfig{SocketPath: "/tmp/pulse-agent/admin.sock"}}, nil
	}
	if code := executeWithDependencies(context.Background(), []string{"runbook", "register", "--config", "config.json", "--runbook", directory}, &stdout, &stderr, runnerFunc(func(context.Context) error { return nil }), loader, client); code != ExitSuccess {
		t.Fatalf("register exit code = %d, stderr=%s", code, stderr.String())
	}
	if !called {
		t.Fatal("runbook register did not use daemon client")
	}
}

func TestExecute_StatusRoutesThroughDaemonClient(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var gotSocketPath string
	var gotReasonCode string

	exitCode := executeWithDependencies(
		context.Background(),
		[]string{"status", "--config", "test.json"},
		&stdout,
		&stderr,
		runnerFunc(func(context.Context) error { return nil }),
		func(string) (config.Config, error) {
			return config.Config{Admin: config.AdminConfig{SocketPath: "/var/lib/pulse-agent/admin.sock"}}, nil
		},
		fakeAdminClient{status: func(_ context.Context, socketPath, reasonCode string) (adminipc.Status, error) {
			gotSocketPath = socketPath
			gotReasonCode = reasonCode
			return adminipc.Status{
				SchemaVersion: adminipc.SchemaVersion,
				State:         adminipc.StatusRunning,
				Capabilities:  []string{"admin_ipc"},
				Unsupported:   []string{"host_power_os_network_outage"},
			}, nil
		}},
	)

	if exitCode != ExitSuccess {
		t.Fatalf("executeWithDependencies() exit code = %d, want %d; stderr = %s", exitCode, ExitSuccess, stderr.String())
	}
	if gotSocketPath != "/var/lib/pulse-agent/admin.sock" {
		t.Errorf("status socket path = %q, want daemon socket path", gotSocketPath)
	}
	if gotReasonCode != adminipc.DefaultReasonCode {
		t.Errorf("status reason code = %q, want default", gotReasonCode)
	}
	if strings.Contains(stdout.String(), "state.db") {
		t.Fatalf("status output exposed a local state path: %q", stdout.String())
	}

	var status adminipc.Status
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("decode status %q: %v", stdout.String(), err)
	}
	if status.State != adminipc.StatusRunning {
		t.Errorf("status state = %q, want %q", status.State, adminipc.StatusRunning)
	}
}

func TestExecute_BackupRoutesThroughDaemonClient(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false

	exitCode := executeWithDependencies(
		context.Background(),
		[]string{"backup", "--config", "test.json", "--reason", "routine_backup"},
		&stdout,
		&stderr,
		runnerFunc(func(context.Context) error { return nil }),
		func(string) (config.Config, error) {
			return config.Config{Admin: config.AdminConfig{SocketPath: "/var/lib/pulse-agent/admin.sock"}}, nil
		},
		fakeAdminClient{backup: func(_ context.Context, socketPath, reasonCode string, destination io.Writer) error {
			called = true
			if socketPath != "/var/lib/pulse-agent/admin.sock" || reasonCode != "routine_backup" {
				t.Errorf("backup request = socket %q, reason %q", socketPath, reasonCode)
			}
			_, err := io.WriteString(destination, "snapshot")
			return err
		}},
	)

	if exitCode != ExitSuccess {
		t.Fatalf("executeWithDependencies() exit code = %d, want %d; stderr = %s", exitCode, ExitSuccess, stderr.String())
	}
	if !called {
		t.Fatal("backup did not use daemon client")
	}
	if got := stdout.String(); got != "snapshot" {
		t.Errorf("backup output = %q, want daemon snapshot", got)
	}
}

func TestExecute_AdminRequestFailureDoesNotExposeClientError(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := executeWithDependencies(
		context.Background(),
		[]string{"status", "--config", "test.json"},
		&stdout,
		&stderr,
		runnerFunc(func(context.Context) error { return nil }),
		func(string) (config.Config, error) {
			return config.Config{Admin: config.AdminConfig{SocketPath: "/var/lib/pulse-agent/admin.sock"}}, nil
		},
		fakeAdminClient{status: func(context.Context, string, string) (adminipc.Status, error) {
			return adminipc.Status{}, errors.New("very-secret-client-detail")
		}},
	)

	if exitCode != ExitFailure {
		t.Fatalf("executeWithDependencies() exit code = %d, want %d", exitCode, ExitFailure)
	}
	if strings.Contains(stderr.String(), "very-secret-client-detail") {
		t.Fatalf("diagnostic exposed client detail: %q", stderr.String())
	}
	var got diagnostic
	if err := json.Unmarshal(stderr.Bytes(), &got); err != nil {
		t.Fatalf("decode diagnostic %q: %v", stderr.String(), err)
	}
	if got.Error.Code != "daemon_unavailable" {
		t.Errorf("error code = %q, want daemon_unavailable", got.Error.Code)
	}
}

func TestExecute_StandaloneUsesCallerContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false

	exitCode := executeWithConfig(
		ctx,
		[]string{"standalone", "--config", "test.json"},
		&stdout,
		&stderr,
		runnerFunc(func(got context.Context) error {
			called = true
			return got.Err()
		}),
		func(string) (config.Config, error) { return config.Config{}, nil },
	)

	if !called {
		t.Fatal("standalone runner was not called")
	}
	if exitCode != ExitFailure {
		t.Fatalf("execute() exit code = %d, want %d", exitCode, ExitFailure)
	}

	var got diagnostic
	if err := json.Unmarshal(stderr.Bytes(), &got); err != nil {
		t.Fatalf("decode diagnostic %q: %v", stderr.String(), err)
	}
	if got.Error.Code != "standalone_failed" {
		t.Errorf("error code = %q, want %q", got.Error.Code, "standalone_failed")
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("context error = %v, want %v", ctx.Err(), context.Canceled)
	}
}

func TestExecute_ConfigValidateReadsOnlyConfigAndDoesNotExposeSecrets(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "config", "testdata", "valid-production.json"))
	if err != nil {
		t.Fatalf("read valid fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config fixture before validation: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := execute(
		context.Background(),
		[]string{"config", "validate", "--config", path},
		&stdout,
		&stderr,
		runnerFunc(func(context.Context) error { t.Fatal("config validate started standalone service"); return nil }),
	)

	if exitCode != ExitSuccess {
		t.Fatalf("execute() exit code = %d, want %d; stderr = %s", exitCode, ExitSuccess, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("execute() stderr = %q, want empty", stderr.String())
	}
	var result configValidation
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode validation result %q: %v", stdout.String(), err)
	}
	if result.SchemaVersion != "pulse-agent.cli.config_validation.v1" || !result.Valid {
		t.Errorf("validation result = %#v, want valid config result", result)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config fixture after validation: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("config validate changed the configuration file modification time")
	}
}

func TestExecute_ConfigValidateReturnsSecretFreeDiagnostic(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "config", "testdata", "invalid-plain-secret.json"))
	if err != nil {
		t.Fatalf("read invalid fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatalf("write invalid fixture: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := execute(
		context.Background(),
		[]string{"config", "validate", "--config", path},
		&stdout,
		&stderr,
		runnerFunc(func(context.Context) error { t.Fatal("config validate started standalone service"); return nil }),
	)

	if exitCode != ExitFailure {
		t.Fatalf("execute() exit code = %d, want %d", exitCode, ExitFailure)
	}
	if stdout.Len() != 0 {
		t.Errorf("execute() stdout = %q, want empty", stdout.String())
	}
	if strings.Contains(stderr.String(), "very-secret-value") || strings.Contains(stderr.String(), "env:KEY") {
		t.Fatalf("diagnostic exposed secret material: %q", stderr.String())
	}
	var got diagnostic
	if err := json.Unmarshal(stderr.Bytes(), &got); err != nil {
		t.Fatalf("decode diagnostic %q: %v", stderr.String(), err)
	}
	if got.Error.Code != "config_invalid" || got.Error.Command != "config validate" {
		t.Errorf("diagnostic = %#v, want config_invalid for config validate", got)
	}
}

func TestExecute_StandaloneRejectsInvalidConfigBeforeStartingService(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false

	exitCode := executeWithConfig(
		context.Background(),
		[]string{"standalone", "--config", "invalid.json"},
		&stdout,
		&stderr,
		runnerFunc(func(context.Context) error { called = true; return nil }),
		func(string) (config.Config, error) { return config.Config{}, errors.New("invalid configuration") },
	)

	if exitCode != ExitFailure {
		t.Fatalf("execute() exit code = %d, want %d", exitCode, ExitFailure)
	}
	if called {
		t.Fatal("standalone service started after configuration validation failed")
	}
	if strings.Contains(stderr.String(), "invalid.json") {
		t.Fatalf("diagnostic exposed configuration path: %q", stderr.String())
	}
}

func TestExecute_UnknownCommandReturnsUsageError(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := execute(
		context.Background(),
		[]string{"cluster"},
		&stdout,
		&stderr,
		runnerFunc(func(context.Context) error { return nil }),
	)

	if exitCode != ExitUsage {
		t.Fatalf("execute() exit code = %d, want %d", exitCode, ExitUsage)
	}

	var got diagnostic
	if err := json.Unmarshal(stderr.Bytes(), &got); err != nil {
		t.Fatalf("decode diagnostic %q: %v", stderr.String(), err)
	}
	if got.Error.Code != "unknown_command" {
		t.Errorf("error code = %q, want %q", got.Error.Code, "unknown_command")
	}
}
