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

	"pulse-agent/internal/adminipc"
	"pulse-agent/internal/config"
)

type runnerFunc func(context.Context) error

func (f runnerFunc) Run(ctx context.Context) error {
	return f(ctx)
}

type fakeAdminClient struct {
	status func(context.Context, string, string) (adminipc.Status, error)
	backup func(context.Context, string, string, io.Writer) error
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
		"runbook validate",
		"runbook register",
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

func TestExecute_RecognizedUnimplementedCommandsReturnStructuredError(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "target register", args: []string{"target", "register"}},
		{name: "runbook validate", args: []string{"runbook", "validate"}},
		{name: "runbook register", args: []string{"runbook", "register"}},
		{name: "incident list", args: []string{"incident", "list"}},
		{name: "incident show", args: []string{"incident", "show"}},
		{name: "approval grant", args: []string{"approval", "grant"}},
		{name: "approval deny", args: []string{"approval", "deny"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			exitCode := execute(
				context.Background(),
				tt.args,
				&stdout,
				&stderr,
				runnerFunc(func(context.Context) error { return nil }),
			)

			if exitCode != ExitNotImplemented {
				t.Fatalf("execute() exit code = %d, want %d", exitCode, ExitNotImplemented)
			}
			if stdout.Len() != 0 {
				t.Fatalf("execute() stdout = %q, want empty", stdout.String())
			}

			var got diagnostic
			if err := json.Unmarshal(stderr.Bytes(), &got); err != nil {
				t.Fatalf("decode diagnostic %q: %v", stderr.String(), err)
			}
			if got.SchemaVersion != errorSchemaVersion {
				t.Errorf("schema version = %q, want %q", got.SchemaVersion, errorSchemaVersion)
			}
			if got.Error.Code != "not_implemented" {
				t.Errorf("error code = %q, want %q", got.Error.Code, "not_implemented")
			}
			if got.Error.Command != tt.name {
				t.Errorf("error command = %q, want %q", got.Error.Command, tt.name)
			}
			if got.Error.Retryable {
				t.Error("error retryable = true, want false")
			}
		})
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
