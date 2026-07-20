package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type runnerFunc func(context.Context) error

func (f runnerFunc) Run(ctx context.Context) error {
	return f(ctx)
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
		{name: "config validate", args: []string{"config", "validate"}},
		{name: "target register", args: []string{"target", "register"}},
		{name: "runbook validate", args: []string{"runbook", "validate"}},
		{name: "runbook register", args: []string{"runbook", "register"}},
		{name: "incident list", args: []string{"incident", "list"}},
		{name: "incident show", args: []string{"incident", "show"}},
		{name: "approval grant", args: []string{"approval", "grant"}},
		{name: "approval deny", args: []string{"approval", "deny"}},
		{name: "status", args: []string{"status"}},
		{name: "backup", args: []string{"backup"}},
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

func TestExecute_StandaloneUsesCallerContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false

	exitCode := execute(
		ctx,
		[]string{"standalone"},
		&stdout,
		&stderr,
		runnerFunc(func(got context.Context) error {
			called = true
			return got.Err()
		}),
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
