//go:build linux

// Package e2eadmin verifies the Linux-only administrative CLI boundary end to end.
package e2eadmin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"pulse-agent/internal/adminipc"
	"pulse-agent/internal/command"
	"pulse-agent/internal/config"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/incident"
	"pulse-agent/internal/standalone"
	"pulse-agent/internal/store"
	"pulse-agent/internal/target"
)

const (
	testTimeout           = 3 * time.Second
	testSecretMarker      = "e2e-secret-must-not-leak"
	testRawEvidenceMarker = "e2e-raw-evidence-must-not-leak"
)

func TestManagementCLI_E2EConfigValidationLeavesDaemonStateUntouched(t *testing.T) {
	runtimeConfig, configPath, statePath := newRuntimeConfig(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exitCode := command.Execute(testContext(t), []string{"config", "validate", "--config", configPath}, &stdout, &stderr); exitCode != command.ExitSuccess {
		t.Fatalf("config validate exit code = %d, want %d; stderr = %s", exitCode, command.ExitSuccess, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"valid":true`)) || stderr.Len() != 0 {
		t.Fatalf("config validate output = stdout %q stderr %q", stdout.String(), stderr.String())
	}
	assertStateAbsent(t, statePath)

	runtimeConfig.Gemini.APIKeyRef = config.SecretReference(testSecretMarker)
	writeConfig(t, configPath, runtimeConfig)
	stdout.Reset()
	stderr.Reset()
	if exitCode := command.Execute(testContext(t), []string{"config", "validate", "--config", configPath}, &stdout, &stderr); exitCode == command.ExitSuccess {
		t.Fatal("invalid config validate succeeded")
	}
	if bytes.Contains(stderr.Bytes(), []byte(testSecretMarker)) {
		t.Fatal("invalid config diagnostic exposed secret material")
	}
	if stdout.Len() != 0 {
		t.Fatalf("invalid config wrote unexpected stdout: %d bytes", stdout.Len())
	}
	assertStateAbsent(t, statePath)
}

func TestManagementCLI_E2EDaemonFlowsPersistAndRedact(t *testing.T) {
	runtimeConfig, configPath, statePath := newRuntimeConfig(t)
	seedIncidents(t, statePath)
	targetPath := writeTarget(t)
	runbookPath := writeRunbook(t)

	stop := startStandalone(t, runtimeConfig)
	assertCommandSuccess(t, []string{"status", "--config", configPath}, func(stdout []byte) {
		var status adminipc.Status
		if err := json.Unmarshal(stdout, &status); err != nil {
			t.Fatalf("decode status %q: %v", stdout, err)
		}
		if status.State != adminipc.StatusRunning {
			t.Errorf("status state = %q, want %q", status.State, adminipc.StatusRunning)
		}
	})
	assertCommandSuccess(t, []string{"target", "register", "--config", configPath, "--target", targetPath, "--reason", "onboarding"}, func(stdout []byte) {
		var result target.RegistrationResult
		if err := json.Unmarshal(stdout, &result); err != nil {
			t.Fatalf("decode target registration %q: %v", stdout, err)
		}
		if result.Version != 1 || result.TargetID != "checkout" {
			t.Errorf("target registration = %#v, want checkout at version 1", result)
		}
	})
	assertCommandSuccess(t, []string{"runbook", "validate", "--runbook", runbookPath}, func(stdout []byte) {
		if !bytes.Contains(stdout, []byte(`"runbook_id":"restart-checkout"`)) {
			t.Errorf("runbook validation = %q, want restart-checkout", stdout)
		}
	})
	assertCommandSuccess(t, []string{"runbook", "register", "--config", configPath, "--runbook", runbookPath, "--reason", "onboarding"}, func(stdout []byte) {
		if !bytes.Contains(stdout, []byte(`"runbook_id":"restart-checkout"`)) {
			t.Errorf("runbook registration = %q, want restart-checkout", stdout)
		}
	})
	assertCommandSuccess(t, []string{"incident", "list", "--config", configPath, "--page-size", "1"}, func(stdout []byte) {
		var page incident.Page
		if err := json.Unmarshal(stdout, &page); err != nil {
			t.Fatalf("decode incident page %q: %v", stdout, err)
		}
		if len(page.Incidents) != 1 || page.Incidents[0].IncidentID != "incident-1" || page.NextOffset != 1 {
			t.Errorf("incident page = %#v, want first deterministic page", page)
		}
	})
	assertCommandSuccess(t, []string{"incident", "list", "--config", configPath, "--state", "closed", "--page-size", "1"}, func(stdout []byte) {
		if !bytes.Contains(stdout, []byte(`"incident_id":"incident-2"`)) {
			t.Errorf("closed incident filter = %q, want incident-2", stdout)
		}
	})
	assertCommandSuccess(t, []string{"incident", "show", "--config", configPath, "--id", "incident-1"}, func(stdout []byte) {
		if bytes.Contains(stdout, []byte(testRawEvidenceMarker)) {
			t.Error("incident show exposed raw evidence")
		}
		if !bytes.Contains(stdout, []byte(`"incident_id":"incident-1"`)) {
			t.Errorf("incident show did not return incident-1: %d bytes", len(stdout))
		}
	})
	assertCommandSuccess(t, []string{"backup", "--config", configPath}, func(stdout []byte) {
		if len(stdout) == 0 {
			t.Error("backup returned an empty daemon snapshot")
		}
	})

	stop()
	assertPersistedRegistrations(t, statePath)
	assertAuditedOperations(t, statePath)

	stop = startStandalone(t, runtimeConfig)
	assertCommandSuccess(t, []string{"status", "--config", configPath}, func([]byte) {})
	assertDaemonCommandFailure(t, []string{"target", "register", "--config", configPath, "--target", targetPath})
	assertDaemonCommandFailure(t, []string{"runbook", "register", "--config", configPath, "--runbook", runbookPath})
	stop()
	assertPersistedRegistrations(t, statePath)
}

func TestManagementCLI_E2EDaemonUnavailableAndSymlinkDoNotCreateState(t *testing.T) {
	runtimeConfig, configPath, statePath := newRuntimeConfig(t)
	targetPath := writeTarget(t)

	assertCommandFailure(t, []string{"target", "register", "--config", configPath, "--target", targetPath}, statePath)
	if err := os.Symlink(filepath.Join(t.TempDir(), "replacement"), runtimeConfig.Admin.SocketPath); err != nil {
		t.Fatalf("create replacement socket symlink: %v", err)
	}
	assertCommandFailure(t, []string{"status", "--config", configPath}, statePath)
}

func TestAdminIPCE2EUnauthorizedAndMalformedRequestsAreAuditedWithoutTargetMutation(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "state.db")
	state := openState(t, statePath)
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Errorf("close administrative E2E state: %v", err)
		}
	})
	actor := adminipc.Actor{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	registry, err := target.NewRegistry(target.Options{
		State:            state,
		AllowedTargets:   []target.AllowedTarget{{TargetID: "checkout", AdapterType: "docker"}},
		MaxTargets:       1,
		MaxEvidenceBytes: 1024,
		Clock:            time.Now,
		NewAuditEventID:  adminipc.NewAuditID,
	})
	if err != nil {
		t.Fatalf("create target registry: %v", err)
	}

	socketPath := filepath.Join(directory, "admin.sock")
	unauthorizedStop := startServer(t, state, socketPath, actor, adminipc.Actor{UID: actor.UID + 1, GID: actor.GID}, registry)
	client, err := adminipc.NewProductionClient()
	if err != nil {
		t.Fatalf("create production client: %v", err)
	}
	if _, err := client.Register(testContext(t), socketPath, "onboarding", testTarget()); !errors.Is(err, adminipc.ErrRequestRejected) {
		t.Fatalf("unauthorized target registration error = %v, want %v", err, adminipc.ErrRequestRejected)
	}
	unauthorizedStop()

	authorizedStop := startServer(t, state, socketPath, actor, actor, registry)
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("dial administrative socket: %v", err)
	}
	t.Cleanup(func() {
		if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close malformed-request connection: %v", err)
		}
	})
	if _, err := connection.Write([]byte(`{"schema_version":"v1","request_id":"request-malformed","operation":"target.register","reason_code":"onboarding","unexpected":true}` + "\n")); err != nil {
		t.Fatalf("write malformed request: %v", err)
	}
	if _, err := bufio.NewReader(connection).ReadBytes('\n'); err != nil {
		t.Fatalf("read malformed response: %v", err)
	}
	authorizedStop()

	if snapshot := registry.Snapshot(); snapshot.Version != 0 || len(snapshot.Targets) != 0 {
		t.Fatalf("rejected requests mutated target registry: %#v", snapshot)
	}
	assertRejectedAudits(t, state)
}

func newRuntimeConfig(t *testing.T) (config.Config, string, string) {
	t.Helper()
	directory := t.TempDir()
	dataDirectory := filepath.Join(directory, "data")
	evidenceDirectory := filepath.Join(dataDirectory, "evidence")
	if err := os.MkdirAll(evidenceDirectory, 0o700); err != nil {
		t.Fatalf("create temporary data directories: %v", err)
	}
	runtimeConfig := config.Config{
		SchemaVersion:     config.SchemaVersion,
		UsageMode:         config.UsageSyntheticDevelopment,
		DataDirectory:     dataDirectory,
		EvidenceDirectory: evidenceDirectory,
		Docker:            config.DockerConfig{Endpoint: "unix://" + filepath.Join(directory, "docker.sock")},
		Admin: config.AdminConfig{
			SocketPath:  filepath.Join(dataDirectory, "admin.sock"),
			AllowedUIDs: []uint32{uint32(os.Getuid())},
			AllowedGIDs: []uint32{uint32(os.Getgid())},
		},
		Limits: config.LimitsConfig{
			MaxTargets: 1,
			Retention:  config.RetentionConfig{MaxAge: contract.NewDuration(time.Hour), MaxBytes: 1024},
		},
		AllowedTargets: []config.AllowedTarget{{TargetID: "checkout", AdapterType: "docker"}},
		Gemini: config.GeminiConfig{
			Provider:           "gemini",
			Model:              "gemini-2.5-flash",
			Timeout:            contract.NewDuration(time.Second),
			DataProcessingMode: config.DataProcessingUnpaidOrFree,
			APIKeyRef:          "env:PULSE_AGENT_TEST_KEY",
		},
		Webhooks: config.WebhooksConfig{
			Ingress:  config.WebhookConfig{Endpoint: "http://127.0.0.1:1/ingress", SecretRef: "env:PULSE_AGENT_TEST_INGRESS"},
			Outbound: config.WebhookConfig{Endpoint: "http://127.0.0.1:1/outbound", SecretRef: "env:PULSE_AGENT_TEST_OUTBOUND"},
		},
	}
	configPath := filepath.Join(directory, "config.json")
	writeConfig(t, configPath, runtimeConfig)
	return runtimeConfig, configPath, filepath.Join(dataDirectory, "state.db")
}

func writeConfig(t *testing.T, path string, runtimeConfig config.Config) {
	t.Helper()
	document, err := json.Marshal(runtimeConfig)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func startStandalone(t *testing.T, runtimeConfig config.Config) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var runErr error
	go func() {
		runErr = standalone.New().RunWithConfig(ctx, runtimeConfig)
		close(done)
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			select {
			case <-done:
				if runErr != nil {
					t.Errorf("standalone daemon stopped with error: %v", runErr)
				}
			case <-time.After(testTimeout):
				t.Error("standalone daemon did not stop before timeout")
			}
		})
	}
	t.Cleanup(stop)
	waitForSocket(t, runtimeConfig.Admin.SocketPath, done, func() error { return runErr })
	return stop
}

func startServer(t *testing.T, state *store.Store, socketPath string, allowed, reported adminipc.Actor, registry *target.Registry) func() {
	t.Helper()
	server, err := adminipc.NewServer(adminipc.Options{
		SocketPath:      socketPath,
		AllowedUIDs:     []uint32{allowed.UID},
		AllowedGIDs:     []uint32{allowed.GID},
		State:           state,
		Targets:         registry,
		RequestTimeout:  time.Second,
		PeerCredentials: func(*net.UnixConn) (adminipc.Actor, error) { return reported, nil },
		Clock:           time.Now,
		NewAuditID:      adminipc.NewAuditID,
	})
	if err != nil {
		t.Fatalf("create administrative server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var serveErr error
	go func() {
		serveErr = server.Serve(ctx)
		close(done)
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			select {
			case <-done:
				if serveErr != nil {
					t.Errorf("administrative server stopped with error: %v", serveErr)
				}
			case <-time.After(testTimeout):
				t.Error("administrative server did not stop before timeout")
			}
		})
	}
	t.Cleanup(stop)
	waitForSocket(t, socketPath, done, func() error { return serveErr })
	return stop
}

func waitForSocket(t *testing.T, socketPath string, done <-chan struct{}, runErr func() error) {
	t.Helper()
	timeout := time.NewTimer(testTimeout)
	defer timeout.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := os.Lstat(socketPath)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		select {
		case <-done:
			t.Fatalf("daemon stopped before socket %q became available: %v", socketPath, runErr())
		case <-timeout.C:
			t.Fatalf("socket %q did not become available: %v", socketPath, err)
		case <-ticker.C:
		}
	}
}

func assertCommandSuccess(t *testing.T, args []string, check func([]byte)) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exitCode := command.Execute(testContext(t), args, &stdout, &stderr); exitCode != command.ExitSuccess {
		t.Fatalf("command %v exit code = %d, want %d; stderr = %s", args, exitCode, command.ExitSuccess, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("command %v stderr = %q, want empty", args, stderr.String())
	}
	check(stdout.Bytes())
}

func assertCommandFailure(t *testing.T, args []string, statePath string) {
	t.Helper()
	assertDaemonCommandFailure(t, args)
	assertStateAbsent(t, statePath)
}

func assertDaemonCommandFailure(t *testing.T, args []string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exitCode := command.Execute(testContext(t), args, &stdout, &stderr); exitCode == command.ExitSuccess {
		t.Fatalf("command %v succeeded unexpectedly", args)
	}
	if stdout.Len() != 0 || !bytes.Contains(stderr.Bytes(), []byte(`"code":"daemon_unavailable"`)) {
		t.Fatalf("command %v failure output = stdout %q stderr %q", args, stdout.String(), stderr.String())
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

func assertStateAbsent(t *testing.T, statePath string) {
	t.Helper()
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state file after daemonless command error = %v, want not exist", err)
	}
}

func writeTarget(t *testing.T) string {
	t.Helper()
	document, err := json.Marshal(testTarget())
	if err != nil {
		t.Fatalf("marshal target: %v", err)
	}
	path := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	return path
}

func writeRunbook(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "runbook.md"), []byte("---\nrunbook_id: restart-checkout\nversion: 1\n---\n"), 0o600); err != nil {
		t.Fatalf("write runbook markdown: %v", err)
	}
	document := []byte(`{"schema_version":"v1","runbook_id":"restart-checkout","version":"1","adapter_type":"docker","target_constraints":[],"typed_actions":[{"action_type":"docker.container.restart","target_selector":"container:checkout","stop_timeout":"5s","cooldown":"0s"}],"risk_tier":"low","auto_execute":false,"approval_policy":{"required":false},"preconditions":[],"retry_policy":{"max_attempts":1},"stabilization_policy":{"recovery_samples":1,"window":"1m"}}`)
	if err := os.WriteFile(filepath.Join(directory, "runbook.json"), document, 0o600); err != nil {
		t.Fatalf("write runbook contract: %v", err)
	}
	return directory
}

func testTarget() contract.ServiceTarget {
	return contract.ServiceTarget{
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
		EvidencePolicy:      contract.EvidencePolicy{RedactionProfile: "strict", MaxBytes: 1024},
		StabilizationPolicy: contract.StabilizationPolicy{RecoverySamples: 2, Window: contract.NewDuration(time.Minute)},
		Enabled:             true,
	}
}

func seedIncidents(t *testing.T, statePath string) {
	t.Helper()
	state := openState(t, statePath)
	closed := false
	defer func() {
		if !closed {
			if err := state.Close(); err != nil {
				t.Errorf("close failed seeded state: %v", err)
			}
		}
	}()
	now := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	for _, value := range []contract.Incident{
		{SchemaVersion: contract.SchemaVersionV1, IncidentID: "incident-1", DedupeKey: "checkout/availability/1", TargetID: "checkout", RuleIDs: []string{"availability"}, State: contract.IncidentOpen, Severity: contract.SeverityWarning, OpenedAt: now},
		{SchemaVersion: contract.SchemaVersionV1, IncidentID: "incident-2", DedupeKey: "checkout/availability/2", TargetID: "checkout", RuleIDs: []string{"availability"}, State: contract.IncidentClosed, Severity: contract.SeverityWarning, OpenedAt: now.Add(time.Hour), TerminalAt: now.Add(2 * time.Hour)},
	} {
		document, err := json.Marshal(struct {
			SchemaVersion string            `json:"schema_version"`
			Phase         string            `json:"phase"`
			Incident      contract.Incident `json:"incident"`
			SeenInputs    []string          `json:"seen_inputs"`
		}{SchemaVersion: contract.SchemaVersionV1, Phase: "candidate", Incident: value, SeenInputs: []string{testRawEvidenceMarker}})
		if err != nil {
			t.Fatalf("marshal seeded incident: %v", err)
		}
		if err := state.Update(func(tx *store.Tx) error {
			return tx.Put(store.BucketIncidents, value.DedupeKey, document)
		}); err != nil {
			t.Fatalf("seed incident %q: %v", value.IncidentID, err)
		}
	}
	if err := state.Close(); err != nil {
		t.Fatalf("close seeded state: %v", err)
	}
	closed = true
}

func openState(t *testing.T, statePath string) *store.Store {
	t.Helper()
	state, err := store.Open(store.Options{Path: statePath, LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	return state
}

func assertPersistedRegistrations(t *testing.T, statePath string) {
	t.Helper()
	state := openState(t, statePath)
	defer func() {
		if err := state.Close(); err != nil {
			t.Errorf("close inspected state: %v", err)
		}
	}()
	if err := state.View(func(tx *store.Tx) error {
		if _, found, err := tx.Get(store.BucketServiceTargets, "checkout"); err != nil || !found {
			t.Errorf("persisted target found=%t error=%v", found, err)
		}
		if _, found, err := tx.Get(store.BucketRunbooks, "restart-checkout"); err != nil || !found {
			t.Errorf("persisted runbook found=%t error=%v", found, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect persisted registrations: %v", err)
	}
}

func assertAuditedOperations(t *testing.T, statePath string) {
	t.Helper()
	state := openState(t, statePath)
	defer func() {
		if err := state.Close(); err != nil {
			t.Errorf("close audited state: %v", err)
		}
	}()
	actions := map[string]bool{}
	if err := state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketAudit, func(_ string, document []byte) error {
			var event contract.AuditEvent
			if err := json.Unmarshal(document, &event); err != nil {
				return err
			}
			if event.Result == "accepted" {
				actions[event.Action] = true
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("read administrative audits: %v", err)
	}
	for _, action := range []string{"admin.status", "admin.backup", "target.register", "runbook.register", "incident.list", "incident.show"} {
		if !actions[action] {
			t.Errorf("accepted audit actions = %#v, want %q", actions, action)
		}
	}
}

func assertRejectedAudits(t *testing.T, state *store.Store) {
	t.Helper()
	var events []contract.AuditEvent
	if err := state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketAudit, func(_ string, document []byte) error {
			var event contract.AuditEvent
			if err := json.Unmarshal(document, &event); err != nil {
				return err
			}
			events = append(events, event)
			return nil
		})
	}); err != nil {
		t.Fatalf("read rejection audits: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("rejection audit count = %d, want 2", len(events))
	}
	reasons := map[string]bool{}
	for _, event := range events {
		if event.Result != "rejected" {
			t.Errorf("rejection audit result = %q, want rejected", event.Result)
		}
		reasons[event.ReasonCode] = true
	}
	if !reasons["peer_unauthorized"] || !reasons["malformed_request"] {
		t.Errorf("rejection audit reasons = %#v, want unauthorized and malformed", reasons)
	}
}
