package adminipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
	"pulse-agent/internal/target"
)

var authorizedTestActor = Actor{UID: 1000, GID: 1000}

var errTestWrite = errors.New("test write failure")

func TestClient_UsesInjectedRequestID(t *testing.T) {
	state := openTestStore(t)
	_, socketPath, stop := startTestServer(t, state, time.Second, func(*net.UnixConn) (Actor, error) {
		return authorizedTestActor, nil
	})
	clock := time.Now()
	client, err := NewClient(ClientOptions{
		RequestTimeout: time.Second,
		Clock:          func() time.Time { return clock },
		NewRequestID: func() (string, error) {
			return "request-test-fixed", nil
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if _, err := client.Status(context.Background(), socketPath, "operator_status"); err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	events := readAuditEvents(t, state)
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	if events[0].AggregateID != "request-request-test-fixed" {
		t.Errorf("audit aggregate ID = %q, want injected request ID", events[0].AggregateID)
	}
	stop()
}

func TestServer_UsesInjectedClockAndAuditID(t *testing.T) {
	state := openTestStore(t)
	clock := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	server, err := NewServer(Options{
		SocketPath:      filepath.Join(t.TempDir(), "admin.sock"),
		AllowedUIDs:     []uint32{authorizedTestActor.UID},
		AllowedGIDs:     []uint32{authorizedTestActor.GID},
		State:           state,
		RequestTimeout:  time.Second,
		PeerCredentials: func(*net.UnixConn) (Actor, error) { return authorizedTestActor, nil },
		Clock:           func() time.Time { return clock },
		NewAuditID: func() (string, error) {
			return "admin-test-fixed", nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	var destination bytes.Buffer
	err = server.route(&destination, authorizedTestActor, Request{
		SchemaVersion: SchemaVersion,
		RequestID:     "request-test-fixed",
		Operation:     OperationStatus,
		ReasonCode:    "operator_status",
	})
	if err != nil {
		t.Fatalf("route() error = %v", err)
	}
	events := readAuditEvents(t, state)
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	if events[0].EventID != "admin-test-fixed" || !events[0].OccurredAt.Equal(clock) {
		t.Errorf("audit event = %#v, want injected ID and clock", events[0])
	}
}

func TestServer_RoutePropagatesStatusAndBackupWriteFailures(t *testing.T) {
	state := openTestStore(t)
	server := newTestServer(t, state, testSocketPath(t), time.Second, func(*net.UnixConn) (Actor, error) {
		return authorizedTestActor, nil
	})
	for _, request := range []Request{
		{
			SchemaVersion: SchemaVersion,
			RequestID:     "request-status-write-failure",
			Operation:     OperationStatus,
			ReasonCode:    "operator_status",
		},
		{
			SchemaVersion: SchemaVersion,
			RequestID:     "request-backup-write-failure",
			Operation:     OperationBackup,
			ReasonCode:    "routine_backup",
		},
	} {
		if err := server.route(failingWriter{}, authorizedTestActor, request); !errors.Is(err, errTestWrite) {
			t.Errorf("route(%s) error = %v, want %v", request.Operation, err, errTestWrite)
		}
	}
	events := readAuditEvents(t, state)
	if len(events) != 2 {
		t.Fatalf("audit event count = %d, want 2", len(events))
	}
	assertAuditEvent(t, events[0], auditActionStatus, auditResultAccepted, "operator_status")
	assertAuditEvent(t, events[1], auditActionBackup, auditResultAccepted, "routine_backup")
}

func TestServer_StatusAndBackupAuditAuthenticatedActor(t *testing.T) {
	state := openTestStore(t)
	server, socketPath, stop := startTestServer(t, state, time.Second, func(*net.UnixConn) (Actor, error) {
		return authorizedTestActor, nil
	})
	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatalf("Lstat() daemon socket: %v", err)
	}
	if info.Mode().Perm()&^socketMode != 0 {
		t.Errorf("socket mode = %#o, want no bits outside %#o", info.Mode().Perm(), socketMode)
	}
	if !server.socketIsCurrent() {
		t.Fatal("daemon socket did not retain its expected owner, group, and inode")
	}
	client := newTestClient(t, time.Second)

	status, err := client.Status(context.Background(), socketPath, "operator_status")
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.State != StatusRunning {
		t.Errorf("status state = %q, want %q", status.State, StatusRunning)
	}
	if len(status.Capabilities) != 1 || status.Capabilities[0] != statusCapabilityAdminIPC {
		t.Errorf("status capabilities = %#v, want admin IPC capability", status.Capabilities)
	}

	var snapshot bytes.Buffer
	if err := client.Backup(context.Background(), socketPath, "routine_backup", &snapshot); err != nil {
		t.Fatalf("Backup() error = %v", err)
	}
	if snapshot.Len() == 0 {
		t.Fatal("Backup() returned an empty snapshot")
	}
	var expected bytes.Buffer
	if err := state.Backup(&expected); err != nil {
		t.Fatalf("Store.Backup() error = %v", err)
	}
	if !bytes.Equal(snapshot.Bytes(), expected.Bytes()) {
		t.Fatal("Backup() did not return the daemon-owned state snapshot")
	}

	events := readAuditEvents(t, state)
	if len(events) != 2 {
		t.Fatalf("audit event count = %d, want 2", len(events))
	}
	assertAuditEvent(t, events[0], auditActionStatus, auditResultAccepted, "operator_status")
	assertAuditEvent(t, events[1], auditActionBackup, auditResultAccepted, "routine_backup")
	for _, event := range events {
		if event.ActorIdentity != authorizedTestActor.Identity() {
			t.Errorf("audit actor identity = %q, want %q", event.ActorIdentity, authorizedTestActor.Identity())
		}
	}

	stop()
}

func TestServer_RejectsUnauthorizedPeerAndAuditsRejection(t *testing.T) {
	state := openTestStore(t)
	unauthorized := Actor{UID: authorizedTestActor.UID + 1, GID: authorizedTestActor.GID}
	_, socketPath, stop := startTestServer(t, state, time.Second, func(*net.UnixConn) (Actor, error) {
		return unauthorized, nil
	})
	client := newTestClient(t, time.Second)

	_, err := client.Status(context.Background(), socketPath, "operator_status")
	if !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("Status() error = %v, want %v", err, ErrRequestRejected)
	}

	events := readAuditEvents(t, state)
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	assertAuditEvent(t, events[0], auditActionRequest, auditResultRejected, auditReasonUnauthorized)
	if events[0].ActorIdentity != unauthorized.Identity() {
		t.Errorf("audit actor identity = %q, want %q", events[0].ActorIdentity, unauthorized.Identity())
	}

	stop()
}

func TestServer_RejectsMalformedRequestBeforeRouting(t *testing.T) {
	state := openTestStore(t)
	_, socketPath, stop := startTestServer(t, state, time.Second, func(*net.UnixConn) (Actor, error) {
		return authorizedTestActor, nil
	})
	connection := dialTestSocket(t, socketPath)

	if _, err := io.WriteString(connection, `{"schema_version":"v1","request_id":"request-1","operation":"status","reason_code":"operator_status","unexpected":true}`+"\n"); err != nil {
		t.Fatalf("write malformed request: %v", err)
	}
	response := readTestResponse(t, connection)
	if response.Result != resultFailure || response.ErrorCode != errorMalformedRequest {
		t.Errorf("malformed response = %#v, want malformed request failure", response)
	}

	events := readAuditEvents(t, state)
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	assertAuditEvent(t, events[0], auditActionRequest, auditResultRejected, auditReasonMalformed)

	stop()
}

func TestServer_TargetRegisterUsesDaemonRegistryAndAuditsActor(t *testing.T) {
	state := openTestStore(t)
	registry := newTestTargetRegistry(t, state)
	_, socketPath, stop := startTestServer(t, state, time.Second, func(*net.UnixConn) (Actor, error) {
		return authorizedTestActor, nil
	}, registry)
	client := newTestClient(t, time.Second)

	result, err := client.Register(context.Background(), socketPath, "onboarding", testServiceTarget())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if result.Version != 1 || result.TargetID != "checkout" {
		t.Fatalf("Register() result = %#v, want registered checkout target", result)
	}
	if persisted := registry.Snapshot(); persisted.Version != 1 || len(persisted.Targets) != 1 {
		t.Fatalf("registry snapshot = %#v, want daemon-persisted target", persisted)
	}

	events := readAuditEvents(t, state)
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	assertAuditEvent(t, events[0], "target.register", "accepted", "onboarding")
	if events[0].ActorIdentity != authorizedTestActor.Identity() {
		t.Errorf("audit actor identity = %q, want %q", events[0].ActorIdentity, authorizedTestActor.Identity())
	}
	stop()
}

func TestServer_TargetRegisterRejectsUnauthorizedPeer(t *testing.T) {
	state := openTestStore(t)
	registry := newTestTargetRegistry(t, state)
	unauthorized := Actor{UID: authorizedTestActor.UID + 1, GID: authorizedTestActor.GID}
	_, socketPath, stop := startTestServer(t, state, time.Second, func(*net.UnixConn) (Actor, error) {
		return unauthorized, nil
	}, registry)
	client := newTestClient(t, time.Second)

	_, err := client.Register(context.Background(), socketPath, "onboarding", testServiceTarget())
	if !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("Register() error = %v, want %v", err, ErrRequestRejected)
	}
	if snapshot := registry.Snapshot(); len(snapshot.Targets) != 0 {
		t.Fatalf("unauthorized request changed target registry: %#v", snapshot)
	}
	events := readAuditEvents(t, state)
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	assertAuditEvent(t, events[0], auditActionRequest, auditResultRejected, auditReasonUnauthorized)
	stop()
}

func TestClient_RejectsAbsentAndSymlinkSocket(t *testing.T) {
	client := newTestClient(t, time.Second)
	socketPath := filepath.Join(t.TempDir(), "admin.sock")

	_, err := client.Status(context.Background(), socketPath, "operator_status")
	if !errors.Is(err, ErrDaemonUnavailable) {
		t.Fatalf("Status() absent socket error = %v, want %v", err, ErrDaemonUnavailable)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), socketPath); err != nil {
		t.Fatalf("create socket symlink: %v", err)
	}
	_, err = client.Status(context.Background(), socketPath, "operator_status")
	if !errors.Is(err, ErrInsecureSocket) {
		t.Fatalf("Status() symlink error = %v, want %v", err, ErrInsecureSocket)
	}
}

func TestServer_RefusesExistingPathAndPreservesIt(t *testing.T) {
	state := openTestStore(t)
	socketPath := filepath.Join(t.TempDir(), "admin.sock")
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), socketPath); err != nil {
		t.Fatalf("create socket symlink: %v", err)
	}
	server := newTestServer(t, state, socketPath, time.Second, func(*net.UnixConn) (Actor, error) {
		return authorizedTestActor, nil
	})

	err := server.Serve(context.Background())
	if !errors.Is(err, ErrSocketPathExists) {
		t.Fatalf("Serve() error = %v, want %v", err, ErrSocketPathExists)
	}
	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatalf("Lstat() after refused startup: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("Serve() replaced the existing symlink")
	}
}

func TestServer_PreservesReplacementDuringShutdown(t *testing.T) {
	state := openTestStore(t)
	server, socketPath, stop := startTestServer(t, state, time.Second, func(*net.UnixConn) (Actor, error) {
		return authorizedTestActor, nil
	})
	if err := os.Remove(socketPath); err != nil {
		t.Fatalf("remove daemon socket for replacement test: %v", err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "replacement"), socketPath); err != nil {
		t.Fatalf("replace socket with symlink: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	stop()

	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatalf("Lstat() replacement after shutdown: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("Close() removed the replacement path")
	}
}

func TestServer_HandlesConcurrentRequestsAndGracefulShutdown(t *testing.T) {
	state := openTestStore(t)
	_, socketPath, stop := startTestServer(t, state, time.Second, func(*net.UnixConn) (Actor, error) {
		return authorizedTestActor, nil
	})
	client := newTestClient(t, time.Second)

	const requestCount = 24
	errorsByRequest := make(chan error, requestCount)
	var requests sync.WaitGroup
	for range requestCount {
		requests.Add(1)
		go func() {
			defer requests.Done()
			_, err := client.Status(context.Background(), socketPath, "parallel_status")
			errorsByRequest <- err
		}()
	}
	requests.Wait()
	close(errorsByRequest)
	for err := range errorsByRequest {
		if err != nil {
			t.Errorf("concurrent Status() error = %v", err)
		}
	}

	events := readAuditEvents(t, state)
	if len(events) != requestCount {
		t.Fatalf("audit event count = %d, want %d", len(events), requestCount)
	}
	stop()
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket after graceful shutdown error = %v, want not exist", err)
	}
}

func TestServer_TimeoutAndCancellationCloseIncompleteConnections(t *testing.T) {
	state := openTestStore(t)
	accepted := make(chan struct{}, 2)
	_, socketPath, stop := startTestServer(t, state, 25*time.Millisecond, func(*net.UnixConn) (Actor, error) {
		accepted <- struct{}{}
		return authorizedTestActor, nil
	})

	timeoutConnection := dialTestSocket(t, socketPath)
	awaitSignal(t, accepted, "server did not accept timeout connection")
	if err := timeoutConnection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set timeout connection read deadline: %v", err)
	}
	var oneByte [1]byte
	if _, err := timeoutConnection.Read(oneByte[:]); err == nil {
		t.Fatal("incomplete request stayed open after server timeout")
	}

	cancelConnection := dialTestSocket(t, socketPath)
	awaitSignal(t, accepted, "server did not accept cancellation connection")
	if err := cancelConnection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set cancellation connection read deadline: %v", err)
	}
	stop()
	if _, err := cancelConnection.Read(oneByte[:]); err == nil {
		t.Fatal("incomplete request stayed open after graceful shutdown")
	}
}

func TestClient_ContextCancellationClosesPendingRequest(t *testing.T) {
	state := openTestStore(t)
	credentialsStarted := make(chan struct{}, 1)
	releaseCredentials := make(chan struct{})
	_, socketPath, stop := startTestServer(t, state, time.Second, func(*net.UnixConn) (Actor, error) {
		credentialsStarted <- struct{}{}
		<-releaseCredentials
		return authorizedTestActor, nil
	})
	client := newTestClient(t, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := client.Status(ctx, socketPath, "operator_status")
		result <- err
	}()

	awaitSignal(t, credentialsStarted, "server did not begin the pending request")
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Status() cancellation error = %v, want %v", err, context.Canceled)
		}
	case <-time.After(time.Second):
		t.Fatal("Status() did not return after context cancellation")
	}
	close(releaseCredentials)
	stop()
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	state, err := store.Open(store.Options{
		Path:        filepath.Join(t.TempDir(), "state.db"),
		LockTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Errorf("Store.Close() error = %v", err)
		}
	})
	return state
}

func startTestServer(t *testing.T, state *store.Store, timeout time.Duration, credentials PeerCredentials, registries ...*target.Registry) (*Server, string, func()) {
	t.Helper()
	socketPath := testSocketPath(t)
	var registry *target.Registry
	if len(registries) == 1 {
		registry = registries[0]
	}
	server := newTestServerWithTargets(t, state, socketPath, timeout, credentials, registry)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- server.Serve(ctx)
	}()
	waitForSocket(t, server, socketPath, result)

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			select {
			case err := <-result:
				if err != nil {
					t.Errorf("Server.Serve() error = %v", err)
				}
			case <-time.After(time.Second):
				t.Error("Server.Serve() did not stop")
			}
		})
	}
	t.Cleanup(stop)
	return server, socketPath, stop
}

func testSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/private/tmp", "pulse-agent-ipc-")
	if err != nil {
		t.Fatalf("create short socket directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove short socket directory: %v", err)
		}
	})
	return filepath.Join(directory, "admin.sock")
}

func newTestServer(t *testing.T, state *store.Store, socketPath string, timeout time.Duration, credentials PeerCredentials) *Server {
	return newTestServerWithTargets(t, state, socketPath, timeout, credentials, nil)
}

func newTestServerWithTargets(t *testing.T, state *store.Store, socketPath string, timeout time.Duration, credentials PeerCredentials, registry *target.Registry) *Server {
	t.Helper()
	clock := time.Now()
	server, err := NewServer(Options{
		SocketPath:      socketPath,
		AllowedUIDs:     []uint32{authorizedTestActor.UID},
		AllowedGIDs:     []uint32{authorizedTestActor.GID},
		State:           state,
		Targets:         registry,
		RequestTimeout:  timeout,
		PeerCredentials: credentials,
		Clock:           func() time.Time { return clock },
		NewAuditID:      newTestIDGenerator("admin-test"),
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	return server
}

func newTestTargetRegistry(t *testing.T, state *store.Store) *target.Registry {
	t.Helper()
	registry, err := target.NewRegistry(target.Options{
		State: state,
		AllowedTargets: []target.AllowedTarget{{
			TargetID:    "checkout",
			AdapterType: "docker",
		}},
		MaxTargets:       2,
		MaxEvidenceBytes: 1024,
		Clock:            time.Now,
		NewAuditEventID:  target.NewAuditEventID,
	})
	if err != nil {
		t.Fatalf("target.NewRegistry() error = %v", err)
	}
	return registry
}

func testServiceTarget() contract.ServiceTarget {
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
		EvidencePolicy: contract.EvidencePolicy{RedactionProfile: "strict", MaxBytes: 1024},
		StabilizationPolicy: contract.StabilizationPolicy{
			RecoverySamples: 2,
			Window:          contract.NewDuration(time.Minute),
		},
		Enabled: true,
	}
}

func waitForSocket(t *testing.T, server *Server, socketPath string, result <-chan error) {
	t.Helper()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := os.Lstat(socketPath)
		if err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm()&^socketMode == 0 && server.socketIsCurrent() {
			return
		}
		select {
		case err := <-result:
			t.Fatalf("server stopped before socket became available: %v", err)
		case <-timeout.C:
			t.Fatalf("socket %q did not become available; Lstat error = %v", socketPath, err)
		case <-ticker.C:
		}
	}
}

func dialTestSocket(t *testing.T, socketPath string) *net.UnixConn {
	t.Helper()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("DialUnix(%q) error = %v", socketPath, err)
	}
	t.Cleanup(func() {
		if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("UnixConn.Close() error = %v", err)
		}
	})
	return connection
}

func newTestClient(t *testing.T, timeout time.Duration) *Client {
	t.Helper()
	clock := time.Now()
	client, err := NewClient(ClientOptions{
		RequestTimeout: timeout,
		Clock:          func() time.Time { return clock },
		NewRequestID:   newTestIDGenerator("request-test"),
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return client
}

func newTestIDGenerator(prefix string) func() (string, error) {
	var mu sync.Mutex
	sequence := 0
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		sequence++
		return fmt.Sprintf("%s-%d", prefix, sequence), nil
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errTestWrite
}

func readTestResponse(t *testing.T, connection *net.UnixConn) response {
	t.Helper()
	document, err := readMessage(bufioReader(connection))
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	decoded, err := decodeResponse(document)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return decoded
}

func readAuditEvents(t *testing.T, state *store.Store) []contract.AuditEvent {
	t.Helper()
	var events []contract.AuditEvent
	err := state.View(func(transaction *store.Tx) error {
		return transaction.ForEach(store.BucketAudit, func(_ string, document []byte) error {
			var event contract.AuditEvent
			if err := json.Unmarshal(document, &event); err != nil {
				return err
			}
			events = append(events, event)
			return nil
		})
	})
	if err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	return events
}

func assertAuditEvent(t *testing.T, event contract.AuditEvent, action, outcome, reason string) {
	t.Helper()
	if event.Action != action || event.Result != outcome || event.ReasonCode != reason {
		t.Errorf("audit event = action %q, result %q, reason %q; want action %q, result %q, reason %q", event.Action, event.Result, event.ReasonCode, action, outcome, reason)
	}
}

func awaitSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}
