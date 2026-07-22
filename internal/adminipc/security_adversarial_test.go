package adminipc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	adminPeerAuthorizationCorpusSize   = 8
	adminSocketAuthorizationCorpusSize = 4
	adminAuthorizationCorpusSize       = adminPeerAuthorizationCorpusSize + adminSocketAuthorizationCorpusSize
)

func TestServer_UnauthorizedPeerCorpusAuditsBeforeTargetMutation(t *testing.T) {
	maximumID := ^uint32(0)
	tests := []struct {
		name  string
		actor Actor
	}{
		{name: "UID mismatch", actor: Actor{UID: authorizedTestActor.UID + 1, GID: authorizedTestActor.GID}},
		{name: "GID mismatch", actor: Actor{UID: authorizedTestActor.UID, GID: authorizedTestActor.GID + 1}},
		{name: "UID and GID mismatch", actor: Actor{UID: authorizedTestActor.UID + 1, GID: authorizedTestActor.GID + 1}},
		{name: "zero UID", actor: Actor{UID: 0, GID: authorizedTestActor.GID}},
		{name: "zero GID", actor: Actor{UID: authorizedTestActor.UID, GID: 0}},
		{name: "maximum UID", actor: Actor{UID: maximumID, GID: authorizedTestActor.GID}},
		{name: "maximum GID", actor: Actor{UID: authorizedTestActor.UID, GID: maximumID}},
		{name: "maximum UID and GID", actor: Actor{UID: maximumID, GID: maximumID}},
	}
	if got := len(tests); got != adminPeerAuthorizationCorpusSize {
		t.Fatalf("admin peer authorization corpus size = %d, want %d", got, adminPeerAuthorizationCorpusSize)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := openTestStore(t)
			registry := newTestTargetRegistry(t, state)
			_, socketPath, stop := startTestServer(t, state, time.Second, func(*net.UnixConn) (Actor, error) {
				return test.actor, nil
			}, registry)

			_, err := newTestClient(t, time.Second).Register(context.Background(), socketPath, "security_test", testServiceTarget())
			if !errors.Is(err, ErrRequestRejected) {
				t.Fatalf("Register() error = %v, want %v", err, ErrRequestRejected)
			}
			if snapshot := registry.Snapshot(); snapshot.Version != 0 || len(snapshot.Targets) != 0 {
				t.Fatalf("unauthorized peer changed target registry: %#v", snapshot)
			}
			events := readAuditEvents(t, state)
			if len(events) != 1 {
				t.Fatalf("audit event count = %d, want 1", len(events))
			}
			assertAuditEvent(t, events[0], auditActionRequest, auditResultRejected, auditReasonUnauthorized)
			if events[0].ActorIdentity != test.actor.Identity() {
				t.Fatalf("audit actor = %q, want %q", events[0].ActorIdentity, test.actor.Identity())
			}
			stop()
		})
	}
}

func TestServer_SocketIntegrityCorpusPreservesUnownedPaths(t *testing.T) {
	tests := []struct {
		name     string
		exercise func(*testing.T) error
		want     error
	}{
		{name: "startup symlink", exercise: exerciseStartupSocketObject(os.ModeSymlink), want: ErrSocketPathExists},
		{name: "startup regular file", exercise: exerciseStartupSocketObject(0), want: ErrSocketPathExists},
		{name: "runtime symlink replacement", exercise: exerciseRuntimeSocketReplacement(os.ModeSymlink), want: ErrInsecureSocket},
		{name: "runtime regular replacement", exercise: exerciseRuntimeSocketReplacement(0), want: ErrInsecureSocket},
	}
	if got := len(tests); got != adminSocketAuthorizationCorpusSize || adminAuthorizationCorpusSize != 12 {
		t.Fatalf("admin socket authorization corpus size = %d, total = %d; want %d and 12", got, adminAuthorizationCorpusSize, adminSocketAuthorizationCorpusSize)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.exercise(t); !errors.Is(err, test.want) {
				t.Fatalf("socket boundary error = %v, want errors.Is(_, %v)", err, test.want)
			}
		})
	}
}

func exerciseStartupSocketObject(mode os.FileMode) func(*testing.T) error {
	return func(t *testing.T) error {
		t.Helper()
		state := openTestStore(t)
		socketPath := filepath.Join(t.TempDir(), "admin.sock")
		if mode&os.ModeSymlink != 0 {
			if err := os.Symlink(filepath.Join(t.TempDir(), "target"), socketPath); err != nil {
				t.Fatalf("create socket symlink: %v", err)
			}
		} else if err := os.WriteFile(socketPath, []byte("preserve"), 0o600); err != nil {
			t.Fatalf("create socket file: %v", err)
		}
		server := newTestServer(t, state, socketPath, time.Second, func(*net.UnixConn) (Actor, error) {
			return authorizedTestActor, nil
		})
		err := server.Serve(context.Background())
		assertPreservedSocketObject(t, socketPath, mode)
		return err
	}
}

func exerciseRuntimeSocketReplacement(mode os.FileMode) func(*testing.T) error {
	return func(t *testing.T) error {
		t.Helper()
		state := openTestStore(t)
		server, socketPath, stop := startTestServer(t, state, time.Second, func(*net.UnixConn) (Actor, error) {
			return authorizedTestActor, nil
		})
		if err := os.Remove(socketPath); err != nil {
			t.Fatalf("remove daemon socket: %v", err)
		}
		if mode&os.ModeSymlink != 0 {
			if err := os.Symlink(filepath.Join(t.TempDir(), "replacement"), socketPath); err != nil {
				t.Fatalf("replace socket with symlink: %v", err)
			}
		} else if err := os.WriteFile(socketPath, []byte("replacement"), 0o600); err != nil {
			t.Fatalf("replace socket with file: %v", err)
		}
		_, requestErr := newTestClient(t, time.Second).Status(context.Background(), socketPath, "security_test")
		if err := server.Close(); err != nil {
			t.Fatalf("Server.Close() error = %v", err)
		}
		stop()
		assertPreservedSocketObject(t, socketPath, mode)
		return requestErr
	}
}

func assertPreservedSocketObject(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(preserved socket object): %v", err)
	}
	if mode&os.ModeSymlink != 0 {
		if info.Mode()&os.ModeSymlink == 0 {
			t.Fatal("socket boundary replaced or removed the symlink")
		}
		return
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("preserved socket object mode = %v, want regular file", info.Mode())
	}
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read preserved socket file: %v", err)
	}
	if string(document) != "preserve" && string(document) != "replacement" {
		t.Fatalf("preserved socket file = %q", document)
	}
}
