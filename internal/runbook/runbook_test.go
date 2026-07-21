package runbook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pulse-agent/internal/store"
)

func TestLoad_ValidatesMatchingMetadataAndCanonicalDigest(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "runbook.md"), validMarkdown(), 0o600); err != nil {
		t.Fatalf("write markdown: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "runbook.json"), validDocument(), 0o600); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	pair, err := Load(directory)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if pair.Runbook.RunbookID != "restart-checkout" || pair.Digest == "" || pair.Runbook.Digest != pair.Digest {
		t.Errorf("pair = %#v, want matching runbook and derived digest", pair)
	}
}

func TestDecode_RejectsUnsafeFieldsAndMismatchedMarkdown(t *testing.T) {
	markdown := validMarkdown()
	for _, field := range []string{"command", "argv", "shell", "script", "exec"} {
		document := []byte(strings.TrimSuffix(string(validDocument()), "}") + `,"` + field + `":"untrusted"}`)
		if _, err := Decode(markdown, document); !errors.Is(err, ErrInvalidPair) {
			t.Errorf("Decode(%s) error = %v, want %v", field, err, ErrInvalidPair)
		}
	}
	for name, document := range map[string][]byte{
		"path traversal":     []byte(strings.Replace(string(validDocument()), "container:checkout", "container:../checkout", 1)),
		"unsupported action": []byte(strings.Replace(string(validDocument()), "docker.container.restart", "docker.container.exec", 1)),
	} {
		if _, err := Decode(markdown, document); !errors.Is(err, ErrInvalidPair) {
			t.Errorf("Decode(%s) error = %v, want %v", name, err, ErrInvalidPair)
		}
	}
	if _, err := Decode([]byte("---\nrunbook_id: other\nversion: 1\n---\n"), validDocument()); !errors.Is(err, ErrInvalidPair) {
		t.Fatalf("Decode(mismatched markdown) error = %v, want %v", err, ErrInvalidPair)
	}
	if _, err := Decode([]byte("runbook_id: restart-checkout\nversion: 1\n"), validDocument()); !errors.Is(err, ErrInvalidPair) {
		t.Fatalf("Decode(metadata outside front matter) error = %v, want %v", err, ErrInvalidPair)
	}
}

func TestLoad_RejectsSymlinkMember(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "runbook.md"), validMarkdown(), 0o600); err != nil {
		t.Fatalf("write markdown: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "runbook.json")
	if err := os.WriteFile(outside, validDocument(), 0o600); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "runbook.json")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := Load(directory); !errors.Is(err, ErrInvalidPair) {
		t.Fatalf("Load(symlink) error = %v, want %v", err, ErrInvalidPair)
	}
}

func TestRegistry_RegisterPersistsAndAuditsDuplicate(t *testing.T) {
	state, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db"), LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Errorf("Store.Close() error = %v", err)
		}
	})
	next := 0
	registry, err := NewRegistry(Options{State: state, Clock: func() time.Time { return time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC) }, NewAuditEventID: func() (string, error) { next++; return fmt.Sprintf("runbook-test-%d", next), nil }})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	pair, err := Decode(validMarkdown(), validDocument())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	registration := Registration{Pair: pair, ActorIdentity: "uid:1000/gid:1000", RequestID: "request-1", ReasonCode: "operator_requested"}
	result, err := registry.Register(registration)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if result.RunbookID != pair.Runbook.RunbookID || result.Digest != pair.Digest {
		t.Errorf("result = %#v, want persisted runbook result", result)
	}
	if _, err := registry.Register(registration); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate Register() error = %v, want %v", err, ErrDuplicate)
	}
	var audits int
	err = state.View(func(tx *store.Tx) error {
		if _, found, err := tx.Get(store.BucketRunbooks, pair.Runbook.RunbookID); err != nil || !found {
			t.Errorf("persisted runbook found=%v err=%v", found, err)
		}
		return tx.ForEach(store.BucketAudit, func(_ string, document []byte) error {
			var value map[string]any
			if err := json.Unmarshal(document, &value); err != nil {
				return err
			}
			audits++
			return nil
		})
	})
	if err != nil {
		t.Fatalf("state.View() error = %v", err)
	}
	if audits != 2 {
		t.Errorf("audit count = %d, want 2", audits)
	}
}

func TestRegistry_RegisterRollsBackWhenAuditAppendCannotStart(t *testing.T) {
	state, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db"), LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Errorf("Store.Close() error = %v", err)
		}
	})
	registry, err := NewRegistry(Options{State: state, Clock: time.Now, NewAuditEventID: func() (string, error) { return "", errors.New("entropy unavailable") }})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	pair, err := Decode(validMarkdown(), validDocument())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if _, err := registry.Register(Registration{Pair: pair, ActorIdentity: "uid:1000/gid:1000", RequestID: "request-1", ReasonCode: "operator_requested"}); err == nil {
		t.Fatal("Register() succeeded after audit ID failure")
	}
	err = state.View(func(tx *store.Tx) error {
		if _, found, err := tx.Get(store.BucketRunbooks, pair.Runbook.RunbookID); err != nil || found {
			t.Errorf("runbook after rollback found=%v err=%v", found, err)
		}
		return tx.ForEach(store.BucketAudit, func(string, []byte) error { t.Error("audit event persisted after rollback"); return nil })
	})
	if err != nil {
		t.Fatalf("state.View() error = %v", err)
	}
}

func validDocument() []byte {
	return []byte(`{"schema_version":"v1","runbook_id":"restart-checkout","version":"1","adapter_type":"docker","target_constraints":[],"typed_actions":[{"action_type":"docker.container.restart","target_selector":"container:checkout","stop_timeout":"5s","cooldown":"0s"}],"risk_tier":"low","auto_execute":false,"approval_policy":{"required":false},"preconditions":[],"retry_policy":{"max_attempts":1},"stabilization_policy":{"recovery_samples":1,"window":"1m"}}`)
}

func validMarkdown() []byte {
	return []byte("---\nrunbook_id: restart-checkout\nversion: 1\n---\n")
}
