package target

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
)

func TestRegistry_RegisterAuditsAndReturnsImmutableSnapshot(t *testing.T) {
	state := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	registry := newTestRegistry(t, state, func() time.Time {
		return time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	}, nil)

	snapshot, err := registry.Register(testRegistration(testTarget()))
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if snapshot.SchemaVersion != SchemaVersion || snapshot.Version != 1 || len(snapshot.Targets) != 1 {
		t.Fatalf("Register() snapshot = %#v, want one versioned target", snapshot)
	}
	snapshot.Targets[0].TargetID = "changed"
	snapshot.Targets[0].ProbeRules[0].RuleID = "changed"

	fresh := registry.Snapshot()
	if fresh.Targets[0].TargetID != "checkout" || fresh.Targets[0].ProbeRules[0].RuleID != "availability" {
		t.Fatalf("Snapshot() exposed mutable registry state: %#v", fresh)
	}

	var events []contract.AuditEvent
	if err := state.View(func(transaction *store.Tx) error {
		return transaction.ForEach(store.BucketAudit, func(_ string, document []byte) error {
			var event contract.AuditEvent
			if err := json.Unmarshal(document, &event); err != nil {
				return err
			}
			events = append(events, event)
			return nil
		})
	}); err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	event := events[0]
	if event.AggregateType != auditAggregateType || event.AggregateID != "checkout" || event.ActorIdentity != "uid:1000/gid:1000" || event.Action != auditAction || event.Result != auditResultAccepted || event.ReasonCode != "onboarding" {
		t.Errorf("audit event = %#v, want accepted target registration", event)
	}
}

func TestRegistry_RejectsInvalidTargetsBeforePersistence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*contract.ServiceTarget)
		want   error
	}{
		{name: "unknown adapter", mutate: func(value *contract.ServiceTarget) { value.AdapterType = "unsupported" }, want: ErrUnknownAdapter},
		{name: "selector traversal", mutate: func(value *contract.ServiceTarget) { value.Selector = "container:../escape" }, want: ErrInvalidTarget},
		{name: "invalid probe timeout", mutate: func(value *contract.ServiceTarget) { value.ProbeRules[0].Timeout = 0 }, want: ErrInvalidTarget},
		{name: "unbounded evidence", mutate: func(value *contract.ServiceTarget) { value.EvidencePolicy.MaxBytes = 1025 }, want: ErrInvalidTarget},
		{name: "invalid stabilization", mutate: func(value *contract.ServiceTarget) { value.StabilizationPolicy.Window = 0 }, want: ErrInvalidTarget},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
			registry := newTestRegistry(t, state, time.Now, nil)
			candidate := testTarget()
			tt.mutate(&candidate)

			_, err := registry.Register(testRegistration(candidate))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Register() error = %v, want errors.Is(_, %v)", err, tt.want)
			}
			if snapshot := registry.Snapshot(); len(snapshot.Targets) != 0 || snapshot.Version != 0 {
				t.Fatalf("invalid target persisted in snapshot: %#v", snapshot)
			}
			if err := state.View(func(transaction *store.Tx) error {
				_, found, err := transaction.Get(store.BucketServiceTargets, "checkout")
				if err != nil || found {
					t.Fatalf("persisted invalid target = found %t, error %v", found, err)
				}
				return nil
			}); err != nil {
				t.Fatalf("verify target absence: %v", err)
			}
		})
	}
}

func TestRegistry_ConcurrentDuplicateRegistrationAuditsOnlyOneTarget(t *testing.T) {
	state := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	registry := newTestRegistry(t, state, time.Now, nil)

	const registrations = 24
	results := make(chan error, registrations)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range registrations {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := registry.Register(testRegistration(testTarget()))
			results <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	successes := 0
	duplicates := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrDuplicateTarget):
			duplicates++
		default:
			t.Errorf("concurrent Register() error = %v", err)
		}
	}
	if successes != 1 || duplicates != registrations-1 {
		t.Fatalf("registration results = %d success, %d duplicates; want 1 and %d", successes, duplicates, registrations-1)
	}
	if snapshot := registry.Snapshot(); snapshot.Version != 1 || len(snapshot.Targets) != 1 {
		t.Fatalf("snapshot after concurrent registration = %#v, want one target", snapshot)
	}
}

func TestRegistry_RecoversPersistedSnapshotAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	state, err := store.Open(store.Options{Path: path, LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("open source store: %v", err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			if err := state.Close(); err != nil {
				t.Errorf("close source store: %v", err)
			}
		}
	})
	registry := newTestRegistry(t, state, time.Now, nil)
	if _, err := registry.Register(testRegistration(testTarget())); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if err := state.Close(); err != nil {
		t.Fatalf("close source store: %v", err)
	}
	closed = true

	reopened, err := store.Open(store.Options{Path: path, LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened store: %v", err)
		}
	})
	recovered := newTestRegistry(t, reopened, time.Now, nil).Snapshot()
	if recovered.Version != 1 || len(recovered.Targets) != 1 || recovered.Targets[0].TargetID != "checkout" {
		t.Fatalf("recovered snapshot = %#v, want persisted checkout target", recovered)
	}
}

func TestRegistry_AuditFailureRollsBackTargetMutation(t *testing.T) {
	state := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	registry := newTestRegistry(t, state, time.Now, func() (string, error) {
		return "", errors.New("audit ID unavailable")
	})

	_, err := registry.Register(testRegistration(testTarget()))
	if err == nil {
		t.Fatal("Register() error = nil, want audit failure")
	}
	if snapshot := registry.Snapshot(); len(snapshot.Targets) != 0 || snapshot.Version != 0 {
		t.Fatalf("audit failure changed snapshot: %#v", snapshot)
	}
	if err := state.View(func(transaction *store.Tx) error {
		if _, found, err := transaction.Get(store.BucketServiceTargets, "checkout"); err != nil || found {
			t.Fatalf("target after audit failure = found %t, error %v", found, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("verify rolled back target: %v", err)
	}
}

func TestDecode_RejectsAmbiguousTargetDocument(t *testing.T) {
	_, err := Decode([]byte(`{"schema_version":"v1","target_id":"checkout","target_id":"duplicate"}`))
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("Decode() error = %v, want %v", err, ErrInvalidTarget)
	}
}

func newTestRegistry(t *testing.T, state *store.Store, clock func() time.Time, eventID func() (string, error)) *Registry {
	t.Helper()
	if eventID == nil {
		sequence := 0
		eventID = func() (string, error) {
			sequence++
			return fmt.Sprintf("target-event-%d", sequence), nil
		}
	}
	registry, err := NewRegistry(Options{
		State: state,
		AllowedTargets: []AllowedTarget{{
			TargetID:    "checkout",
			AdapterType: "docker",
		}},
		MaxTargets:       2,
		MaxEvidenceBytes: 1024,
		Clock:            clock,
		NewAuditEventID:  eventID,
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	return registry
}

func openTestStore(t *testing.T, path string) *store.Store {
	t.Helper()
	state, err := store.Open(store.Options{Path: path, LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Errorf("store.Close() error = %v", err)
		}
	})
	return state
}

func testRegistration(candidate contract.ServiceTarget) Registration {
	return Registration{
		Target:        candidate,
		ActorIdentity: "uid:1000/gid:1000",
		RequestID:     "request-1",
		ReasonCode:    "onboarding",
	}
}

func testTarget() contract.ServiceTarget {
	return contract.ServiceTarget{
		SchemaVersion: SchemaVersion,
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
		EvidencePolicy: contract.EvidencePolicy{
			RedactionProfile: "strict",
			MaxBytes:         1024,
		},
		StabilizationPolicy: contract.StabilizationPolicy{
			RecoverySamples: 2,
			Window:          contract.NewDuration(time.Minute),
		},
		Enabled: true,
	}
}
