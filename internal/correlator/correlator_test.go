package correlator

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
)

func TestCorrelator_IngestMergesDirectAndExternalSignalsInEitherOrder(t *testing.T) {
	now := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		signals []Signal
	}{
		{
			name: "direct then external",
			signals: []Signal{
				testSignal("observation-direct", "observer", "", contract.StateUnhealthy, now),
				testSignal("observation-external", "monitor", "alert-1", contract.StateUnhealthy, now),
			},
		},
		{
			name: "external then direct",
			signals: []Signal{
				testSignal("observation-external", "monitor", "alert-1", contract.StateUnhealthy, now),
				testSignal("observation-direct", "observer", "", contract.StateUnhealthy, now),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			correlator, _ := newTestCorrelator(t)
			candidate, err := correlator.Ingest(test.signals[0])
			if err != nil {
				t.Fatalf("Ingest(candidate) error = %v", err)
			}
			if candidate.Phase != PhaseCandidate || candidate.Incident.State != contract.IncidentOpen {
				t.Fatalf("candidate = %#v, want candidate/open", candidate)
			}
			confirmed, err := correlator.Ingest(test.signals[1])
			if err != nil {
				t.Fatalf("Ingest(confirmation) error = %v", err)
			}
			if confirmed.Incident.IncidentID != candidate.Incident.IncidentID || confirmed.Incident.DedupeKey != candidate.Incident.DedupeKey {
				t.Fatalf("merged incident = %#v, candidate = %#v", confirmed.Incident, candidate.Incident)
			}
			if confirmed.Phase != PhaseConfirmed || confirmed.Incident.State != contract.IncidentAnalyzing || len(confirmed.Incident.RuleIDs) != 1 {
				t.Fatalf("confirmed = %#v, want confirmed/analyzing with one rule", confirmed)
			}
		})
	}
}

func TestCorrelator_IngestPersistsReplayAndRecoveryLifecycle(t *testing.T) {
	now := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	correlator, state := newTestCorrelator(t)
	external := testSignal("observation-external", "monitor", "alert-1", contract.StateUnhealthy, now)
	candidate, err := correlator.Ingest(external)
	if err != nil {
		t.Fatalf("Ingest(candidate) error = %v", err)
	}
	duplicate, err := correlator.Ingest(external)
	if err != nil {
		t.Fatalf("Ingest(duplicate) error = %v", err)
	}
	if !duplicate.Duplicate || duplicate.Incident.IncidentID != candidate.Incident.IncidentID {
		t.Fatalf("duplicate = %#v, candidate = %#v", duplicate, candidate)
	}

	createdAfterRestart := false
	restarted, err := New(Options{
		State: state,
		NewIncidentID: func() (string, error) {
			createdAfterRestart = true
			return "must-not-create", nil
		},
	})
	if err != nil {
		t.Fatalf("New(restarted) error = %v", err)
	}
	afterRestart, err := restarted.Ingest(external)
	if err != nil {
		t.Fatalf("Ingest(replayed after restart) error = %v", err)
	}
	if !afterRestart.Duplicate || afterRestart.Incident.IncidentID != candidate.Incident.IncidentID {
		t.Fatalf("after restart = %#v, candidate = %#v", afterRestart, candidate)
	}
	if createdAfterRestart {
		t.Fatal("replayed input created a new incident after restart")
	}

	confirmed, err := restarted.Ingest(testSignal("observation-direct", "observer", "", contract.StateUnhealthy, now))
	if err != nil {
		t.Fatalf("Ingest(confirmation) error = %v", err)
	}
	if confirmed.Phase != PhaseConfirmed || confirmed.Incident.State != contract.IncidentAnalyzing {
		t.Fatalf("confirmed = %#v, want confirmed/analyzing", confirmed)
	}
	recovering, err := restarted.Ingest(testSignal("observation-recovery-1", "observer", "", contract.StateHealthy, now.Add(time.Minute)))
	if err != nil {
		t.Fatalf("Ingest(first recovery) error = %v", err)
	}
	if recovering.Phase != PhaseRecovering || recovering.Incident.State != contract.IncidentRecovering || !recovering.Incident.TerminalAt.IsZero() {
		t.Fatalf("first recovery = %#v, want recovering without terminal time", recovering)
	}
	stabilizing, err := restarted.Ingest(testSignal("observation-recovery-2", "observer", "", contract.StateHealthy, now.Add(2*time.Minute)))
	if err != nil {
		t.Fatalf("Ingest(second recovery) error = %v", err)
	}
	if stabilizing.Phase != PhaseRecovering || stabilizing.Incident.State != contract.IncidentStabilizing || !stabilizing.Incident.TerminalAt.IsZero() {
		t.Fatalf("second recovery = %#v, want stabilizing without terminal time", stabilizing)
	}
	terminal, err := restarted.Ingest(testSignal("observation-recovery-3", "observer", "", contract.StateHealthy, now.Add(3*time.Minute)))
	if err != nil {
		t.Fatalf("Ingest(terminal recovery) error = %v", err)
	}
	if terminal.Phase != PhaseTerminal || terminal.Incident.State != contract.IncidentClosed || terminal.Incident.TerminalAt.IsZero() {
		t.Fatalf("terminal = %#v, want terminal/closed", terminal)
	}
	if terminal.Incident.IncidentID != candidate.Incident.IncidentID {
		t.Fatalf("terminal incident ID = %q, want %q", terminal.Incident.IncidentID, candidate.Incident.IncidentID)
	}
}

func TestCorrelator_IngestFailsRecoveringIncidentOnUnhealthySignal(t *testing.T) {
	now := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	correlator, _ := newTestCorrelator(t)
	for _, signal := range []Signal{
		testSignal("observation-1", "observer", "", contract.StateUnhealthy, now),
		testSignal("observation-2", "monitor", "alert-1", contract.StateUnhealthy, now),
		testSignal("observation-3", "observer", "", contract.StateHealthy, now.Add(time.Minute)),
	} {
		if _, err := correlator.Ingest(signal); err != nil {
			t.Fatalf("Ingest(%q) error = %v", signal.Observation.ObservationID, err)
		}
	}
	failed, err := correlator.Ingest(testSignal("observation-4", "observer", "", contract.StateUnhealthy, now.Add(2*time.Minute)))
	if err != nil {
		t.Fatalf("Ingest(recovery failure) error = %v", err)
	}
	if failed.Phase != PhaseTerminal || failed.Incident.State != contract.IncidentFailed || failed.Incident.TerminalAt.IsZero() {
		t.Fatalf("failed = %#v, want terminal/failed", failed)
	}
}

func TestCorrelator_IngestMatchesRecoveryOutsideFailureDedupeWindow(t *testing.T) {
	now := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	correlator, _ := newTestCorrelator(t)
	correlator.dedupeWindow = time.Minute
	for _, signal := range []Signal{
		testSignal("observation-1", "observer", "", contract.StateUnhealthy, now),
		testSignal("observation-2", "monitor", "alert-1", contract.StateUnhealthy, now),
	} {
		if _, err := correlator.Ingest(signal); err != nil {
			t.Fatalf("Ingest(%q) error = %v", signal.Observation.ObservationID, err)
		}
	}
	recovering, err := correlator.Ingest(testSignal("observation-recovery", "observer", "", contract.StateHealthy, now.Add(2*time.Minute)))
	if err != nil {
		t.Fatalf("Ingest(recovery) error = %v", err)
	}
	if recovering.Ignored || recovering.Phase != PhaseRecovering || recovering.Incident.State != contract.IncidentRecovering {
		t.Fatalf("recovery = %#v, want matching recovering incident", recovering)
	}
}

func TestCorrelator_IngestRejectsUnsafeSignals(t *testing.T) {
	correlator, _ := newTestCorrelator(t)
	now := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		signal Signal
	}{
		{name: "unknown state", signal: testSignal("observation-1", "observer", "", contract.StateUnknown, now)},
		{name: "missing target", signal: Signal{Observation: contract.HealthObservation{SchemaVersion: contract.SchemaVersionV1, ObservationID: "observation-1", RuleID: "availability", ObservedAt: now, NormalizedState: contract.StateUnhealthy}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := correlator.Ingest(test.signal); !errors.Is(err, ErrInvalidSignal) {
				t.Fatalf("Ingest() error = %v, want %v", err, ErrInvalidSignal)
			}
		})
	}
}

func TestCorrelator_IngestDoesNotPersistRawExternalIdentity(t *testing.T) {
	now := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	correlator, state := newTestCorrelator(t)
	signal := testSignal("observation-external", "monitor-token-value", "customer-alert-value", contract.StateUnhealthy, now)
	result, err := correlator.Ingest(signal)
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	err = state.View(func(tx *store.Tx) error {
		document, found, err := tx.Get(store.BucketIncidents, result.Incident.DedupeKey)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("persisted incident not found")
		}
		if bytes.Contains(document, []byte(signal.Source)) || bytes.Contains(document, []byte(signal.ExternalAlertID)) {
			return errors.New("persisted incident contains external identity")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("State.View() error = %v", err)
	}
}

func newTestCorrelator(t *testing.T) (*Correlator, *store.Store) {
	t.Helper()
	state, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db"), LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Errorf("Store.Close() error = %v", err)
		}
	})
	nextID := 0
	correlator, err := New(Options{
		State: state,
		NewIncidentID: func() (string, error) {
			nextID++
			return fmt.Sprintf("incident-%d", nextID), nil
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return correlator, state
}

func testSignal(id, source, externalID string, state contract.NormalizedState, observedAt time.Time) Signal {
	return Signal{
		Source:          source,
		ExternalAlertID: externalID,
		Severity:        contract.SeverityWarning,
		Observation: contract.HealthObservation{
			SchemaVersion:   contract.SchemaVersionV1,
			ObservationID:   id,
			TargetID:        "checkout",
			RuleID:          "availability",
			ObservedAt:      observedAt,
			NormalizedState: state,
		},
	}
}
