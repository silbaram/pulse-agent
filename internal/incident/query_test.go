package incident

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
)

func TestQuery_ListFiltersPagesAndRedactsStoredEnvelope(t *testing.T) {
	state := openState(t)
	now := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	putIncident(t, state, incident("incident-2", contract.IncidentClosed, now.Add(time.Hour)))
	putIncident(t, state, incident("incident-1", contract.IncidentOpen, now))
	query, err := NewQuery(state)
	if err != nil {
		t.Fatalf("NewQuery() error = %v", err)
	}
	page, err := query.List(Filter{PageSize: 1})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page.Incidents) != 1 || page.Incidents[0].IncidentID != "incident-1" || page.NextOffset != 1 {
		t.Fatalf("page = %#v", page)
	}
	filtered, err := query.List(Filter{State: contract.IncidentClosed, From: now.Add(30 * time.Minute), PageSize: 10})
	if err != nil {
		t.Fatalf("List(filtered) error = %v", err)
	}
	if len(filtered.Incidents) != 1 || filtered.Incidents[0].IncidentID != "incident-2" {
		t.Fatalf("filtered = %#v", filtered)
	}
}

func TestQuery_ShowReturnsNotFound(t *testing.T) {
	state := openState(t)
	query, err := NewQuery(state)
	if err != nil {
		t.Fatalf("NewQuery() error = %v", err)
	}
	if _, err := query.Show("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Show() error = %v, want %v", err, ErrNotFound)
	}
}

func openState(t *testing.T) *store.Store {
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
	return state
}
func incident(id string, state contract.IncidentState, opened time.Time) contract.Incident {
	terminal := time.Time{}
	if state == contract.IncidentClosed {
		terminal = opened.Add(time.Minute)
	}
	return contract.Incident{SchemaVersion: contract.SchemaVersionV1, IncidentID: id, DedupeKey: "checkout/availability/1", TargetID: "checkout", RuleIDs: []string{"availability"}, State: state, Severity: contract.SeverityWarning, OpenedAt: opened, TerminalAt: terminal}
}
func putIncident(t *testing.T, state *store.Store, value contract.Incident) {
	t.Helper()
	document, err := json.Marshal(struct {
		SchemaVersion string            `json:"schema_version"`
		Phase         string            `json:"phase"`
		Incident      contract.Incident `json:"incident"`
		SeenInputs    []string          `json:"seen_inputs"`
	}{SchemaVersion: contract.SchemaVersionV1, Phase: phase(value.State), Incident: value, SeenInputs: []string{"input"}})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := state.Update(func(tx *store.Tx) error {
		return tx.Put(store.BucketIncidents, value.DedupeKey+value.IncidentID, document)
	}); err != nil {
		t.Fatalf("State.Update() error = %v", err)
	}
}
func phase(state contract.IncidentState) string {
	if state == contract.IncidentClosed || state == contract.IncidentFailed {
		return "terminal"
	}
	if state == contract.IncidentOpen {
		return "candidate"
	}
	return "confirmed"
}
