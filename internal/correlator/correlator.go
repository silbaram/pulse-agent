// Package correlator deterministically combines local and external observations.
package correlator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
	"pulse-agent/internal/telemetry"
)

const (
	defaultDedupeWindow = 5 * time.Minute
	maxDedupeWindow     = 24 * time.Hour
	maxSeenInputs       = 256
	maxRecordBytes      = 128 * 1024
)

var (
	// ErrInvalidOptions indicates that correlator dependencies or limits are unsafe.
	ErrInvalidOptions = errors.New("invalid correlator options")
	// ErrInvalidSignal indicates an observation that cannot safely affect incidents.
	ErrInvalidSignal = errors.New("invalid correlation signal")
	// ErrCorruptIncident indicates a persisted incident record that fails validation.
	ErrCorruptIncident = errors.New("corrupt persisted incident")
)

// Phase identifies the correlator-owned lifecycle phase. The incident's public
// state records the matching contract lifecycle state.
type Phase string

const (
	// PhaseCandidate identifies an unconfirmed unhealthy signal.
	PhaseCandidate Phase = "candidate"
	// PhaseConfirmed identifies an incident confirmed by another unhealthy signal.
	PhaseConfirmed Phase = "confirmed"
	// PhaseRecovering identifies a confirmed incident receiving recovery samples.
	PhaseRecovering Phase = "recovering"
	// PhaseTerminal identifies a closed or failed incident.
	PhaseTerminal Phase = "terminal"
)

// Signal describes one already-normalized direct or external observation. It
// never carries raw webhook bodies or evidence content.
type Signal struct {
	// Source identifies the producer, such as observer or a monitoring system.
	Source string
	// ExternalAlertID deduplicates an external alert across process restarts.
	// It is empty for direct observer input.
	ExternalAlertID string
	// Severity is the caller-supplied urgency. An empty value defaults to warning.
	Severity contract.Severity
	// Observation is the bounded, normalized observation to correlate.
	Observation contract.HealthObservation
}

// Result describes the persisted incident outcome for one signal.
type Result struct {
	// Incident is the current durable incident contract.
	Incident contract.Incident
	// Phase is the current correlator-owned lifecycle phase.
	Phase Phase
	// Duplicate reports that an already persisted input caused no state change.
	Duplicate bool
	// Ignored reports that a healthy signal had no matching active incident.
	Ignored bool
}

// Options configures one daemon-owned correlator.
type Options struct {
	// State persists incident lifecycle records in the daemon-owned local store.
	State *store.Store
	// NewIncidentID creates immutable incident IDs for newly detected failures.
	NewIncidentID func() (string, error)
	// DedupeWindow groups signals for one target and rule. Zero defaults to five minutes.
	DedupeWindow time.Duration
	// Telemetry records bounded incident transition measurements when configured.
	Telemetry *telemetry.Recorder
}

// Correlator atomically deduplicates normalized signals and persists lifecycle
// progress. Its zero value is invalid; construct it with New.
type Correlator struct {
	state         *store.Store
	newIncidentID func() (string, error)
	dedupeWindow  time.Duration
	telemetry     *telemetry.Recorder
}

type persistedIncident struct {
	SchemaVersion string            `json:"schema_version"`
	Phase         Phase             `json:"phase"`
	Incident      contract.Incident `json:"incident"`
	SeenInputs    []string          `json:"seen_inputs"`
}

// New validates daemon-owned dependencies and bounds for a correlator.
func New(options Options) (*Correlator, error) {
	dedupeWindow := options.DedupeWindow
	if dedupeWindow == 0 {
		dedupeWindow = defaultDedupeWindow
	}
	if options.State == nil || options.NewIncidentID == nil || dedupeWindow < time.Second || dedupeWindow > maxDedupeWindow {
		return nil, ErrInvalidOptions
	}
	return &Correlator{
		state:         options.State,
		newIncidentID: options.NewIncidentID,
		dedupeWindow:  dedupeWindow,
		telemetry:     options.Telemetry,
	}, nil
}

// Ingest persists one deterministic candidate, confirmation, recovery, or
// terminal transition. Replayed input returns Duplicate without mutation.
func (c *Correlator) Ingest(signal Signal) (result Result, resultErr error) {
	startedAt := time.Now()
	defer func() {
		c.recordTransition(result, resultErr, time.Since(startedAt))
	}()
	if c == nil {
		return Result{}, ErrInvalidOptions
	}
	if err := validateSignal(&signal); err != nil {
		return Result{}, err
	}
	dedupeKey := c.dedupeKey(signal.Observation)
	inputKey := signalInputKey(signal)
	err := c.state.Update(func(tx *store.Tx) error {
		recordKey := dedupeKey
		document, found, err := tx.Get(store.BucketIncidents, recordKey)
		if err != nil {
			return err
		}
		if !found && signal.Observation.NormalizedState == contract.StateHealthy {
			recordKey, record, found, err := findActiveRecord(tx, signal.Observation)
			if err != nil {
				return err
			}
			if !found {
				result = Result{Ignored: true}
				return nil
			}
			result, err = updateRecord(tx, recordKey, record, inputKey, signal)
			return err
		}
		if !found {
			record, err := c.newCandidate(signal, dedupeKey, inputKey)
			if err != nil {
				return err
			}
			result = Result{Incident: record.Incident, Phase: record.Phase}
			return putRecord(tx, recordKey, record)
		}

		record, err := decodeRecord(document)
		if err != nil {
			return err
		}
		result, err = updateRecord(tx, recordKey, record, inputKey, signal)
		return err
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

func (c *Correlator) recordTransition(result Result, ingestErr error, duration time.Duration) {
	if c == nil || c.telemetry == nil {
		return
	}
	telemetryResult, reason := telemetry.ResultSuccess, telemetry.ReasonAccepted
	if ingestErr != nil {
		telemetryResult, reason = telemetry.ResultFailure, telemetry.ReasonInternal
		if errors.Is(ingestErr, ErrInvalidSignal) || errors.Is(ingestErr, ErrInvalidOptions) {
			telemetryResult, reason = telemetry.ResultRejected, telemetry.ReasonInvalid
		}
	} else if result.Duplicate {
		telemetryResult, reason = telemetry.ResultRejected, telemetry.ReasonDuplicate
	}
	event, err := telemetry.NewEvent(telemetry.ComponentCorrelator, telemetry.OperationTransition, telemetryResult, reason, duration)
	if err == nil {
		c.telemetry.RecordBestEffort(context.Background(), event)
	}
}

func updateRecord(tx *store.Tx, key string, record persistedIncident, inputKey string, signal Signal) (Result, error) {
	if contains(record.SeenInputs, inputKey) {
		return Result{Incident: record.Incident, Phase: record.Phase, Duplicate: true}, nil
	}
	record.SeenInputs = appendBounded(record.SeenInputs, inputKey)
	advance(&record, signal)
	if err := putRecord(tx, key, record); err != nil {
		return Result{}, err
	}
	return Result{Incident: record.Incident, Phase: record.Phase}, nil
}

func findActiveRecord(tx *store.Tx, observation contract.HealthObservation) (string, persistedIncident, bool, error) {
	var (
		key    string
		latest persistedIncident
		found  bool
	)
	err := tx.ForEach(store.BucketIncidents, func(candidateKey string, document []byte) error {
		record, err := decodeRecord(document)
		if err != nil {
			return err
		}
		if !matchesActiveRecord(record, observation) {
			return nil
		}
		if !found || record.Incident.OpenedAt.After(latest.Incident.OpenedAt) {
			key = candidateKey
			latest = record
			found = true
		}
		return nil
	})
	if err != nil {
		return "", persistedIncident{}, false, err
	}
	return key, latest, found, nil
}

func matchesActiveRecord(record persistedIncident, observation contract.HealthObservation) bool {
	return record.Phase != PhaseTerminal && record.Incident.TargetID == observation.TargetID && len(record.Incident.RuleIDs) == 1 && record.Incident.RuleIDs[0] == observation.RuleID && !observation.ObservedAt.Before(record.Incident.OpenedAt)
}

func (c *Correlator) newCandidate(signal Signal, dedupeKey, inputKey string) (persistedIncident, error) {
	incidentID, err := c.newIncidentID()
	if err != nil {
		return persistedIncident{}, err
	}
	if strings.TrimSpace(incidentID) == "" {
		return persistedIncident{}, ErrInvalidOptions
	}
	return persistedIncident{
		SchemaVersion: contract.SchemaVersionV1,
		Phase:         PhaseCandidate,
		Incident: contract.Incident{
			SchemaVersion: contract.SchemaVersionV1,
			IncidentID:    incidentID,
			DedupeKey:     dedupeKey,
			TargetID:      signal.Observation.TargetID,
			RuleIDs:       []string{signal.Observation.RuleID},
			State:         contract.IncidentOpen,
			Severity:      signal.Severity,
			OpenedAt:      signal.Observation.ObservedAt.UTC(),
		},
		SeenInputs: []string{inputKey},
	}, nil
}

func (c *Correlator) dedupeKey(observation contract.HealthObservation) string {
	windowStart := observation.ObservedAt.UTC().Truncate(c.dedupeWindow)
	return observation.TargetID + "/" + observation.RuleID + "/" + strconv.FormatInt(windowStart.UnixNano(), 10)
}

func validateSignal(signal *Signal) error {
	if signal == nil || signal.Observation.SchemaVersion != contract.SchemaVersionV1 || strings.TrimSpace(signal.Observation.ObservationID) == "" || strings.TrimSpace(signal.Observation.TargetID) == "" || strings.TrimSpace(signal.Observation.RuleID) == "" || signal.Observation.ObservedAt.IsZero() {
		return ErrInvalidSignal
	}
	if signal.Observation.NormalizedState != contract.StateHealthy && signal.Observation.NormalizedState != contract.StateUnhealthy {
		return ErrInvalidSignal
	}
	if signal.Source == "" {
		signal.Source = "observer"
	}
	if len(signal.Source) > 96 || len(signal.ExternalAlertID) > 128 || strings.TrimSpace(signal.Source) == "" || strings.TrimSpace(signal.ExternalAlertID) != signal.ExternalAlertID {
		return ErrInvalidSignal
	}
	if signal.Severity == "" {
		signal.Severity = contract.SeverityWarning
	}
	if signal.Severity != contract.SeverityInfo && signal.Severity != contract.SeverityWarning && signal.Severity != contract.SeverityCritical {
		return ErrInvalidSignal
	}
	return nil
}

func signalInputKey(signal Signal) string {
	identity := signal.Observation.ObservationID
	if signal.ExternalAlertID != "" {
		identity = signal.Source + "\x00" + signal.ExternalAlertID
	}
	sum := sha256.Sum256([]byte(identity))
	return "input:" + hex.EncodeToString(sum[:])
}

func advance(record *persistedIncident, signal Signal) {
	if record.Phase == PhaseTerminal {
		return
	}
	if severityHigher(signal.Severity, record.Incident.Severity) {
		record.Incident.Severity = signal.Severity
	}
	if signal.Observation.NormalizedState == contract.StateUnhealthy {
		advanceUnhealthy(record, signal.Observation.ObservedAt)
		return
	}
	advanceHealthy(record, signal.Observation.ObservedAt)
}

func advanceUnhealthy(record *persistedIncident, observedAt time.Time) {
	switch record.Phase {
	case PhaseCandidate:
		record.Phase = PhaseConfirmed
		record.Incident.State = contract.IncidentAnalyzing
	case PhaseRecovering:
		record.Phase = PhaseTerminal
		record.Incident.State = contract.IncidentFailed
		record.Incident.TerminalAt = observedAt.UTC()
	}
}

func advanceHealthy(record *persistedIncident, observedAt time.Time) {
	switch record.Phase {
	case PhaseCandidate:
		record.Phase = PhaseTerminal
		record.Incident.State = contract.IncidentClosed
		record.Incident.TerminalAt = observedAt.UTC()
	case PhaseConfirmed:
		record.Phase = PhaseRecovering
		record.Incident.State = contract.IncidentRecovering
	case PhaseRecovering:
		if record.Incident.State == contract.IncidentRecovering {
			record.Incident.State = contract.IncidentStabilizing
			return
		}
		record.Phase = PhaseTerminal
		record.Incident.State = contract.IncidentClosed
		record.Incident.TerminalAt = observedAt.UTC()
	}
}

func putRecord(tx *store.Tx, key string, record persistedIncident) error {
	if err := validateRecord(record); err != nil {
		return err
	}
	document, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode incident record: %w", err)
	}
	return tx.Put(store.BucketIncidents, key, document)
}

func decodeRecord(document []byte) (persistedIncident, error) {
	record, err := contract.Decode(document, contract.DecodeOptions[persistedIncident]{
		MaxBytes:      maxRecordBytes,
		SchemaVersion: contract.SchemaVersionV1,
		Validate:      validateRecord,
	})
	if err != nil {
		return persistedIncident{}, ErrCorruptIncident
	}
	return record, nil
}

func validateRecord(record persistedIncident) error {
	if record.SchemaVersion != contract.SchemaVersionV1 || !validPhase(record.Phase) || len(record.SeenInputs) == 0 || len(record.SeenInputs) > maxSeenInputs || record.Incident.Validate() != nil {
		return ErrCorruptIncident
	}
	if record.Incident.DedupeKey == "" || !phaseMatchesIncident(record.Phase, record.Incident) {
		return ErrCorruptIncident
	}
	seen := make(map[string]struct{}, len(record.SeenInputs))
	for _, input := range record.SeenInputs {
		if input == "" || len(input) > 256 {
			return ErrCorruptIncident
		}
		if _, duplicate := seen[input]; duplicate {
			return ErrCorruptIncident
		}
		seen[input] = struct{}{}
	}
	return nil
}

func validPhase(phase Phase) bool {
	return phase == PhaseCandidate || phase == PhaseConfirmed || phase == PhaseRecovering || phase == PhaseTerminal
}

func phaseMatchesIncident(phase Phase, incident contract.Incident) bool {
	switch phase {
	case PhaseCandidate:
		return incident.State == contract.IncidentOpen
	case PhaseConfirmed:
		return incident.State == contract.IncidentAnalyzing
	case PhaseRecovering:
		return incident.State == contract.IncidentRecovering || incident.State == contract.IncidentStabilizing
	case PhaseTerminal:
		return incident.State == contract.IncidentClosed || incident.State == contract.IncidentFailed
	default:
		return false
	}
}

func appendBounded(inputs []string, input string) []string {
	inputs = append(inputs, input)
	if len(inputs) <= maxSeenInputs {
		return inputs
	}
	return append([]string(nil), inputs[len(inputs)-maxSeenInputs:]...)
}

func contains(inputs []string, input string) bool {
	for _, candidate := range inputs {
		if candidate == input {
			return true
		}
	}
	return false
}

func severityHigher(candidate, current contract.Severity) bool {
	return severityRank(candidate) > severityRank(current)
}

func severityRank(severity contract.Severity) int {
	switch severity {
	case contract.SeverityCritical:
		return 3
	case contract.SeverityWarning:
		return 2
	case contract.SeverityInfo:
		return 1
	default:
		return 0
	}
}
