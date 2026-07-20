// Package contract defines the versioned data contracts shared by Pulse Agent
// components.
package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SchemaVersionV1 is the only schema version supported by the initial MVP.
const SchemaVersionV1 = "v1"

const maxReferenceCount = 64

var (
	// ErrInvalidContract indicates an invalid value in a domain contract.
	ErrInvalidContract = errors.New("invalid contract")
	// ErrInvalidStateTransition indicates a transition outside an approved state lifecycle.
	ErrInvalidStateTransition = errors.New("invalid state transition")
)

// Duration is a JSON duration encoded as a Go duration string, such as "30s".
type Duration time.Duration

// NewDuration converts a standard-library duration to a contract Duration.
func NewDuration(value time.Duration) Duration {
	return Duration(value)
}

// Value returns the standard-library duration represented by d.
func (d Duration) Value() time.Duration {
	return time.Duration(d)
}

// MarshalJSON serializes d as a Go duration string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON parses a JSON duration string without exposing input content.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return ErrInvalidContract
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return ErrInvalidContract
	}
	*d = Duration(parsed)
	return nil
}

// DeploymentProfile identifies where an agent process runs.
type DeploymentProfile string

const (
	// DeploymentStandalone identifies the standalone host-service profile.
	DeploymentStandalone DeploymentProfile = "standalone"
)

// AgentStatus identifies the lifecycle state of an agent process.
type AgentStatus string

const (
	// AgentStarting identifies an agent that is starting.
	AgentStarting AgentStatus = "starting"
	// AgentRunning identifies an agent that is running.
	AgentRunning AgentStatus = "running"
	// AgentStopping identifies an agent that is stopping.
	AgentStopping AgentStatus = "stopping"
	// AgentStopped identifies an agent that stopped normally.
	AgentStopped AgentStatus = "stopped"
	// AgentFailed identifies an agent that stopped after failure.
	AgentFailed AgentStatus = "failed"
)

// Severity is the bounded urgency of an observation or incident.
type Severity string

const (
	// SeverityInfo identifies informational urgency.
	SeverityInfo Severity = "info"
	// SeverityWarning identifies warning urgency.
	SeverityWarning Severity = "warning"
	// SeverityCritical identifies critical urgency.
	SeverityCritical Severity = "critical"
)

// NormalizedState is a deterministic health observation result.
type NormalizedState string

const (
	// StateHealthy identifies a healthy observation.
	StateHealthy NormalizedState = "healthy"
	// StateUnhealthy identifies an unhealthy observation.
	StateUnhealthy NormalizedState = "unhealthy"
	// StateUnknown identifies an indeterminate observation.
	StateUnknown NormalizedState = "unknown"
)

// RiskTier is the approved risk classification for a typed action.
type RiskTier string

const (
	// RiskLow identifies a low-risk action.
	RiskLow RiskTier = "low"
	// RiskMedium identifies a medium-risk action.
	RiskMedium RiskTier = "medium"
	// RiskHigh identifies a high-risk action.
	RiskHigh RiskTier = "high"
)

// ActionType identifies a registered action without exposing a raw command.
type ActionType string

const (
	// ActionDockerContainerRestart restarts one registered Docker container.
	ActionDockerContainerRestart ActionType = "docker.container.restart"
	// ActionDockerComposeServiceRestart restarts one eligible Compose service.
	ActionDockerComposeServiceRestart ActionType = "docker.compose_service.restart"
)

// ApprovalDecision identifies a human approval outcome.
type ApprovalDecision string

const (
	// ApprovalGranted identifies an approved recovery command.
	ApprovalGranted ApprovalDecision = "grant"
	// ApprovalDenied identifies a denied recovery command.
	ApprovalDenied ApprovalDecision = "deny"
)

// NotificationRecommendation is the bounded notification suggestion from analysis.
type NotificationRecommendation string

const (
	// NotificationNone identifies no notification suggestion.
	NotificationNone NotificationRecommendation = "none"
	// NotificationNotify identifies a normal notification suggestion.
	NotificationNotify NotificationRecommendation = "notify"
	// NotificationPage identifies an urgent notification suggestion.
	NotificationPage NotificationRecommendation = "page"
)

// IncidentState identifies the lifecycle state of an incident.
type IncidentState string

const (
	// IncidentOpen identifies a newly detected incident.
	IncidentOpen IncidentState = "open"
	// IncidentAnalyzing identifies an incident being analyzed.
	IncidentAnalyzing IncidentState = "analyzing"
	// IncidentAwaitingApproval identifies an incident awaiting approval.
	IncidentAwaitingApproval IncidentState = "awaiting_approval"
	// IncidentRecovering identifies an incident with recovery in progress.
	IncidentRecovering IncidentState = "recovering"
	// IncidentStabilizing identifies an incident being verified after recovery.
	IncidentStabilizing IncidentState = "stabilizing"
	// IncidentClosed identifies a resolved incident.
	IncidentClosed IncidentState = "closed"
	// IncidentFailed identifies a terminal incident failure.
	IncidentFailed IncidentState = "failed"
)

// RecoveryCommandState identifies the lifecycle state of a recovery command.
type RecoveryCommandState string

const (
	// RecoveryPending identifies a command awaiting policy processing.
	RecoveryPending RecoveryCommandState = "pending"
	// RecoveryApproved identifies a command approved to execute.
	RecoveryApproved RecoveryCommandState = "approved"
	// RecoveryExecuting identifies a command currently executing.
	RecoveryExecuting RecoveryCommandState = "executing"
	// RecoverySucceeded identifies a successful command.
	RecoverySucceeded RecoveryCommandState = "succeeded"
	// RecoveryFailed identifies a failed command.
	RecoveryFailed RecoveryCommandState = "failed"
	// RecoveryDenied identifies a denied command.
	RecoveryDenied RecoveryCommandState = "denied"
	// RecoveryExpired identifies a command that expired before execution.
	RecoveryExpired RecoveryCommandState = "expired"
)

// DeliveryPayloadType identifies the only payloads accepted by the shared queue.
type DeliveryPayloadType string

const (
	// DeliveryPayloadLifecycleEvent identifies a lifecycle event payload.
	DeliveryPayloadLifecycleEvent DeliveryPayloadType = "lifecycle_event"
	// DeliveryPayloadIncidentReport identifies an incident report payload.
	DeliveryPayloadIncidentReport DeliveryPayloadType = "incident_report"
)

// DeliveryState identifies the delivery state of a queue item.
type DeliveryState string

const (
	// DeliveryPending identifies an item waiting for delivery.
	DeliveryPending DeliveryState = "pending"
	// DeliveryDelivered identifies a delivered item.
	DeliveryDelivered DeliveryState = "delivered"
	// DeliveryExpired identifies an expired item.
	DeliveryExpired DeliveryState = "expired"
	// DeliveryFailed identifies an item that exhausted its attempts.
	DeliveryFailed DeliveryState = "failed"
)

// ConfidenceLabel is a bounded confidence value produced by analysis.
type ConfidenceLabel string

const (
	// ConfidenceLow identifies low confidence.
	ConfidenceLow ConfidenceLabel = "low"
	// ConfidenceMedium identifies medium confidence.
	ConfidenceMedium ConfidenceLabel = "medium"
	// ConfidenceHigh identifies high confidence.
	ConfidenceHigh ConfidenceLabel = "high"
)

// LifecycleEventType identifies an incident lifecycle notification.
type LifecycleEventType string

const (
	// LifecycleIncidentConfirmed identifies a confirmed incident.
	LifecycleIncidentConfirmed LifecycleEventType = "incident.confirmed"
	// LifecycleAnalysisUnavailable identifies unavailable analysis.
	LifecycleAnalysisUnavailable LifecycleEventType = "analysis.unavailable"
	// LifecyclePolicyDenied identifies a policy denial.
	LifecyclePolicyDenied LifecycleEventType = "policy.denied"
	// LifecycleApprovalRequested identifies a required approval.
	LifecycleApprovalRequested LifecycleEventType = "approval.requested"
	// LifecycleRecoveryStarted identifies recovery start.
	LifecycleRecoveryStarted LifecycleEventType = "recovery.started"
	// LifecycleIncidentClosed identifies an incident closure.
	LifecycleIncidentClosed LifecycleEventType = "incident.closed"
	// LifecycleIncidentFailed identifies an incident failure.
	LifecycleIncidentFailed LifecycleEventType = "incident.failed"
)

// AgentInstance describes a running Pulse Agent process.
type AgentInstance struct {
	SchemaVersion     string            `json:"schema_version"`
	InstanceID        string            `json:"instance_id"`
	DeploymentProfile DeploymentProfile `json:"deployment_profile"`
	HostID            string            `json:"host_id"`
	Capabilities      []string          `json:"capabilities"`
	StartedAt         time.Time         `json:"started_at"`
	LastCycleAt       time.Time         `json:"last_cycle_at"`
	Status            AgentStatus       `json:"status"`
}

// EvidencePolicy constrains locally retained evidence without containing it.
type EvidencePolicy struct {
	RedactionProfile string `json:"redaction_profile"`
	MaxBytes         int    `json:"max_bytes"`
}

// StabilizationPolicy defines bounded post-recovery verification.
type StabilizationPolicy struct {
	RecoverySamples int      `json:"recovery_samples"`
	Window          Duration `json:"window"`
}

// ProbeRule defines a deterministic health signal evaluation.
type ProbeRule struct {
	RuleID              string   `json:"rule_id"`
	SignalType          string   `json:"signal_type"`
	Interval            Duration `json:"interval"`
	Timeout             Duration `json:"timeout"`
	Threshold           float64  `json:"threshold"`
	ConsecutiveFailures int      `json:"consecutive_failures"`
	RecoverySamples     int      `json:"recovery_samples"`
	SLOWindow           Duration `json:"slo_window"`
	Severity            Severity `json:"severity"`
}

// ServiceTarget identifies one monitored local service.
type ServiceTarget struct {
	SchemaVersion       string              `json:"schema_version"`
	TargetID            string              `json:"target_id"`
	AdapterType         string              `json:"adapter_type"`
	Selector            string              `json:"selector"`
	ProbeRules          []ProbeRule         `json:"probe_rules"`
	EvidencePolicy      EvidencePolicy      `json:"evidence_policy"`
	StabilizationPolicy StabilizationPolicy `json:"stabilization_policy"`
	Enabled             bool                `json:"enabled"`
}

// HealthObservation is a normalized observation with bounded metric values.
type HealthObservation struct {
	SchemaVersion   string             `json:"schema_version"`
	ObservationID   string             `json:"observation_id"`
	TargetID        string             `json:"target_id"`
	RuleID          string             `json:"rule_id"`
	ObservedAt      time.Time          `json:"observed_at"`
	NormalizedState NormalizedState    `json:"normalized_state"`
	BoundedValues   map[string]float64 `json:"bounded_values"`
	EvidenceRefs    []string           `json:"evidence_refs"`
	Sequence        uint64             `json:"sequence"`
}

// Incident is the durable record for one deduplicated service failure.
type Incident struct {
	SchemaVersion     string        `json:"schema_version"`
	IncidentID        string        `json:"incident_id"`
	DedupeKey         string        `json:"dedupe_key"`
	TargetID          string        `json:"target_id"`
	RuleIDs           []string      `json:"rule_ids"`
	State             IncidentState `json:"state"`
	Severity          Severity      `json:"severity"`
	OpenedAt          time.Time     `json:"opened_at"`
	AnalysisRef       string        `json:"analysis_ref,omitempty"`
	SelectedRunbookID string        `json:"selected_runbook_id,omitempty"`
	TerminalAt        time.Time     `json:"terminal_at,omitempty"`
}

// Validate verifies the Incident state and terminal-time invariants.
func (i Incident) Validate() error {
	if err := validateVersion(i.SchemaVersion); err != nil {
		return err
	}
	if err := required("incident_id", i.IncidentID); err != nil {
		return err
	}
	if err := required("target_id", i.TargetID); err != nil {
		return err
	}
	if !validIncidentState(i.State) || i.OpenedAt.IsZero() || len(i.RuleIDs) == 0 || len(i.RuleIDs) > maxReferenceCount {
		return invalid("incident")
	}
	if terminalIncident(i.State) != !i.TerminalAt.IsZero() {
		return invalid("incident terminal time")
	}
	return nil
}

// CanTransitionTo reports whether i may move to next.
func (i IncidentState) CanTransitionTo(next IncidentState) bool {
	switch i {
	case IncidentOpen:
		return next == IncidentAnalyzing || next == IncidentClosed || next == IncidentFailed
	case IncidentAnalyzing:
		return next == IncidentAwaitingApproval || next == IncidentRecovering || next == IncidentClosed || next == IncidentFailed
	case IncidentAwaitingApproval:
		return next == IncidentRecovering || next == IncidentClosed || next == IncidentFailed
	case IncidentRecovering:
		return next == IncidentStabilizing || next == IncidentFailed
	case IncidentStabilizing:
		return next == IncidentClosed || next == IncidentFailed
	default:
		return false
	}
}

// ValidateTransition rejects an incident transition outside the lifecycle.
func (i IncidentState) ValidateTransition(next IncidentState) error {
	if !i.CanTransitionTo(next) {
		return ErrInvalidStateTransition
	}
	return nil
}

// EvidenceRef identifies locally retained, redacted evidence without storing
// original evidence content in the contract.
type EvidenceRef struct {
	SchemaVersion    string    `json:"schema_version"`
	EvidenceID       string    `json:"evidence_id"`
	SourceType       string    `json:"source_type"`
	CollectorID      string    `json:"collector_id"`
	Start            time.Time `json:"start"`
	End              time.Time `json:"end"`
	RedactionProfile string    `json:"redaction_profile"`
	Digest           string    `json:"digest"`
	ByteCount        int       `json:"byte_count"`
	RetentionUntil   time.Time `json:"retention_until"`
}

// TargetConstraint restricts a registered runbook to an approved target.
type TargetConstraint struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

// TypedAction is a registered action description. It deliberately has no raw
// command, argv, shell, script, or exec field.
type TypedAction struct {
	ActionType     ActionType `json:"action_type"`
	TargetSelector string     `json:"target_selector"`
	StopTimeout    Duration   `json:"stop_timeout"`
	Cooldown       Duration   `json:"cooldown"`
}

// ApprovalPolicy defines whether a typed action requires human approval.
type ApprovalPolicy struct {
	Required bool `json:"required"`
}

// RetryPolicy defines a bounded number of action attempts.
type RetryPolicy struct {
	MaxAttempts int `json:"max_attempts"`
}

// Runbook is the strict, executable JSON member of a runbook pair.
type Runbook struct {
	SchemaVersion       string              `json:"schema_version"`
	RunbookID           string              `json:"runbook_id"`
	Version             string              `json:"version"`
	Digest              string              `json:"digest"`
	AdapterType         string              `json:"adapter_type"`
	TargetConstraints   []TargetConstraint  `json:"target_constraints"`
	TypedActions        []TypedAction       `json:"typed_actions"`
	RiskTier            RiskTier            `json:"risk_tier"`
	AutoExecute         bool                `json:"auto_execute"`
	ApprovalPolicy      ApprovalPolicy      `json:"approval_policy"`
	Preconditions       []string            `json:"preconditions"`
	RetryPolicy         RetryPolicy         `json:"retry_policy"`
	StabilizationPolicy StabilizationPolicy `json:"stabilization_policy"`
}

// Hypothesis is an evidence-referenced analysis statement with no executable
// command field.
type Hypothesis struct {
	Summary      string   `json:"summary"`
	EvidenceRefs []string `json:"evidence_refs"`
}

// AnalysisResult is a versioned model output that may recommend registered
// runbooks but cannot carry command text or execution details.
type AnalysisResult struct {
	SchemaVersion              string                     `json:"schema_version"`
	IncidentID                 string                     `json:"incident_id"`
	Hypotheses                 []Hypothesis               `json:"hypotheses"`
	EvidenceRefs               []string                   `json:"evidence_refs"`
	ConfidenceLabels           []ConfidenceLabel          `json:"confidence_labels"`
	NotificationRecommendation NotificationRecommendation `json:"notification_recommendation"`
	CandidateRunbookIDs        []string                   `json:"candidate_runbook_ids"`
	MissingEvidence            []string                   `json:"missing_evidence"`
}

// Validate verifies the AnalysisResult contract.
func (a AnalysisResult) Validate() error {
	if err := validateVersion(a.SchemaVersion); err != nil {
		return err
	}
	if err := required("incident_id", a.IncidentID); err != nil {
		return err
	}
	if len(a.Hypotheses) == 0 || len(a.Hypotheses) > maxReferenceCount || len(a.EvidenceRefs) > maxReferenceCount || len(a.ConfidenceLabels) > maxReferenceCount || len(a.CandidateRunbookIDs) > maxReferenceCount || len(a.MissingEvidence) > maxReferenceCount || !oneOf(string(a.NotificationRecommendation), string(NotificationNone), string(NotificationNotify), string(NotificationPage)) {
		return invalid("analysis result")
	}
	for _, hypothesis := range a.Hypotheses {
		if err := required("hypothesis summary", hypothesis.Summary); err != nil {
			return err
		}
		if len(hypothesis.EvidenceRefs) > maxReferenceCount {
			return invalid("hypothesis evidence refs")
		}
	}
	for _, label := range a.ConfidenceLabels {
		if !oneOf(string(label), string(ConfidenceLow), string(ConfidenceMedium), string(ConfidenceHigh)) {
			return invalid("confidence label")
		}
	}
	return nil
}

// RecoveryCommand is a durable request to execute one typed runbook action.
type RecoveryCommand struct {
	SchemaVersion  string               `json:"schema_version"`
	CommandID      string               `json:"command_id"`
	IncidentID     string               `json:"incident_id"`
	RunbookID      string               `json:"runbook_id"`
	RunbookDigest  string               `json:"runbook_digest"`
	TargetID       string               `json:"target_id"`
	ActionIndex    int                  `json:"action_index"`
	RiskTier       RiskTier             `json:"risk_tier"`
	ApprovalID     string               `json:"approval_id,omitempty"`
	IssuedAt       time.Time            `json:"issued_at"`
	ExpiresAt      time.Time            `json:"expires_at"`
	IdempotencyKey string               `json:"idempotency_key"`
	State          RecoveryCommandState `json:"state"`
}

// Validate verifies the RecoveryCommand state and time invariants.
func (r RecoveryCommand) Validate() error {
	if err := validateVersion(r.SchemaVersion); err != nil {
		return err
	}
	if err := required("command_id", r.CommandID); err != nil {
		return err
	}
	if !validRecoveryState(r.State) || r.ActionIndex < 0 || r.IssuedAt.IsZero() || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(r.IssuedAt) {
		return invalid("recovery command")
	}
	return nil
}

// CanTransitionTo reports whether r may move to next.
func (r RecoveryCommandState) CanTransitionTo(next RecoveryCommandState) bool {
	switch r {
	case RecoveryPending:
		return next == RecoveryApproved || next == RecoveryDenied || next == RecoveryExpired
	case RecoveryApproved:
		return next == RecoveryExecuting || next == RecoveryExpired
	case RecoveryExecuting:
		return next == RecoverySucceeded || next == RecoveryFailed
	default:
		return false
	}
}

// ValidateTransition rejects a recovery command transition outside the lifecycle.
func (r RecoveryCommandState) ValidateTransition(next RecoveryCommandState) error {
	if !r.CanTransitionTo(next) {
		return ErrInvalidStateTransition
	}
	return nil
}

// Approval records a human decision for exactly one recovery command.
type Approval struct {
	SchemaVersion    string           `json:"schema_version"`
	ApprovalID       string           `json:"approval_id"`
	CommandID        string           `json:"command_id"`
	Decision         ApprovalDecision `json:"decision"`
	ApproverIdentity string           `json:"approver_identity"`
	Reason           string           `json:"reason"`
	CreatedAt        time.Time        `json:"created_at"`
	ExpiresAt        time.Time        `json:"expires_at"`
}

// AuditEvent is an append-only digest-linked record without raw secret or
// evidence fields.
type AuditEvent struct {
	SchemaVersion  string    `json:"schema_version"`
	EventID        string    `json:"event_id"`
	AggregateType  string    `json:"aggregate_type"`
	AggregateID    string    `json:"aggregate_id"`
	ActorIdentity  string    `json:"actor_identity"`
	Action         string    `json:"action"`
	Result         string    `json:"result"`
	ReasonCode     string    `json:"reason_code"`
	OccurredAt     time.Time `json:"occurred_at"`
	PreviousDigest string    `json:"previous_digest,omitempty"`
	Digest         string    `json:"digest"`
}

// ReportAction is a safe summary of a recovery action in an incident report.
type ReportAction struct {
	CommandID  string     `json:"command_id"`
	ActionType ActionType `json:"action_type"`
	Result     string     `json:"result"`
}

// IncidentReport is a secret-free, versioned incident summary for delivery.
type IncidentReport struct {
	SchemaVersion                 string         `json:"schema_version"`
	ReportID                      string         `json:"report_id"`
	IncidentID                    string         `json:"incident_id"`
	Hypotheses                    []Hypothesis   `json:"hypotheses"`
	EvidenceRefs                  []string       `json:"evidence_refs"`
	Actions                       []ReportAction `json:"actions"`
	Approvals                     []string       `json:"approvals"`
	VerificationResult            string         `json:"verification_result"`
	PreventionRecommendations     []string       `json:"prevention_recommendations"`
	PostmortemDraft               string         `json:"postmortem_draft"`
	RunbookImprovementSuggestions []string       `json:"runbook_improvement_suggestions"`
	DeliveryStatus                DeliveryState  `json:"delivery_status"`
}

// DeliveryQueueItem is the shared queue contract for lifecycle events and
// incident reports. It intentionally has no report_id-only branch.
type DeliveryQueueItem struct {
	SchemaVersion  string              `json:"schema_version"`
	DeliveryID     string              `json:"delivery_id"`
	PayloadType    DeliveryPayloadType `json:"payload_type"`
	PayloadRef     string              `json:"payload_ref"`
	WebhookID      string              `json:"webhook_id"`
	DestinationRef string              `json:"destination_ref"`
	AttemptCount   int                 `json:"attempt_count"`
	NextAttemptAt  time.Time           `json:"next_attempt_at"`
	ExpiresAt      time.Time           `json:"expires_at"`
	State          DeliveryState       `json:"state"`
}

// Validate verifies the DeliveryQueueItem contract.
func (d DeliveryQueueItem) Validate() error {
	if err := validateVersion(d.SchemaVersion); err != nil {
		return err
	}
	if err := required("delivery_id", d.DeliveryID); err != nil {
		return err
	}
	if err := required("payload_ref", d.PayloadRef); err != nil {
		return err
	}
	if err := required("webhook_id", d.WebhookID); err != nil {
		return err
	}
	if err := required("destination_ref", d.DestinationRef); err != nil {
		return err
	}
	if (d.PayloadType != DeliveryPayloadLifecycleEvent && d.PayloadType != DeliveryPayloadIncidentReport) || d.AttemptCount < 0 || d.NextAttemptAt.IsZero() || d.ExpiresAt.IsZero() || !d.ExpiresAt.After(d.NextAttemptAt) || !validDeliveryState(d.State) {
		return invalid("delivery queue item")
	}
	return nil
}

// LifecycleEvent is a secret-free event payload reference.
type LifecycleEvent struct {
	SchemaVersion string             `json:"schema_version"`
	EventID       string             `json:"event_id"`
	EventType     LifecycleEventType `json:"event_type"`
	IncidentID    string             `json:"incident_id"`
	OccurredAt    time.Time          `json:"occurred_at"`
	ReasonCode    string             `json:"reason_code"`
}

// Validate verifies the LifecycleEvent contract.
func (l LifecycleEvent) Validate() error {
	if err := validateVersion(l.SchemaVersion); err != nil {
		return err
	}
	if err := required("event_id", l.EventID); err != nil {
		return err
	}
	if err := required("incident_id", l.IncidentID); err != nil {
		return err
	}
	if !validLifecycleEvent(l.EventType) || l.OccurredAt.IsZero() {
		return invalid("lifecycle event")
	}
	return nil
}

// WebhookEnvelope is the secret-free payload envelope used before later tasks
// add Standard Webhooks signing.
type WebhookEnvelope struct {
	SchemaVersion string             `json:"schema_version"`
	EventID       string             `json:"event_id"`
	EventType     LifecycleEventType `json:"event_type"`
	OccurredAt    time.Time          `json:"occurred_at"`
	PayloadRef    string             `json:"payload_ref"`
}

// Validate verifies the WebhookEnvelope contract.
func (w WebhookEnvelope) Validate() error {
	if err := validateVersion(w.SchemaVersion); err != nil {
		return err
	}
	if err := required("event_id", w.EventID); err != nil {
		return err
	}
	if err := required("payload_ref", w.PayloadRef); err != nil {
		return err
	}
	if !validLifecycleEvent(w.EventType) || w.OccurredAt.IsZero() {
		return invalid("webhook envelope")
	}
	return nil
}

func validateVersion(version string) error {
	if version != SchemaVersionV1 {
		return invalid("schema version")
	}
	return nil
}

func required(name, value string) error {
	if value == "" {
		return fmt.Errorf("%w: missing %s", ErrInvalidContract, name)
	}
	return nil
}

func invalid(name string) error {
	return fmt.Errorf("%w: %s", ErrInvalidContract, name)
}

func oneOf(value string, values ...string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func validIncidentState(state IncidentState) bool {
	return oneOf(string(state), string(IncidentOpen), string(IncidentAnalyzing), string(IncidentAwaitingApproval), string(IncidentRecovering), string(IncidentStabilizing), string(IncidentClosed), string(IncidentFailed))
}

func terminalIncident(state IncidentState) bool {
	return state == IncidentClosed || state == IncidentFailed
}

func validRecoveryState(state RecoveryCommandState) bool {
	return oneOf(string(state), string(RecoveryPending), string(RecoveryApproved), string(RecoveryExecuting), string(RecoverySucceeded), string(RecoveryFailed), string(RecoveryDenied), string(RecoveryExpired))
}

func validDeliveryState(state DeliveryState) bool {
	return oneOf(string(state), string(DeliveryPending), string(DeliveryDelivered), string(DeliveryExpired), string(DeliveryFailed))
}

func validLifecycleEvent(eventType LifecycleEventType) bool {
	return oneOf(string(eventType), string(LifecycleIncidentConfirmed), string(LifecycleAnalysisUnavailable), string(LifecyclePolicyDenied), string(LifecycleApprovalRequested), string(LifecycleRecoveryStarted), string(LifecycleIncidentClosed), string(LifecycleIncidentFailed))
}
