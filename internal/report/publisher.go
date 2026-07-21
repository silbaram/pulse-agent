package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/delivery"
	"pulse-agent/internal/lifecycle"
	"pulse-agent/internal/store"
	"pulse-agent/internal/telemetry"
)

const (
	defaultDeliveryTTL      = 24 * time.Hour
	maxDeliveryTTL          = 30 * 24 * time.Hour
	maxReportIDLength       = 128
	maxEvidenceRefLength    = 128
	maxShortTextLength      = 512
	maxPostmortemTextLength = 4096
	reportRecordPrefix      = "report/"
)

var secretPattern = regexp.MustCompile(`(?i)\b(?:api[_-]?key|token|password|secret|authorization)\b\s*(?:[:=]|bearer\s+)\s*[^\s,;]+`)

// Clock supplies deterministic report timestamps.
type Clock interface {
	// Now returns the current report time.
	Now() time.Time
}

// ClockFunc adapts a function to the Clock interface.
type ClockFunc func() time.Time

// Now returns the time supplied by f.
func (f ClockFunc) Now() time.Time { return f() }

// Options configures the report publisher and its shared delivery lifetime.
type Options struct {
	// State owns persisted terminal reports and must be shared with Queue.
	State *store.Store
	// Queue accepts a report payload and its delivery item in one local transaction.
	Queue *delivery.Dispatcher
	// Lifecycle publishes the paired terminal lifecycle event through Queue.
	Lifecycle *lifecycle.Publisher
	// DestinationRef selects one configured outbound webhook destination.
	DestinationRef string
	// Clock supplies deterministic fallback timestamps.
	Clock Clock
	// DeliveryTTL bounds how long a terminal report may remain pending. Zero defaults to one day.
	DeliveryTTL time.Duration
	// Telemetry records bounded terminal publication outcomes after local durability succeeds.
	Telemetry *telemetry.Recorder
}

// Publisher composes terminal reports and pairs each with a terminal lifecycle
// event. It performs no HTTP calls, so delivery retries and expiry cannot
// change a completed recovery or incident state.
type Publisher struct {
	state          *store.Store
	queue          *delivery.Dispatcher
	lifecycle      *lifecycle.Publisher
	destinationRef string
	clock          Clock
	deliveryTTL    time.Duration
	telemetry      *telemetry.Recorder

	mu sync.Mutex
}

// Input is the already-redacted terminal context for one incident. The caller
// must reuse IdempotencyKey for a repeated terminal transition.
type Input struct {
	IncidentID                    string
	TerminalState                 contract.IncidentState
	IdempotencyKey                string
	OccurredAt                    time.Time
	Analysis                      *contract.AnalysisResult
	AnalysisUnavailable           bool
	EvidenceRefs                  []string
	Actions                       []contract.ReportAction
	ApprovalIDs                   []string
	VerificationResult            string
	PreventionRecommendations     []string
	PostmortemDraft               string
	RunbookImprovementSuggestions []string
}

// Result identifies both durable terminal payloads and their delivery items.
type Result struct {
	Report             contract.IncidentReport
	ReportQueueItem    contract.DeliveryQueueItem
	LifecycleQueueItem contract.DeliveryQueueItem
	Duplicate          bool
}

// New validates dependencies and returns a terminal report publisher.
func New(options Options) (*Publisher, error) {
	ttl := options.DeliveryTTL
	if ttl == 0 {
		ttl = defaultDeliveryTTL
	}
	if options.State == nil || options.Queue == nil || !options.Queue.UsesStore(options.State) || options.Lifecycle == nil || options.Clock == nil || !validIdentifier(options.DestinationRef, maxReportIDLength) || ttl < time.Second || ttl > maxDeliveryTTL {
		return nil, ErrInvalidOptions
	}
	return &Publisher{
		state:          options.State,
		queue:          options.Queue,
		lifecycle:      options.Lifecycle,
		destinationRef: options.DestinationRef,
		clock:          options.Clock,
		deliveryTTL:    ttl,
		telemetry:      options.Telemetry,
	}, nil
}

// PublishTerminal persists a report before publishing its paired terminal
// lifecycle event. A retry with the same idempotency key completes any missing
// paired event without creating another report delivery item.
func (p *Publisher) PublishTerminal(ctx context.Context, input Input) (result Result, err error) {
	startedAt := time.Now()
	defer func() { p.recordPublication(ctx, startedAt, result, err) }()
	if p == nil || ctx == nil {
		return Result{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	report, event, err := p.compose(input)
	if err != nil {
		return Result{}, err
	}
	document, err := json.Marshal(report)
	if err != nil {
		return Result{}, fmt.Errorf("encode incident report: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	existing, found, err := p.load(report.ReportID)
	if err != nil {
		return Result{}, err
	}
	result = Result{Report: report, Duplicate: found}
	if found {
		if !sameReport(existing, report) {
			return Result{}, ErrInvalidInput
		}
		result.Report = existing
	} else {
		item, enqueueErr := p.queue.EnqueueWithMutation(delivery.EnqueueRequest{
			PayloadType:    contract.DeliveryPayloadIncidentReport,
			PayloadRef:     report.ReportID,
			DestinationRef: p.destinationRef,
			ExpiresAt:      event.OccurredAt.Add(p.deliveryTTL),
		}, func(transaction *store.Tx) error {
			key := reportRecordKey(report.ReportID)
			if _, present, getErr := transaction.Get(store.BucketIncidentReports, key); getErr != nil {
				return getErr
			} else if present {
				return errReportExists
			}
			return transaction.Put(store.BucketIncidentReports, key, document)
		})
		if errors.Is(enqueueErr, errReportExists) {
			existing, exists, loadErr := p.load(report.ReportID)
			if loadErr != nil {
				return Result{}, loadErr
			}
			if !exists || !sameReport(existing, report) {
				return Result{}, ErrCorruptPayload
			}
			result.Report, result.Duplicate = existing, true
		} else if enqueueErr != nil {
			return Result{}, fmt.Errorf("enqueue incident report: %w", enqueueErr)
		} else {
			result.ReportQueueItem = item
		}
	}

	lifecycleResult, lifecycleErr := p.lifecycle.Publish(ctx, event)
	if lifecycleErr != nil {
		return result, fmt.Errorf("enqueue terminal lifecycle event: %w", lifecycleErr)
	}
	result.LifecycleQueueItem = lifecycleResult.QueueItem
	result.Duplicate = result.Duplicate && lifecycleResult.Duplicate
	return result, nil
}

func (p *Publisher) recordPublication(ctx context.Context, startedAt time.Time, result Result, publicationErr error) {
	if p == nil || p.telemetry == nil {
		return
	}
	telemetryResult, reason := telemetry.ResultSuccess, telemetry.ReasonAccepted
	if publicationErr != nil {
		switch {
		case errors.Is(publicationErr, ErrInvalidInput):
			telemetryResult, reason = telemetry.ResultRejected, telemetry.ReasonInvalid
		case errors.Is(publicationErr, context.DeadlineExceeded):
			telemetryResult, reason = telemetry.ResultUnavailable, telemetry.ReasonTimeout
		case errors.Is(publicationErr, context.Canceled):
			telemetryResult, reason = telemetry.ResultUnavailable, telemetry.ReasonUnavailable
		default:
			telemetryResult, reason = telemetry.ResultFailure, telemetry.ReasonInternal
		}
	} else if result.Duplicate {
		reason = telemetry.ReasonDuplicate
	}
	event, eventErr := telemetry.NewEvent(telemetry.ComponentReport, telemetry.OperationPublish, telemetryResult, reason, time.Since(startedAt))
	if eventErr == nil {
		p.telemetry.RecordBestEffort(ctx, event)
	}
}

// StableReportID derives an opaque stable report identity without retaining an
// incident's idempotency key outside its digest.
func StableReportID(incidentID string, terminalState contract.IncidentState, idempotencyKey string) string {
	sum := sha256.Sum256([]byte(string(terminalState) + "\x00" + incidentID + "\x00" + idempotencyKey))
	return "report-" + hex.EncodeToString(sum[:])
}

func (p *Publisher) compose(input Input) (contract.IncidentReport, lifecycle.Input, error) {
	occurredAt := input.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = p.clock.Now()
	}
	if !validIdentifier(input.IncidentID, maxReportIDLength) || !validIdentifier(input.IdempotencyKey, maxReportIDLength) || (input.TerminalState != contract.IncidentClosed && input.TerminalState != contract.IncidentFailed) || occurredAt.IsZero() || !validEvidenceRefs(input.EvidenceRefs) || !validActions(input.Actions) || !validApprovalIDs(input.ApprovalIDs) || !safeShortText(input.VerificationResult) || !validTextList(input.PreventionRecommendations) || !validPostmortem(input.PostmortemDraft) || !validTextList(input.RunbookImprovementSuggestions) {
		return contract.IncidentReport{}, lifecycle.Input{}, ErrInvalidInput
	}
	hypotheses, evidenceRefs, err := composeHypotheses(input)
	if err != nil {
		return contract.IncidentReport{}, lifecycle.Input{}, err
	}
	prevention := cloneOrDefault(input.PreventionRecommendations, "Review recurrence controls for this incident class.")
	postmortem := input.PostmortemDraft
	if postmortem == "" {
		postmortem = "Terminal incident summary recorded for " + input.IncidentID + "."
	}
	improvements := cloneOrDefault(input.RunbookImprovementSuggestions, "Review runbook coverage for this incident class.")
	report := contract.IncidentReport{
		SchemaVersion:                 contract.SchemaVersionV1,
		ReportID:                      StableReportID(input.IncidentID, input.TerminalState, input.IdempotencyKey),
		IncidentID:                    input.IncidentID,
		Hypotheses:                    hypotheses,
		EvidenceRefs:                  evidenceRefs,
		Actions:                       cloneActions(input.Actions),
		Approvals:                     append([]string{}, input.ApprovalIDs...),
		VerificationResult:            input.VerificationResult,
		PreventionRecommendations:     prevention,
		PostmortemDraft:               postmortem,
		RunbookImprovementSuggestions: improvements,
		DeliveryStatus:                contract.DeliveryPending,
	}
	if err := report.Validate(); err != nil || !validReportContent(report) {
		return contract.IncidentReport{}, lifecycle.Input{}, ErrInvalidInput
	}
	eventType := contract.LifecycleIncidentClosed
	reasonCode := "terminal_closed"
	if input.TerminalState == contract.IncidentFailed {
		eventType, reasonCode = contract.LifecycleIncidentFailed, "terminal_failed"
	}
	return report, lifecycle.Input{
		EventID:      lifecycle.StableEventID(eventType, input.IncidentID, input.IdempotencyKey),
		EventType:    eventType,
		IncidentID:   input.IncidentID,
		ReasonCode:   reasonCode,
		EvidenceRefs: append([]string(nil), evidenceRefs...),
		OccurredAt:   occurredAt.UTC(),
	}, nil
}

func (p *Publisher) load(reportID string) (contract.IncidentReport, bool, error) {
	var (
		document []byte
		found    bool
	)
	err := p.state.View(func(transaction *store.Tx) error {
		var readErr error
		document, found, readErr = transaction.Get(store.BucketIncidentReports, reportRecordKey(reportID))
		return readErr
	})
	if err != nil {
		return contract.IncidentReport{}, false, fmt.Errorf("load incident report: %w", err)
	}
	if !found {
		return contract.IncidentReport{}, false, nil
	}
	report, err := decodeReport(document)
	if err != nil || report.ReportID != reportID {
		return contract.IncidentReport{}, false, ErrCorruptPayload
	}
	return report, true, nil
}

func composeHypotheses(input Input) ([]contract.Hypothesis, []string, error) {
	references := append([]string{}, input.EvidenceRefs...)
	if input.Analysis == nil {
		if !input.AnalysisUnavailable {
			return nil, nil, ErrInvalidInput
		}
		return []contract.Hypothesis{{Summary: "Analysis unavailable; root cause not determined.", EvidenceRefs: append([]string{}, references...)}}, references, nil
	}
	if input.AnalysisUnavailable || input.Analysis.Validate() != nil || input.Analysis.IncidentID != input.IncidentID || !validHypotheses(input.Analysis.Hypotheses) || !validEvidenceRefs(input.Analysis.EvidenceRefs) {
		return nil, nil, ErrInvalidInput
	}
	for _, reference := range input.Analysis.EvidenceRefs {
		if !contains(references, reference) {
			references = append(references, reference)
		}
	}
	if !validEvidenceRefs(references) {
		return nil, nil, ErrInvalidInput
	}
	return cloneHypotheses(input.Analysis.Hypotheses), references, nil
}

func decodeReport(document []byte) (contract.IncidentReport, error) {
	report, err := contract.Decode(document, contract.DecodeOptions[contract.IncidentReport]{
		MaxBytes:      contract.MaxDocumentBytes,
		SchemaVersion: contract.SchemaVersionV1,
		Validate:      func(value contract.IncidentReport) error { return value.Validate() },
	})
	if err != nil || !validIdentifier(report.ReportID, maxReportIDLength) || !validIdentifier(report.IncidentID, maxReportIDLength) || !validReportContent(report) {
		return contract.IncidentReport{}, ErrCorruptPayload
	}
	return report, nil
}

func reportRecordKey(reportID string) string {
	sum := sha256.Sum256([]byte(reportID))
	return reportRecordPrefix + hex.EncodeToString(sum[:])
}

func validReportContent(report contract.IncidentReport) bool {
	return validEvidenceRefs(report.EvidenceRefs) && validHypotheses(report.Hypotheses) && validActions(report.Actions) && validApprovalIDs(report.Approvals) && safeShortText(report.VerificationResult) && validTextList(report.PreventionRecommendations) && validPostmortem(report.PostmortemDraft) && validTextList(report.RunbookImprovementSuggestions)
}

func validIdentifier(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

func validEvidenceRefs(references []string) bool {
	if len(references) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(references))
	for _, reference := range references {
		if !validIdentifier(reference, maxEvidenceRefLength) {
			return false
		}
		for _, character := range reference {
			if !(unicode.IsLetter(character) || unicode.IsDigit(character) || character == '-' || character == '_' || character == '.' || character == ':') {
				return false
			}
		}
		if _, duplicate := seen[reference]; duplicate {
			return false
		}
		seen[reference] = struct{}{}
	}
	return true
}

func validHypotheses(hypotheses []contract.Hypothesis) bool {
	if len(hypotheses) == 0 || len(hypotheses) > 64 {
		return false
	}
	for _, hypothesis := range hypotheses {
		if !safeShortText(hypothesis.Summary) || !validEvidenceRefs(hypothesis.EvidenceRefs) {
			return false
		}
	}
	return true
}

func validActions(actions []contract.ReportAction) bool {
	if len(actions) > 64 {
		return false
	}
	for _, action := range actions {
		if !validIdentifier(action.CommandID, maxReportIDLength) || (action.ActionType != contract.ActionDockerContainerRestart && action.ActionType != contract.ActionDockerComposeServiceRestart) || !safeShortText(action.Result) {
			return false
		}
	}
	return true
}

func validApprovalIDs(approvalIDs []string) bool {
	if len(approvalIDs) > 64 {
		return false
	}
	for _, approvalID := range approvalIDs {
		if !validIdentifier(approvalID, maxReportIDLength) {
			return false
		}
	}
	return true
}

func validTextList(values []string) bool {
	if len(values) > 64 {
		return false
	}
	for _, value := range values {
		if !safeShortText(value) {
			return false
		}
	}
	return true
}

func validPostmortem(value string) bool {
	return value == "" || safeText(value, maxPostmortemTextLength)
}

func safeShortText(value string) bool {
	return safeText(value, maxShortTextLength)
}

func safeText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00') && !secretPattern.MatchString(value)
}

func cloneHypotheses(values []contract.Hypothesis) []contract.Hypothesis {
	cloned := make([]contract.Hypothesis, 0, len(values))
	for _, value := range values {
		cloned = append(cloned, contract.Hypothesis{Summary: value.Summary, EvidenceRefs: append([]string{}, value.EvidenceRefs...)})
	}
	return cloned
}

func cloneActions(values []contract.ReportAction) []contract.ReportAction {
	return append([]contract.ReportAction{}, values...)
}

func cloneOrDefault(values []string, fallback string) []string {
	if len(values) == 0 {
		return []string{fallback}
	}
	return append([]string{}, values...)
}

func sameReport(left, right contract.IncidentReport) bool {
	leftDocument, leftErr := json.Marshal(left)
	rightDocument, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftDocument) == string(rightDocument)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
