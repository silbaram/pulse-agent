// Package evidence bounds and redacts local evidence before any downstream use.
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/telemetry"
)

var (
	// ErrInvalidOptions indicates unsafe collector limits or dependencies.
	ErrInvalidOptions = errors.New("invalid evidence collector options")
	// ErrRedactionFailed indicates that untrusted input could not be safely redacted.
	ErrRedactionFailed = errors.New("evidence redaction failed")

	sensitiveLabel      = `(?:[a-z0-9_-]*?(?:api[_-]?key|token|password|secret|credential|private[_-]?key)|customer[_-]?(?:id|name|email|phone))`
	secretValuePattern  = regexp.MustCompile(`(?i)\b(` + sensitiveLabel + `)\b\s*([:=])\s*([^\s,;]+)`)
	secretMarkerPattern = regexp.MustCompile(`(?i)\b` + sensitiveLabel + `\b\s*[:=]\s*(?:$|[,;])`)
	bearerPattern       = regexp.MustCompile(`(?i)\bauthorization\s*:\s*bearer\s+\S+`)
	emailPattern        = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	phonePattern        = regexp.MustCompile(`\b(?:\+?\d{1,3}[ -]?)?(?:\d{2,4}[ -]?)?\d{3,4}[ -]\d{4}\b`)
)

// Record is one local collector record before redaction.
type Record struct {
	At     time.Time
	Fields map[string]string
}

// Options configures a bounded collector.
type Options struct {
	AllowedFields []string
	MaxLines      int
	MaxBytes      int
	Retention     time.Duration
	Clock         func() time.Time
	NewEvidenceID func() (string, error)
	// Telemetry records bounded redaction measurements when configured.
	Telemetry *telemetry.Recorder
}

// Result contains only redacted evidence and its durable reference.
type Result struct {
	Reference       contract.EvidenceRef
	Content         string
	RedactionFailed bool
}

// Collector applies time, field, line, byte and redaction boundaries.
type Collector struct {
	allowed   map[string]struct{}
	maxLines  int
	maxBytes  int
	retention time.Duration
	clock     func() time.Time
	newID     func() (string, error)
	telemetry *telemetry.Recorder
}

// NewCollector validates all bounds before accepting any local evidence.
func NewCollector(options Options) (*Collector, error) {
	if len(options.AllowedFields) == 0 || options.MaxLines < 1 || options.MaxBytes < 1 ||
		options.Retention < time.Minute || options.Clock == nil || options.NewEvidenceID == nil {
		return nil, ErrInvalidOptions
	}

	allowed := make(map[string]struct{}, len(options.AllowedFields))
	for _, field := range options.AllowedFields {
		if field == "" {
			return nil, ErrInvalidOptions
		}
		allowed[field] = struct{}{}
	}

	return &Collector{
		allowed:   allowed,
		maxLines:  options.MaxLines,
		maxBytes:  options.MaxBytes,
		retention: options.Retention,
		clock:     options.Clock,
		newID:     options.NewEvidenceID,
		telemetry: options.Telemetry,
	}, nil
}

// Collect creates a bounded redacted evidence reference for the requested range.
func (c *Collector) Collect(source, profile string, start, end time.Time, records []Record) (result Result, resultErr error) {
	startedAt := time.Now()
	defer func() {
		c.recordRedaction(resultErr, time.Since(startedAt))
	}()
	if c == nil || source == "" || profile == "" || start.IsZero() || end.IsZero() || end.Before(start) {
		return Result{}, ErrInvalidOptions
	}

	lines := make([]string, 0, c.maxLines)
	size := 0
	for _, record := range records {
		if record.At.Before(start) || record.At.After(end) {
			continue
		}
		if len(lines) == c.maxLines {
			break
		}

		line, ok := c.redactRecord(record.Fields)
		if !ok {
			return Result{RedactionFailed: true}, ErrRedactionFailed
		}
		if line == "" {
			continue
		}

		additionalBytes := len(line)
		if len(lines) > 0 {
			additionalBytes++ // newline separator
		}
		if size+additionalBytes > c.maxBytes {
			break
		}

		lines = append(lines, line)
		size += additionalBytes
	}

	content := strings.Join(lines, "\n")
	id, err := c.newID()
	if err != nil || id == "" {
		return Result{}, ErrInvalidOptions
	}
	now := c.clock()
	if now.IsZero() {
		return Result{}, ErrInvalidOptions
	}

	digest := sha256.Sum256([]byte(content))
	return Result{
		Reference: contract.EvidenceRef{
			SchemaVersion:    contract.SchemaVersionV1,
			EvidenceID:       id,
			SourceType:       source,
			CollectorID:      "local",
			Start:            start.UTC(),
			End:              end.UTC(),
			RedactionProfile: profile,
			Digest:           hex.EncodeToString(digest[:]),
			ByteCount:        len(content),
			RetentionUntil:   now.Add(c.retention),
		},
		Content: content,
	}, nil
}

func (c *Collector) recordRedaction(collectErr error, duration time.Duration) {
	if c == nil || c.telemetry == nil {
		return
	}
	result, reason := telemetry.ResultSuccess, telemetry.ReasonAccepted
	if collectErr != nil {
		result, reason = telemetry.ResultFailure, telemetry.ReasonInternal
		if errors.Is(collectErr, ErrRedactionFailed) || errors.Is(collectErr, ErrInvalidOptions) {
			result, reason = telemetry.ResultRejected, telemetry.ReasonInvalid
		}
	}
	event, err := telemetry.NewEvent(telemetry.ComponentEvidence, telemetry.OperationRedact, result, reason, duration)
	if err == nil {
		c.telemetry.RecordBestEffort(context.Background(), event)
	}
}

func (c *Collector) redactRecord(fields map[string]string) (string, bool) {
	values := make([]string, 0, len(c.allowed))
	for key := range c.allowed {
		value, present := fields[key]
		if !present {
			continue
		}
		redacted, ok := redact(value)
		if !ok {
			return "", false
		}
		values = append(values, key+"="+redacted)
	}
	sort.Strings(values)
	return strings.Join(values, " "), true
}

func redact(value string) (string, bool) {
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 || secretMarkerPattern.MatchString(value) {
		return "", false
	}

	redacted := secretValuePattern.ReplaceAllString(value, "${1}${2}[REDACTED]")
	redacted = bearerPattern.ReplaceAllString(redacted, "Authorization: Bearer [REDACTED]")
	redacted = emailPattern.ReplaceAllString(redacted, "[REDACTED_EMAIL]")
	redacted = phonePattern.ReplaceAllString(redacted, "[REDACTED_PHONE]")
	return redacted, true
}
