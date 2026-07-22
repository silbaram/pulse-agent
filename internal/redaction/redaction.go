// Package redaction provides deterministic secret and PII detection for
// boundaries that must never emit raw sensitive values.
package redaction

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

const sensitiveLabel = `(?:[a-z0-9_-]*?(?:api[_-]?key|token|password|secret|credential|private[_-]?key)|customer[_-]?(?:id|name|email|phone))`

var (
	labeledValuePattern  = regexp.MustCompile(`(?i)\b(` + sensitiveLabel + `)\b\s*([:=])\s*([^\s,;]+)`)
	emptyLabelPattern    = regexp.MustCompile(`(?i)\b` + sensitiveLabel + `\b\s*[:=]\s*(?:$|[,;])`)
	authorizationPattern = regexp.MustCompile(`(?i)\bauthorization\s*[:=]\s*((?:bearer\s+)?)([^\s,;]+)`)
	emailPattern         = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	phonePattern         = regexp.MustCompile(`\b(?:\+?\d{1,3}[ -]?)?(?:\d{2,4}[ -]?)?\d{3,4}[ -]\d{4}\b`)
	opaqueTokenPattern   = regexp.MustCompile(`(?i)\b(?:ghp_[A-Z0-9]{20,}|github_pat_[A-Z0-9_]{20,}|xox[baprs]-[A-Z0-9-]{10,}|sk[-_][A-Z0-9_-]{8,}|AKIA[A-Z0-9]{16}|AIza[A-Z0-9_-]{20,}|whsec_[A-Z0-9_+/=-]{16,})\b`)
	unknownTokenPattern  = regexp.MustCompile(`(?i)\b[A-Z][A-Z0-9_-]{2,24}[.~][A-Z0-9_-]{20,}\b`)
)

// Redact replaces recognized secret and PII forms. It returns false when the
// input is malformed or still contains a sensitive value after replacement.
func Redact(value string) (string, bool) {
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 || emptyLabelPattern.MatchString(value) {
		return "", false
	}

	redacted := authorizationPattern.ReplaceAllString(value, "Authorization: ${1}[REDACTED]")
	redacted = labeledValuePattern.ReplaceAllString(redacted, "${1}${2}[REDACTED]")
	redacted = emailPattern.ReplaceAllString(redacted, "[REDACTED_EMAIL]")
	redacted = phonePattern.ReplaceAllString(redacted, "[REDACTED_PHONE]")
	redacted = opaqueTokenPattern.ReplaceAllString(redacted, "[REDACTED_TOKEN]")
	if ContainsSensitive(redacted) {
		return "", false
	}
	return redacted, true
}

// ContainsSensitive reports whether value is malformed or contains a raw
// recognized secret, PII value, or an unrecognized high-entropy token form.
// Canonical redaction markers are safe and do not count as sensitive values.
func ContainsSensitive(value string) bool {
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 || emptyLabelPattern.MatchString(value) {
		return true
	}
	for _, match := range labeledValuePattern.FindAllStringSubmatch(value, -1) {
		if len(match) != 4 || !isMarker(match[3]) {
			return true
		}
	}
	for _, match := range authorizationPattern.FindAllStringSubmatch(value, -1) {
		if len(match) != 3 || !isMarker(match[2]) {
			return true
		}
	}
	return emailPattern.MatchString(value) || phonePattern.MatchString(value) || opaqueTokenPattern.MatchString(value) || unknownTokenPattern.MatchString(value)
}

func isMarker(value string) bool {
	switch value {
	case "[REDACTED]", "[REDACTED_EMAIL]", "[REDACTED_PHONE]", "[REDACTED_TOKEN]":
		return true
	default:
		return false
	}
}
