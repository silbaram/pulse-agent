package alert

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
	"pulse-agent/internal/target"
	"pulse-agent/internal/webhook"
)

const (
	alertAuthenticationCorpusSize = 18
	alertDuplicateCorpusSize      = 2
	alertAuthorizationCorpusSize  = alertAuthenticationCorpusSize + alertDuplicateCorpusSize
)

func TestIngress_AuthenticationCorpusRejectsBeforeNormalization(t *testing.T) {
	now := time.Date(2026, time.July, 22, 0, 0, 0, 0, time.UTC)
	keyring, err := webhook.NewKeyring("whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")
	if err != nil {
		t.Fatalf("webhook.NewKeyring() error = %v", err)
	}
	malformed := []byte("{")
	zeroDigest := base64.StdEncoding.EncodeToString(make([]byte, 32))
	tests := []struct {
		name    string
		prepare func(t *testing.T, id string) (webhook.Headers, []byte)
		want    error
		reason  string
	}{
		{name: "missing webhook ID", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) { headers.ID = "" }), want: webhook.ErrInvalidHeaders, reason: "invalid_signature"},
		{name: "webhook ID delimiter", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) { headers.ID = "message.invalid" }), want: webhook.ErrInvalidHeaders, reason: "invalid_signature"},
		{name: "webhook ID leading space", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) { headers.ID = " message" }), want: webhook.ErrInvalidHeaders, reason: "invalid_signature"},
		{name: "webhook ID newline", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) { headers.ID = "message\nforged" }), want: webhook.ErrInvalidHeaders, reason: "invalid_signature"},
		{name: "webhook ID oversized", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) { headers.ID = strings.Repeat("a", 257) }), want: webhook.ErrInvalidHeaders, reason: "invalid_signature"},
		{name: "missing timestamp", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) { headers.Timestamp = "" }), want: webhook.ErrInvalidHeaders, reason: "invalid_signature"},
		{name: "non-decimal timestamp", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) { headers.Timestamp = "1700000000x" }), want: webhook.ErrInvalidHeaders, reason: "invalid_signature"},
		{name: "past timestamp outside tolerance", prepare: signedSecurityHeaders(keyring, now.Add(-webhook.DefaultTolerance-time.Second), malformed), want: webhook.ErrTimestampOutsideTolerance, reason: "invalid_signature"},
		{name: "future timestamp outside tolerance", prepare: signedSecurityHeaders(keyring, now.Add(webhook.DefaultTolerance+time.Second), malformed), want: webhook.ErrTimestampOutsideTolerance, reason: "invalid_signature"},
		{name: "unsupported v2 signature", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) {
			headers.Signature = strings.Replace(headers.Signature, "v1,", "v2,", 1)
		}), want: webhook.ErrUnsupportedSignatureVersion, reason: "invalid_signature"},
		{name: "unsupported v0 signature", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) {
			headers.Signature = strings.Replace(headers.Signature, "v1,", "v0,", 1)
		}), want: webhook.ErrUnsupportedSignatureVersion, reason: "invalid_signature"},
		{name: "invalid signature base64", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) { headers.Signature = "v1,%%%" }), want: webhook.ErrInvalidHeaders, reason: "invalid_signature"},
		{name: "truncated signature digest", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) { headers.Signature = "v1,AAAA" }), want: webhook.ErrInvalidHeaders, reason: "invalid_signature"},
		{name: "mismatched signature digest", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) { headers.Signature = "v1," + zeroDigest }), want: webhook.ErrSignatureMismatch, reason: "invalid_signature"},
		{name: "mixed unsupported signature version", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) { headers.Signature += " v2,AAAA" }), want: webhook.ErrUnsupportedSignatureVersion, reason: "invalid_signature"},
		{name: "exact body tampering", prepare: func(t *testing.T, id string) (webhook.Headers, []byte) {
			t.Helper()
			headers := signSecurityBody(t, keyring, id, now, []byte(`{"safe":true}`))
			return headers, malformed
		}, want: webhook.ErrSignatureMismatch, reason: "invalid_signature"},
		{name: "missing signature", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) { headers.Signature = "" }), want: webhook.ErrInvalidHeaders, reason: "invalid_signature"},
		{name: "signature leading whitespace", prepare: mutateSecurityHeaders(keyring, now, malformed, func(headers *webhook.Headers) { headers.Signature = " " + headers.Signature }), want: webhook.ErrInvalidHeaders, reason: "invalid_signature"},
	}
	if got := len(tests); got != alertAuthenticationCorpusSize {
		t.Fatalf("alert authentication corpus size = %d, want %d", got, alertAuthenticationCorpusSize)
	}

	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ingress := newTestIngress(t, now, keyring, defaultMaxBodyBytes)
			targets := wrapCountingTargets(t, ingress)
			headers, raw := test.prepare(t, fmt.Sprintf("security-alert-%02d", index))

			_, err := ingress.Accept(context.Background(), headers, raw)
			if !errors.Is(err, test.want) {
				t.Fatalf("Accept() error = %v, want errors.Is(_, %v)", err, test.want)
			}
			if targets.calls != 0 {
				t.Fatalf("TargetSource.Snapshot() calls = %d, want 0 before JSON normalization", targets.calls)
			}
			if countIngressReceipts(t, ingress.state) != 0 {
				t.Fatal("rejected authentication persisted a replay receipt")
			}
			reasons := ingressAuditReasons(t, ingress.state)
			if len(reasons) != 1 || reasons[0] != test.reason {
				t.Fatalf("audit reasons = %#v, want [%q]", reasons, test.reason)
			}
		})
	}
}

func TestIngress_DuplicateIDCorpusRejectsBeforeJSONProcessing(t *testing.T) {
	now := time.Date(2026, time.July, 22, 0, 0, 0, 0, time.UTC)
	keyring, err := webhook.NewKeyring("whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")
	if err != nil {
		t.Fatalf("webhook.NewKeyring() error = %v", err)
	}
	ingress := newTestIngress(t, now, keyring, defaultMaxBodyBytes)
	targets := wrapCountingTargets(t, ingress)
	body := validBody(t, now)
	headers := signSecurityBody(t, keyring, "security-duplicate", now, body)
	if _, err := ingress.Accept(context.Background(), headers, body); err != nil {
		t.Fatalf("seed Accept() error = %v", err)
	}

	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "malformed JSON", raw: []byte("{")},
		{name: "unknown target", raw: validBodyForTarget(t, now, "unknown")},
	}
	if got := len(tests); got != alertDuplicateCorpusSize || alertAuthorizationCorpusSize != 20 {
		t.Fatalf("alert duplicate corpus size = %d, total = %d; want %d and 20", got, alertAuthorizationCorpusSize, alertDuplicateCorpusSize)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			targets.calls = 0
			duplicate := signSecurityBody(t, keyring, headers.ID, now, test.raw)
			if _, err := ingress.Accept(context.Background(), duplicate, test.raw); !errors.Is(err, ErrReplay) {
				t.Fatalf("Accept(duplicate) error = %v, want %v", err, ErrReplay)
			}
			if targets.calls != 0 {
				t.Fatalf("TargetSource.Snapshot() calls = %d, want 0 for duplicate webhook ID", targets.calls)
			}
			if got := countIngressReceipts(t, ingress.state); got != 1 {
				t.Fatalf("replay receipt count = %d, want 1", got)
			}
		})
	}
}

type countingTargetSource struct {
	snapshot target.Snapshot
	calls    int
}

func (s *countingTargetSource) Snapshot() target.Snapshot {
	s.calls++
	return s.snapshot
}

func mutateSecurityHeaders(keyring *webhook.Keyring, signedAt time.Time, raw []byte, mutate func(*webhook.Headers)) func(*testing.T, string) (webhook.Headers, []byte) {
	return func(t *testing.T, id string) (webhook.Headers, []byte) {
		t.Helper()
		headers := signSecurityBody(t, keyring, id, signedAt, raw)
		mutate(&headers)
		return headers, raw
	}
}

func signedSecurityHeaders(keyring *webhook.Keyring, signedAt time.Time, raw []byte) func(*testing.T, string) (webhook.Headers, []byte) {
	return func(t *testing.T, id string) (webhook.Headers, []byte) {
		t.Helper()
		return signSecurityBody(t, keyring, id, signedAt, raw), raw
	}
}

func signSecurityBody(t *testing.T, keyring *webhook.Keyring, id string, signedAt time.Time, raw []byte) webhook.Headers {
	t.Helper()
	headers, err := keyring.Sign(id, signedAt, raw)
	if err != nil {
		t.Fatalf("Keyring.Sign() error = %v", err)
	}
	return headers
}

func wrapCountingTargets(t *testing.T, ingress *Ingress) *countingTargetSource {
	t.Helper()
	configured, ok := ingress.targets.(staticTargets)
	if !ok {
		t.Fatalf("Ingress target source type = %T, want staticTargets", ingress.targets)
	}
	targets := &countingTargetSource{snapshot: configured.snapshot}
	ingress.targets = targets
	return targets
}

func countIngressReceipts(t *testing.T, state *store.Store) int {
	t.Helper()
	count := 0
	if err := state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketIngressReceipts, func(string, []byte) error {
			count++
			return nil
		})
	}); err != nil {
		t.Fatalf("count ingress receipts: %v", err)
	}
	return count
}

func ingressAuditReasons(t *testing.T, state *store.Store) []string {
	t.Helper()
	reasons := []string{}
	if err := state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketAudit, func(_ string, document []byte) error {
			var event contract.AuditEvent
			if err := json.Unmarshal(document, &event); err != nil {
				return err
			}
			reasons = append(reasons, event.ReasonCode)
			return nil
		})
	}); err != nil {
		t.Fatalf("read ingress audit reasons: %v", err)
	}
	return reasons
}
