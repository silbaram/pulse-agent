package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
	"pulse-agent/internal/target"
	"pulse-agent/internal/telemetry"
	"pulse-agent/internal/webhook"
)

func TestIngress_AcceptVerifiesRotationNormalizesAndRejectsReplay(t *testing.T) {
	now := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	current := "whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
	previous := "whsec_YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg="
	signer, err := webhook.NewKeyring(current, previous)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	ingress := newTestIngress(t, now, signer, defaultMaxBodyBytes)
	body := validBody(t, now)
	headers, err := signer.Sign("msg-alert", now, body)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	normalized, err := ingress.Accept(context.Background(), headers, body)
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if normalized.Source != "monitor" || normalized.ExternalAlertID != "external-1" || normalized.Observation.TargetID != "checkout" || len(normalized.Observation.EvidenceRefs) != 0 {
		t.Fatalf("normalized = %#v", normalized)
	}
	previousSigner, err := webhook.NewKeyring(previous)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	previousHeaders, err := previousSigner.Sign("msg-previous", now, body)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := ingress.Accept(context.Background(), previousHeaders, body); err != nil {
		t.Fatalf("Accept() with previous secret error = %v", err)
	}
	if _, err := ingress.Accept(context.Background(), headers, body); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay error = %v, want %v", err, ErrReplay)
	}
}

func TestIngress_ServeHTTPRejectsUnsafeRequestsBeforeStateChange(t *testing.T) {
	now := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	secret := "whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
	keyring, err := webhook.NewKeyring(secret)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	ingress := newTestIngress(t, now, keyring, defaultMaxBodyBytes)
	body := validBody(t, now)
	headers, err := keyring.Sign("msg-http", now, body)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	for _, test := range []struct {
		name, method, contentType string
		body                      []byte
		mutate                    func(webhook.Headers) webhook.Headers
		want                      int
	}{
		{name: "method", method: http.MethodGet, contentType: "application/json", body: body, want: http.StatusBadRequest},
		{name: "content type", method: http.MethodPost, contentType: "text/plain", body: body, want: http.StatusBadRequest},
		{name: "signature", method: http.MethodPost, contentType: "application/json", body: body, mutate: func(h webhook.Headers) webhook.Headers { h.Signature = "v1,AAAA"; return h }, want: http.StatusUnauthorized},
		{name: "oversize", method: http.MethodPost, contentType: "application/json", body: bytes.Repeat([]byte("x"), defaultMaxBodyBytes+1), want: http.StatusRequestEntityTooLarge},
		{name: "malformed", method: http.MethodPost, contentType: "application/json", body: []byte("{"), want: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "/alerts", bytes.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			signed := headers
			if test.mutate != nil {
				signed = test.mutate(signed)
			}
			if test.name == "malformed" {
				signed, _ = keyring.Sign("msg-malformed", now, test.body)
			}
			request.Header.Set(webhook.HeaderID, signed.ID)
			request.Header.Set(webhook.HeaderTimestamp, signed.Timestamp)
			request.Header.Set(webhook.HeaderSignature, signed.Signature)
			response := httptest.NewRecorder()
			ingress.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

func TestIngress_AcceptHonorsTimeoutAndAuditsRejectedInput(t *testing.T) {
	now := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	secret := "whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
	keyring, err := webhook.NewKeyring(secret)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	ingress := newTestIngress(t, now, keyring, defaultMaxBodyBytes)
	body := validBody(t, now)
	headers, err := keyring.Sign("msg-timeout", now, body)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := ingress.Accept(ctx, headers, body); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Accept() error = %v, want %v", err, context.DeadlineExceeded)
	}

	headers.Signature = "v1,AAAA"
	if _, err := ingress.Accept(context.Background(), headers, body); err == nil {
		t.Fatal("Accept() error = nil, want invalid signature")
	}
	malformedBody := []byte("{")
	malformedHeaders, err := keyring.Sign("msg-malformed", now, malformedBody)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := ingress.Accept(context.Background(), malformedHeaders, malformedBody); !errors.Is(err, ErrInvalidAlert) {
		t.Fatalf("Accept() error = %v, want %v", err, ErrInvalidAlert)
	}
	unknownBody := validBodyForTarget(t, now, "unknown")
	unknownHeaders, err := keyring.Sign("msg-unknown", now, unknownBody)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := ingress.Accept(context.Background(), unknownHeaders, unknownBody); !errors.Is(err, ErrInvalidAlert) {
		t.Fatalf("Accept() error = %v, want %v", err, ErrInvalidAlert)
	}

	var auditCount int
	reasons := make(map[string]bool)
	err = ingress.state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketAudit, func(_ string, document []byte) error {
			auditCount++
			var event contract.AuditEvent
			if err := json.Unmarshal(document, &event); err != nil {
				return err
			}
			reasons[event.ReasonCode] = true
			if bytes.Contains(document, []byte("untrusted")) {
				return errors.New("audit document retained untrusted evidence")
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("State.View() error = %v", err)
	}
	if auditCount != 3 {
		t.Fatalf("audit event count = %d, want 3", auditCount)
	}
	for _, reason := range []string{"invalid_signature", "invalid_payload", "unknown_target_or_rule"} {
		if !reasons[reason] {
			t.Errorf("audit reasons = %#v, want %q", reasons, reason)
		}
	}
}

func TestIngress_AcceptExpiresReplayReceipts(t *testing.T) {
	now := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	secret := "whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
	keyring, err := webhook.NewKeyring(secret)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	ingress := newTestIngress(t, now, keyring, defaultMaxBodyBytes)
	ingress.retention = time.Minute
	body := validBody(t, now)
	headers, err := keyring.Sign("msg-expiry", now, body)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := ingress.Accept(context.Background(), headers, body); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	later := *ingress
	later.clock = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := later.Accept(context.Background(), headers, body); err != nil {
		t.Fatalf("Accept() after retention expiry error = %v", err)
	}
}

func TestIngress_AcceptRecordsBoundedValidationTelemetry(t *testing.T) {
	now := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	keyring, err := webhook.NewKeyring("whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	spanExporter := tracetest.NewInMemoryExporter()
	recorder, err := telemetry.New(telemetry.Options{SpanExporter: spanExporter})
	if err != nil {
		t.Fatalf("telemetry.New() error = %v", err)
	}
	t.Cleanup(func() {
		if shutdownErr := recorder.Shutdown(context.Background()); shutdownErr != nil {
			t.Errorf("Shutdown() error = %v", shutdownErr)
		}
	})
	ingress := newTestIngress(t, now, keyring, defaultMaxBodyBytes)
	ingress.telemetry = recorder
	body := validBody(t, now)
	headers, err := keyring.Sign("alert-telemetry", now, body)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := ingress.Accept(context.Background(), headers, body); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if err := recorder.ForceFlush(context.Background()); err != nil {
		t.Fatalf("ForceFlush() error = %v", err)
	}
	spans := spanExporter.GetSpans()
	if len(spans) != 1 || spans[0].Name != "pulse.agent.alert.validate" {
		t.Fatalf("spans = %#v, want one alert validation span", spans)
	}
	attributes := make(map[string]string, len(spans[0].Attributes))
	for _, value := range spans[0].Attributes {
		attributes[string(value.Key)] = value.Value.AsString()
	}
	for key, want := range map[string]string{telemetry.AttributeTarget: "docker", telemetry.AttributeRule: "availability", telemetry.AttributeResult: "success"} {
		if attributes[key] != want {
			t.Errorf("attribute %q = %q, want %q", key, attributes[key], want)
		}
	}
	if strings.Contains(fmt.Sprint(attributes), "external-1") || strings.Contains(fmt.Sprint(attributes), "untrusted") {
		t.Fatal("telemetry attributes contain raw alert identity or evidence")
	}
}

func newTestIngress(t *testing.T, now time.Time, keyring *webhook.Keyring, maxBody int) *Ingress {
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
	next := 0
	ingress, err := NewIngress(Options{
		State: state,
		Targets: staticTargets{snapshot: target.Snapshot{
			SchemaVersion: contract.SchemaVersionV1,
			Version:       1,
			Targets: []contract.ServiceTarget{{
				TargetID:    "checkout",
				AdapterType: "docker",
				Enabled:     true,
				ProbeRules:  []contract.ProbeRule{{RuleID: "availability", SignalType: "availability"}},
			}},
		}},
		Keyring: keyring,
		Clock:   func() time.Time { return now },
		NewObservationID: func() (string, error) {
			next++
			return fmt.Sprintf("observation-%d", next), nil
		},
		NewAuditEventID: func() (string, error) {
			next++
			return fmt.Sprintf("audit-%d", next), nil
		},
		MaxBodyBytes: maxBody,
	})
	if err != nil {
		t.Fatalf("NewIngress() error = %v", err)
	}
	return ingress
}

type staticTargets struct {
	snapshot target.Snapshot
}

func (s staticTargets) Snapshot() target.Snapshot { return s.snapshot }

func validBody(t *testing.T, now time.Time) []byte {
	return validBodyForTarget(t, now, "checkout")
}

func validBodyForTarget(t *testing.T, now time.Time, targetID string) []byte {
	t.Helper()
	body, err := json.Marshal(incoming{
		SchemaVersion:   contract.SchemaVersionV1,
		Source:          "monitor",
		ExternalAlertID: "external-1",
		TargetID:        targetID,
		RuleID:          "availability",
		State:           contract.StateUnhealthy,
		Severity:        contract.SeverityCritical,
		ObservedAt:      now,
		Values:          map[string]float64{"availability": 0.1},
		EvidenceRefs:    []string{"untrusted"},
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return body
}
