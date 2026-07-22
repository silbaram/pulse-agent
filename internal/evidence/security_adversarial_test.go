package evidence

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/telemetry"
)

const evidenceRedactionCorpusSize = 30

type redactionDisposition string

const (
	dispositionRedacted redactionDisposition = "redacted"
	dispositionBlocked  redactionDisposition = "redaction_failed"
)

func TestCollector_RedactionCorpusHasExpectedDisposition(t *testing.T) {
	now := time.Date(2026, time.July, 22, 1, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		input       string
		raw         string
		disposition redactionDisposition
	}{
		{name: "api key underscore", input: "api_key=api-key-synthetic", raw: "api-key-synthetic", disposition: dispositionRedacted},
		{name: "api key hyphen", input: "api-key:api-key-hyphen", raw: "api-key-hyphen", disposition: dispositionRedacted},
		{name: "token", input: "token=token-synthetic", raw: "token-synthetic", disposition: dispositionRedacted},
		{name: "access token", input: "access_token=access-token-synthetic", raw: "access-token-synthetic", disposition: dispositionRedacted},
		{name: "password", input: "password=password-synthetic", raw: "password-synthetic", disposition: dispositionRedacted},
		{name: "database password", input: "db_password=db-password-synthetic", raw: "db-password-synthetic", disposition: dispositionRedacted},
		{name: "client secret", input: "client_secret=client-secret-synthetic", raw: "client-secret-synthetic", disposition: dispositionRedacted},
		{name: "private key", input: "private_key=private-key-synthetic", raw: "private-key-synthetic", disposition: dispositionRedacted},
		{name: "credential", input: "credential=credential-synthetic", raw: "credential-synthetic", disposition: dispositionRedacted},
		{name: "customer ID", input: "customer_id=customer-2048", raw: "customer-2048", disposition: dispositionRedacted},
		{name: "customer name", input: "customer_name=Alice-Synthetic", raw: "Alice-Synthetic", disposition: dispositionRedacted},
		{name: "customer email label", input: "customer_email=alice@example.test", raw: "alice@example.test", disposition: dispositionRedacted},
		{name: "customer phone label", input: "customer_phone=010-1234-5678", raw: "010-1234-5678", disposition: dispositionRedacted},
		{name: "bearer authorization", input: "Authorization: Bearer bearer-synthetic", raw: "bearer-synthetic", disposition: dispositionRedacted},
		{name: "bare email", input: "owner alice@example.test", raw: "alice@example.test", disposition: dispositionRedacted},
		{name: "bare phone", input: "owner 010-1234-5678", raw: "010-1234-5678", disposition: dispositionRedacted},
		{name: "GitHub classic PAT", input: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", raw: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", disposition: dispositionRedacted},
		{name: "GitHub fine grained PAT", input: "github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", raw: "github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", disposition: dispositionRedacted},
		{name: "Slack bot token", input: "xoxb-redaction-fixture", raw: "xoxb-redaction-fixture", disposition: dispositionRedacted},
		{name: "Slack user token", input: "xoxp-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ", raw: "xoxp-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ", disposition: dispositionRedacted},
		{name: "live secret key", input: "sk_fixture_opaque", raw: "sk_fixture_opaque", disposition: dispositionRedacted},
		{name: "test secret key", input: "sk-test-ABCDEFGHIJKLMNOPQRSTUVWXYZ", raw: "sk-test-ABCDEFGHIJKLMNOPQRSTUVWXYZ", disposition: dispositionRedacted},
		{name: "AWS access key", input: "AKIAABCDEFGHIJKLMNOP", raw: "AKIAABCDEFGHIJKLMNOP", disposition: dispositionRedacted},
		{name: "Google API key", input: "AIzaABCDEFGHIJKLMNOPQRSTUVWXYZ012345", raw: "AIzaABCDEFGHIJKLMNOPQRSTUVWXYZ012345", disposition: dispositionRedacted},
		{name: "webhook secret", input: "whsec_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", raw: "whsec_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", disposition: dispositionRedacted},
		{name: "missing password value", input: "password=", raw: "password=", disposition: dispositionBlocked},
		{name: "invalid UTF-8", input: string([]byte{'b', 'a', 'd', 0xff}), raw: "", disposition: dispositionBlocked},
		{name: "embedded NUL", input: "token=abc\x00def", raw: "abc", disposition: dispositionBlocked},
		{name: "new session token form", input: "sessionv2~ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", raw: "sessionv2~ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", disposition: dispositionBlocked},
		{name: "new credential token form", input: "credv3.ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", raw: "credv3.ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", disposition: dispositionBlocked},
	}
	if got := len(tests); got != evidenceRedactionCorpusSize {
		t.Fatalf("evidence redaction corpus size = %d, want %d", got, evidenceRedactionCorpusSize)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := newTestCollector(t, 1, 512, now)
			result, err := collector.Collect("application-log", "strict", now.Add(-time.Minute), now, []Record{{At: now, Fields: map[string]string{"message": test.input}}})
			switch test.disposition {
			case dispositionRedacted:
				if err != nil || result.RedactionFailed || result.Content == "" || result.Reference.EvidenceID == "" {
					t.Fatalf("Collect() disposition = %#v, %v, want %q", result, err, test.disposition)
				}
				if test.raw != "" && strings.Contains(result.Content, test.raw) {
					t.Fatal("redacted evidence contains raw corpus value")
				}
			case dispositionBlocked:
				if !errors.Is(err, ErrRedactionFailed) || !result.RedactionFailed || result.Content != "" || result.Reference != (contract.EvidenceRef{}) {
					t.Fatalf("Collect() disposition = %#v, %v, want %q meta-result only", result, err, test.disposition)
				}
				if test.raw != "" && strings.Contains(err.Error(), test.raw) {
					t.Fatal("redaction error contains raw corpus value")
				}
			default:
				t.Fatalf("unknown expected disposition %q", test.disposition)
			}
		})
	}
}

func TestCollector_NewSecretFormEmitsOnlyRedactionFailedMetaEvent(t *testing.T) {
	now := time.Date(2026, time.July, 22, 1, 0, 0, 0, time.UTC)
	spanExporter := tracetest.NewInMemoryExporter()
	recorder, err := telemetry.New(telemetry.Options{SpanExporter: spanExporter})
	if err != nil {
		t.Fatalf("telemetry.New() error = %v", err)
	}
	t.Cleanup(func() {
		if shutdownErr := recorder.Shutdown(context.Background()); shutdownErr != nil {
			t.Errorf("telemetry shutdown: %v", shutdownErr)
		}
	})
	collector := newTestCollector(t, 1, 512, now)
	collector.telemetry = recorder
	const raw = "sessionv2~ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
	result, err := collector.Collect("application-log", "strict", now.Add(-time.Minute), now, []Record{{At: now, Fields: map[string]string{"message": raw}}})
	if !errors.Is(err, ErrRedactionFailed) || !result.RedactionFailed || result.Content != "" || result.Reference != (contract.EvidenceRef{}) {
		t.Fatalf("Collect() = %#v, %v, want redaction_failed meta-result only", result, err)
	}
	if err := recorder.ForceFlush(context.Background()); err != nil {
		t.Fatalf("telemetry flush: %v", err)
	}
	spans := spanExporter.GetSpans()
	if len(spans) != 1 || spans[0].Name != "pulse.agent.evidence.redact" {
		t.Fatalf("spans = %#v, want one redaction meta-event", spans)
	}
	reasonFound := false
	for _, attribute := range spans[0].Attributes {
		value := attribute.Value.AsString()
		if value == string(telemetry.ReasonRedactionFailed) {
			reasonFound = true
		}
		if strings.Contains(value, raw) {
			t.Fatal("redaction meta-event contains raw new-form secret")
		}
	}
	if !reasonFound {
		t.Fatalf("redaction meta-event attributes = %#v, want reason %q", spans[0].Attributes, telemetry.ReasonRedactionFailed)
	}
}
