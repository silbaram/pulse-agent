package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestRecorder_RecordExportsStableSpanAndMetricContracts(t *testing.T) {
	spanExporter := tracetest.NewInMemoryExporter()
	metricReader := metric.NewManualReader()
	recorder, err := New(Options{SpanExporter: spanExporter, MetricReader: metricReader})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := recorder.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown() error = %v", err)
		}
	})

	event, err := NewEvent(ComponentRunbook, OperationRegister, ResultRejected, ReasonDuplicate, 250*time.Millisecond)
	if err != nil {
		t.Fatalf("NewEvent() error = %v", err)
	}
	if err := recorder.Record(context.Background(), event); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if err := recorder.ForceFlush(context.Background()); err != nil {
		t.Fatalf("ForceFlush() error = %v", err)
	}

	spans := spanExporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("exported spans = %d, want 1", len(spans))
	}
	if spans[0].Name != "pulse.agent.runbook.register" {
		t.Errorf("span name = %q, want %q", spans[0].Name, "pulse.agent.runbook.register")
	}
	if got := spans[0].EndTime.Sub(spans[0].StartTime); got != 250*time.Millisecond {
		t.Errorf("span duration = %s, want %s", got, 250*time.Millisecond)
	}
	attributes := attributesByKey(spans[0].Attributes)
	for key, want := range map[string]string{
		AttributeComponent: string(ComponentRunbook),
		AttributeOperation: string(OperationRegister),
		AttributeResult:    string(ResultRejected),
		AttributeReason:    string(ReasonDuplicate),
	} {
		if got := attributes[key]; got != want {
			t.Errorf("span attribute %q = %q, want %q", key, got, want)
		}
	}

	var collected metricdata.ResourceMetrics
	if err := metricReader.Collect(context.Background(), &collected); err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	metricNames := make(map[string]struct{})
	for _, scope := range collected.ScopeMetrics {
		for _, value := range scope.Metrics {
			metricNames[value.Name] = struct{}{}
		}
	}
	for _, want := range []string{MetricOperationTotal, MetricOperationDuration} {
		if _, found := metricNames[want]; !found {
			t.Errorf("metric %q was not collected", want)
		}
	}
}

func TestRecorder_DisabledIsNoop(t *testing.T) {
	recorder, err := New(Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if recorder.Enabled() {
		t.Fatal("Enabled() = true, want false for default disabled exporter")
	}
	event, err := NewEvent(ComponentStore, OperationWrite, ResultSuccess, ReasonNone, 0)
	if err != nil {
		t.Fatalf("NewEvent() error = %v", err)
	}
	if err := recorder.Record(context.Background(), event); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if err := recorder.ForceFlush(context.Background()); err != nil {
		t.Fatalf("ForceFlush() error = %v", err)
	}
	if err := recorder.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
}

func TestRecorder_ExporterFailureDoesNotChangeRecordOutcome(t *testing.T) {
	exporter := failingExporter{exportErr: errors.New("endpoint unavailable")}
	recorder, err := New(Options{SpanExporter: &exporter})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := recorder.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown() error = %v", err)
		}
	})
	event, err := NewEvent(ComponentWebhook, OperationRequest, ResultUnavailable, ReasonUnavailable, time.Second)
	if err != nil {
		t.Fatalf("NewEvent() error = %v", err)
	}
	if err := recorder.Record(context.Background(), event); err != nil {
		t.Fatalf("Record() error = %v, want exporter error to remain isolated", err)
	}
	if err := recorder.ForceFlush(context.Background()); !errors.Is(err, exporter.exportErr) {
		t.Fatalf("ForceFlush() error = %v, want exporter error", err)
	}
}

func TestRecorder_ShutdownHonorsContextDeadline(t *testing.T) {
	recorder, err := New(Options{SpanExporter: shutdownBlockingExporter{}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	deadline, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := recorder.Shutdown(deadline); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown() error = %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestNewEvent_RejectsSensitiveOrUnboundedValues(t *testing.T) {
	tests := []struct {
		name      string
		component Component
		operation Operation
		result    Result
		reason    Reason
		duration  time.Duration
	}{
		{name: "raw evidence", component: Component("raw_evidence"), operation: OperationRegister, result: ResultRejected, reason: ReasonInvalid},
		{name: "prompt text", component: ComponentRunbook, operation: Operation("summarize prompt"), result: ResultFailure, reason: ReasonInternal},
		{name: "incident identifier", component: Component("incident-01HXY2"), operation: OperationWrite, result: ResultFailure, reason: ReasonInternal},
		{name: "API key", component: ComponentStore, operation: OperationWrite, result: ResultFailure, reason: Reason("AIza-secret")},
		{name: "webhook secret", component: ComponentWebhook, operation: OperationRequest, result: ResultFailure, reason: Reason("whsec_secret")},
		{name: "negative duration", component: ComponentStore, operation: OperationWrite, result: ResultFailure, reason: ReasonInternal, duration: -time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewEvent(test.component, test.operation, test.result, test.reason, test.duration); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("NewEvent() error = %v, want %v", err, ErrInvalidEvent)
			}
		})
	}
}

func TestNewEventWithDimensions_ExportsOnlyBoundedSemanticAttributes(t *testing.T) {
	spanExporter := tracetest.NewInMemoryExporter()
	recorder, err := New(Options{SpanExporter: spanExporter})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if shutdownErr := recorder.Shutdown(context.Background()); shutdownErr != nil {
			t.Errorf("Shutdown() error = %v", shutdownErr)
		}
	})
	event, err := NewEventWithDimensions(ComponentAnalysis, OperationAnalyze, ResultSuccess, ReasonAccepted, time.Millisecond, Dimensions{Target: TargetDocker, Rule: RuleAvailability, Provider: ProviderGemini})
	if err != nil {
		t.Fatalf("NewEventWithDimensions() error = %v", err)
	}
	recorder.RecordBestEffort(context.Background(), event)
	if err := recorder.ForceFlush(context.Background()); err != nil {
		t.Fatalf("ForceFlush() error = %v", err)
	}
	spans := spanExporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("exported spans = %d, want 1", len(spans))
	}
	attributes := attributesByKey(spans[0].Attributes)
	for key, want := range map[string]string{AttributeTarget: string(TargetDocker), AttributeRule: string(RuleAvailability), AttributeProvider: string(ProviderGemini)} {
		if got := attributes[key]; got != want {
			t.Errorf("attribute %q = %q, want %q", key, got, want)
		}
	}
}

func TestNewEventWithDimensions_RejectsHighCardinalityValues(t *testing.T) {
	for _, dimensions := range []Dimensions{
		{Target: Target("checkout-production")},
		{Rule: Rule("customer-rule")},
		{Provider: Provider("https://provider.example")},
	} {
		if _, err := NewEventWithDimensions(ComponentObserver, OperationRead, ResultSuccess, ReasonNone, 0, dimensions); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("NewEventWithDimensions(%#v) error = %v, want %v", dimensions, err, ErrInvalidEvent)
		}
	}
}

func attributesByKey(values []attribute.KeyValue) map[string]string {
	attributes := make(map[string]string, len(values))
	for _, value := range values {
		attributes[string(value.Key)] = value.Value.AsString()
	}
	return attributes
}

type failingExporter struct {
	exportErr error
}

func (e *failingExporter) ExportSpans(context.Context, []trace.ReadOnlySpan) error {
	return e.exportErr
}

func (e *failingExporter) Shutdown(context.Context) error {
	return nil
}

type shutdownBlockingExporter struct{}

func (shutdownBlockingExporter) ExportSpans(context.Context, []trace.ReadOnlySpan) error {
	return nil
}

func (shutdownBlockingExporter) Shutdown(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
