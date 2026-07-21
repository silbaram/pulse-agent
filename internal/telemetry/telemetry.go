// Package telemetry provides bounded OpenTelemetry instrumentation for Pulse
// Agent domain operations.
//
// Only the typed values in this package can become span or metric attributes.
// Callers cannot attach arbitrary attributes or span events, so raw evidence,
// prompts, incident IDs, credentials, and webhook secrets cannot cross this
// boundary into telemetry.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	// InstrumentationName identifies this package as the telemetry scope.
	InstrumentationName = "pulse-agent"
	// SpanNamePrefix scopes every Pulse Agent span to a stable namespace.
	SpanNamePrefix = "pulse.agent"
	// MetricOperationTotal counts completed bounded domain operations.
	MetricOperationTotal = "pulse.agent.operation.count"
	// MetricOperationDuration records completed operation duration in seconds.
	MetricOperationDuration = "pulse.agent.operation.duration"

	// AttributeComponent identifies the bounded owning component.
	AttributeComponent = "pulse.agent.component"
	// AttributeOperation identifies the bounded operation within a component.
	AttributeOperation = "pulse.agent.operation"
	// AttributeResult identifies the bounded result classification.
	AttributeResult = "pulse.agent.result"
	// AttributeReason identifies the bounded reason classification.
	AttributeReason = "pulse.agent.reason"
)

var (
	// ErrInvalidEvent indicates an event cannot satisfy the bounded telemetry
	// attribute contract.
	ErrInvalidEvent = errors.New("invalid telemetry event")
	// ErrInvalidContext indicates an operation was called without a context.
	ErrInvalidContext = errors.New("invalid telemetry context")
)

// Component identifies the subsystem that owns an instrumented operation.
// Values are intentionally closed to keep attribute cardinality bounded.
type Component string

const (
	// ComponentAdminIPC identifies local administrative IPC work.
	ComponentAdminIPC Component = "admin_ipc"
	// ComponentRunbook identifies runbook pair validation and registration work.
	ComponentRunbook Component = "runbook"
	// ComponentStore identifies daemon-owned local-state work.
	ComponentStore Component = "store"
	// ComponentTarget identifies monitoring-target registration work.
	ComponentTarget Component = "target"
	// ComponentWebhook identifies inbound and outbound webhook work.
	ComponentWebhook Component = "webhook"
)

// Operation identifies one stable unit of component work. Values are
// intentionally closed to keep span names and attributes bounded.
type Operation string

const (
	// OperationRead identifies a bounded read-only operation.
	OperationRead Operation = "read"
	// OperationWrite identifies a bounded durable write operation.
	OperationWrite Operation = "write"
	// OperationRegister identifies a bounded registration operation.
	OperationRegister Operation = "register"
	// OperationRequest identifies one authenticated local request.
	OperationRequest Operation = "request"
	// OperationBackup identifies a read-only backup operation.
	OperationBackup Operation = "backup"
)

// Result identifies the stable result classification of an operation.
type Result string

const (
	// ResultSuccess identifies a completed operation.
	ResultSuccess Result = "success"
	// ResultFailure identifies an operation that failed unexpectedly.
	ResultFailure Result = "failure"
	// ResultRejected identifies a fail-closed rejected operation.
	ResultRejected Result = "rejected"
	// ResultUnavailable identifies a dependency-unavailable operation.
	ResultUnavailable Result = "unavailable"
)

// Reason identifies a bounded explanation for a Result. It is deliberately
// not an error message or a caller-provided string.
type Reason string

const (
	// ReasonNone identifies a successful operation with no further reason.
	ReasonNone Reason = "none"
	// ReasonAccepted identifies an accepted operation.
	ReasonAccepted Reason = "accepted"
	// ReasonDuplicate identifies a duplicate registration rejection.
	ReasonDuplicate Reason = "duplicate"
	// ReasonInvalid identifies rejected malformed or unsafe input.
	ReasonInvalid Reason = "invalid"
	// ReasonUnauthorized identifies an authentication or authorization rejection.
	ReasonUnauthorized Reason = "unauthorized"
	// ReasonTimeout identifies a bounded timeout.
	ReasonTimeout Reason = "timeout"
	// ReasonUnavailable identifies an unavailable local or external dependency.
	ReasonUnavailable Reason = "unavailable"
	// ReasonInternal identifies an internal failure without exposing raw detail.
	ReasonInternal Reason = "internal"
)

// Event is a validated, bounded telemetry record. Construct one only with
// NewEvent; its fields remain private so arbitrary strings cannot become
// telemetry attributes.
type Event struct {
	component Component
	operation Operation
	result    Result
	reason    Reason
	duration  time.Duration
}

// NewEvent constructs one bounded telemetry event. duration must be
// non-negative, and all other values must be package-defined constants.
func NewEvent(component Component, operation Operation, result Result, reason Reason, duration time.Duration) (Event, error) {
	event := Event{component: component, operation: operation, result: result, reason: reason, duration: duration}
	if !event.valid() {
		return Event{}, ErrInvalidEvent
	}
	return event, nil
}

// Options configures optional OpenTelemetry exporters. With no exporter or
// reader, New returns a disabled recorder that performs no OpenTelemetry work.
type Options struct {
	// SpanExporter receives traces through the OpenTelemetry SDK batch processor.
	// A nil exporter disables trace export.
	SpanExporter sdktrace.SpanExporter
	// MetricReader receives metrics through the OpenTelemetry SDK. A nil reader
	// disables metric export.
	MetricReader sdkmetric.Reader
}

// Recorder emits only Event-derived OpenTelemetry data. Exporter failures are
// isolated from Record so domain results and policy decisions cannot depend on
// telemetry delivery.
type Recorder struct {
	enabled          bool
	tracer           oteltrace.Tracer
	operationTotal   otelmetric.Int64Counter
	operationLatency otelmetric.Float64Histogram
	tracerProvider   *sdktrace.TracerProvider
	meterProvider    *sdkmetric.MeterProvider
}

// New creates a Recorder with private OpenTelemetry providers. It never
// replaces global providers, preventing telemetry configuration from leaking
// into unrelated packages.
func New(options Options) (*Recorder, error) {
	recorder := &Recorder{}
	if options.SpanExporter == nil && options.MetricReader == nil {
		return recorder, nil
	}

	recorder.enabled = true
	if options.SpanExporter != nil {
		recorder.tracerProvider = sdktrace.NewTracerProvider(
			sdktrace.WithResource(instrumentationResource()),
			sdktrace.WithBatcher(options.SpanExporter),
		)
		recorder.tracer = recorder.tracerProvider.Tracer(InstrumentationName)
	}

	meterOptions := []sdkmetric.Option{sdkmetric.WithResource(instrumentationResource())}
	if options.MetricReader != nil {
		meterOptions = append(meterOptions, sdkmetric.WithReader(options.MetricReader))
	}
	recorder.meterProvider = sdkmetric.NewMeterProvider(meterOptions...)
	meter := recorder.meterProvider.Meter(InstrumentationName)
	var err error
	recorder.operationTotal, err = meter.Int64Counter(MetricOperationTotal, otelmetric.WithDescription("Completed Pulse Agent operations"))
	if err != nil {
		return nil, recorder.initializationError("create operation counter", err)
	}
	recorder.operationLatency, err = meter.Float64Histogram(MetricOperationDuration, otelmetric.WithUnit("s"), otelmetric.WithDescription("Pulse Agent operation duration"))
	if err != nil {
		return nil, recorder.initializationError("create operation duration histogram", err)
	}
	return recorder, nil
}

// Enabled reports whether this recorder owns an active OpenTelemetry SDK
// provider. Disabled recorders are intentionally no-op.
func (r *Recorder) Enabled() bool {
	return r != nil && r.enabled
}

// Record emits one trace and two metrics from a validated Event. It does not
// return exporter delivery errors, so telemetry cannot change domain outcomes.
func (r *Recorder) Record(ctx context.Context, event Event) error {
	if ctx == nil {
		return ErrInvalidContext
	}
	if !event.valid() {
		return ErrInvalidEvent
	}
	if r == nil || !r.enabled {
		return nil
	}

	attributes := event.attributes()
	if r.tracer != nil {
		finishedAt := time.Now()
		_, span := r.tracer.Start(ctx, event.spanName(), oteltrace.WithTimestamp(finishedAt.Add(-event.duration)))
		span.SetAttributes(attributes...)
		if event.result != ResultSuccess {
			span.SetStatus(codes.Error, string(event.reason))
		}
		span.End(oteltrace.WithTimestamp(finishedAt))
	}
	r.operationTotal.Add(ctx, 1, otelmetric.WithAttributes(attributes...))
	r.operationLatency.Record(ctx, event.duration.Seconds(), otelmetric.WithAttributes(attributes...))
	return nil
}

// ForceFlush requests delivery of pending telemetry. Its error is diagnostic
// only; callers must not use it to alter domain state or policy decisions.
func (r *Recorder) ForceFlush(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidContext
	}
	if r == nil || !r.enabled {
		return nil
	}
	var errs []error
	if r.tracerProvider != nil {
		errs = append(errs, r.tracerProvider.ForceFlush(ctx))
	}
	if r.meterProvider != nil {
		errs = append(errs, r.meterProvider.ForceFlush(ctx))
	}
	return errors.Join(errs...)
}

// Shutdown releases OpenTelemetry resources using ctx. Its error is
// diagnostic-only and must not influence a product state transition.
func (r *Recorder) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidContext
	}
	if r == nil || !r.enabled {
		return nil
	}
	var errs []error
	if r.tracerProvider != nil {
		errs = append(errs, r.tracerProvider.Shutdown(ctx))
	}
	if r.meterProvider != nil {
		errs = append(errs, r.meterProvider.Shutdown(ctx))
	}
	return errors.Join(errs...)
}

func (e Event) valid() bool {
	return validComponent(e.component) && validOperation(e.operation) && validResult(e.result) && validReason(e.reason) && e.duration >= 0
}

func (e Event) spanName() string {
	return SpanNamePrefix + "." + string(e.component) + "." + string(e.operation)
}

func (e Event) attributes() []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String(AttributeComponent, string(e.component)),
		attribute.String(AttributeOperation, string(e.operation)),
		attribute.String(AttributeResult, string(e.result)),
		attribute.String(AttributeReason, string(e.reason)),
	}
}

func validComponent(value Component) bool {
	switch value {
	case ComponentAdminIPC, ComponentRunbook, ComponentStore, ComponentTarget, ComponentWebhook:
		return true
	default:
		return false
	}
}

func validOperation(value Operation) bool {
	switch value {
	case OperationRead, OperationWrite, OperationRegister, OperationRequest, OperationBackup:
		return true
	default:
		return false
	}
}

func validResult(value Result) bool {
	switch value {
	case ResultSuccess, ResultFailure, ResultRejected, ResultUnavailable:
		return true
	default:
		return false
	}
}

func validReason(value Reason) bool {
	switch value {
	case ReasonNone, ReasonAccepted, ReasonDuplicate, ReasonInvalid, ReasonUnauthorized, ReasonTimeout, ReasonUnavailable, ReasonInternal:
		return true
	default:
		return false
	}
}

func instrumentationResource() *resource.Resource {
	return resource.NewWithAttributes("", attribute.String("service.name", InstrumentationName))
}

func (r *Recorder) initializationError(operation string, cause error) error {
	initializationErr := fmt.Errorf("%s: %w", operation, cause)
	if shutdownErr := r.Shutdown(context.Background()); shutdownErr != nil {
		return errors.Join(initializationErr, fmt.Errorf("shutdown telemetry providers: %w", shutdownErr))
	}
	return initializationErr
}
