package contract

import (
	"errors"
	"testing"
	"time"
)

func TestDuration_JSONRoundTrip(t *testing.T) {
	var got Duration
	if err := got.UnmarshalJSON([]byte(`"45s"`)); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.Value() != 45*time.Second {
		t.Fatalf("duration = %v, want %v", got.Value(), 45*time.Second)
	}
	if err := got.UnmarshalJSON([]byte(`"not-a-duration"`)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("UnmarshalJSON() error = %v, want %v", err, ErrInvalidContract)
	}
}

func TestIncidentState_TransitionValidation(t *testing.T) {
	tests := []struct {
		name string
		from IncidentState
		to   IncidentState
		want error
	}{
		{name: "open to analyzing", from: IncidentOpen, to: IncidentAnalyzing},
		{name: "analyzing to recovery", from: IncidentAnalyzing, to: IncidentRecovering},
		{name: "closed to recovery", from: IncidentClosed, to: IncidentRecovering, want: ErrInvalidStateTransition},
		{name: "open to stabilization", from: IncidentOpen, to: IncidentStabilizing, want: ErrInvalidStateTransition},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.from.ValidateTransition(tt.to)
			if !errors.Is(err, tt.want) {
				t.Fatalf("ValidateTransition(%q) error = %v, want %v", tt.to, err, tt.want)
			}
		})
	}
}

func TestRecoveryCommandState_TransitionValidation(t *testing.T) {
	tests := []struct {
		name string
		from RecoveryCommandState
		to   RecoveryCommandState
		want error
	}{
		{name: "pending to approved", from: RecoveryPending, to: RecoveryApproved},
		{name: "executing to succeeded", from: RecoveryExecuting, to: RecoverySucceeded},
		{name: "denied to executing", from: RecoveryDenied, to: RecoveryExecuting, want: ErrInvalidStateTransition},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.from.ValidateTransition(tt.to)
			if !errors.Is(err, tt.want) {
				t.Fatalf("ValidateTransition(%q) error = %v, want %v", tt.to, err, tt.want)
			}
		})
	}
}

func TestIncident_ValidateTerminalState(t *testing.T) {
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	incident := Incident{
		SchemaVersion: SchemaVersionV1,
		IncidentID:    "incident-1",
		DedupeKey:     "target-1:rule-1",
		TargetID:      "target-1",
		RuleIDs:       []string{"rule-1"},
		State:         IncidentClosed,
		OpenedAt:      now,
	}
	if err := incident.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidContract)
	}

	incident.TerminalAt = now.Add(time.Minute)
	if err := incident.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestDeliveryQueueItem_Validate(t *testing.T) {
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	item := DeliveryQueueItem{
		SchemaVersion:  SchemaVersionV1,
		DeliveryID:     "delivery-1",
		PayloadType:    DeliveryPayloadLifecycleEvent,
		PayloadRef:     "event-1",
		WebhookID:      "webhook-1",
		DestinationRef: "webhook:operations",
		NextAttemptAt:  now,
		ExpiresAt:      now.Add(time.Hour),
		State:          DeliveryPending,
	}
	if err := item.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}

	item.PayloadType = "report_only"
	if err := item.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidContract)
	}
}
