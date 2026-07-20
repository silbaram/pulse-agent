package contract

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDecode_AnalysisResultCorpus(t *testing.T) {
	tests := []struct {
		name string
		file string
		want error
	}{
		{name: "valid", file: "analysis-valid.json"},
		{name: "command field", file: "analysis-command-field.json", want: ErrUnknownField},
		{name: "unknown field", file: "analysis-unknown-field.json", want: ErrUnknownField},
		{name: "duplicate field", file: "analysis-duplicate-field.json", want: ErrDuplicateField},
		{name: "unsupported schema", file: "analysis-unsupported-schema.json", want: ErrUnsupportedSchemaVersion},
		{name: "trailing data", file: "analysis-trailing-data.json", want: ErrTrailingData},
		{name: "malformed", file: "analysis-malformed.json", want: ErrInvalidJSON},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeAnalysisResult(t, readFixture(t, tt.file))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Decode() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDecode_RejectsOversizedDocument(t *testing.T) {
	document := make([]byte, MaxDocumentBytes+1)
	if _, err := decodeAnalysisResult(t, document); !errors.Is(err, ErrDocumentTooLarge) {
		t.Fatalf("Decode() error = %v, want %v", err, ErrDocumentTooLarge)
	}
}

func TestDecode_DeliveryQueueCorpus(t *testing.T) {
	tests := []struct {
		name string
		file string
		want error
	}{
		{name: "valid", file: "delivery-valid.json"},
		{name: "unsupported payload type", file: "delivery-unsupported-payload.json", want: ErrInvalidContract},
		{name: "missing payload reference", file: "delivery-missing-payload-ref.json", want: ErrInvalidContract},
		{name: "report id branch", file: "delivery-report-id-field.json", want: ErrUnknownField},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeDeliveryQueueItem(t, readFixture(t, tt.file))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Decode() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDecode_RejectsSecretFieldsFromDeliveryPayloads(t *testing.T) {
	tests := []struct {
		name   string
		file   string
		decode func(*testing.T, []byte) error
	}{
		{
			name: "lifecycle event",
			file: "lifecycle-secret-field.json",
			decode: func(t *testing.T, document []byte) error {
				_, err := Decode(document, DecodeOptions[LifecycleEvent]{SchemaVersion: SchemaVersionV1, Validate: func(value LifecycleEvent) error { return value.Validate() }})
				return err
			},
		},
		{
			name: "webhook envelope",
			file: "webhook-secret-field.json",
			decode: func(t *testing.T, document []byte) error {
				_, err := Decode(document, DecodeOptions[WebhookEnvelope]{SchemaVersion: SchemaVersionV1, Validate: func(value WebhookEnvelope) error { return value.Validate() }})
				return err
			},
		},
		{
			name: "webhook raw evidence",
			file: "webhook-raw-evidence-field.json",
			decode: func(t *testing.T, document []byte) error {
				_, err := Decode(document, DecodeOptions[WebhookEnvelope]{SchemaVersion: SchemaVersionV1, Validate: func(value WebhookEnvelope) error { return value.Validate() }})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.decode(t, readFixture(t, tt.file)); !errors.Is(err, ErrUnknownField) {
				t.Fatalf("Decode() error = %v, want %v", err, ErrUnknownField)
			}
		})
	}
}

func FuzzDecodeAnalysisResult(f *testing.F) {
	f.Add(readFixtureForFuzz(f, "analysis-valid.json"))
	f.Add(readFixtureForFuzz(f, "analysis-command-field.json"))
	f.Add(readFixtureForFuzz(f, "analysis-duplicate-field.json"))

	f.Fuzz(func(t *testing.T, document []byte) {
		_, _ = decodeAnalysisResult(t, document)
	})
}

func decodeAnalysisResult(t *testing.T, document []byte) (AnalysisResult, error) {
	t.Helper()
	return Decode(document, DecodeOptions[AnalysisResult]{
		SchemaVersion: SchemaVersionV1,
		Validate: func(value AnalysisResult) error {
			return value.Validate()
		},
	})
}

func decodeDeliveryQueueItem(t *testing.T, document []byte) (DeliveryQueueItem, error) {
	t.Helper()
	return Decode(document, DecodeOptions[DeliveryQueueItem]{
		SchemaVersion: SchemaVersionV1,
		Validate: func(value DeliveryQueueItem) error {
			return value.Validate()
		},
	})
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %q: %v", name, err)
	}
	return data
}

func readFixtureForFuzz(f *testing.F, name string) []byte {
	f.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		f.Fatalf("read fixture %q: %v", name, err)
	}
	return data
}
