package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pulse-agent/internal/contract"
)

func TestLoad_ValidFixtures(t *testing.T) {
	for _, name := range []string{"valid-production.json", "valid-synthetic-loopback.json"} {
		t.Run(name, func(t *testing.T) {
			config, err := Load(filepath.Join("testdata", name))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if config.SchemaVersion != SchemaVersion {
				t.Errorf("schema version = %q, want %q", config.SchemaVersion, SchemaVersion)
			}
		})
	}
}

func TestLoad_PackagingExample(t *testing.T) {
	value, err := Load(filepath.Join("..", "..", "packaging", "examples", "config.json"))
	if err != nil {
		t.Fatalf("Load() packaging example error = %v", err)
	}
	if value.UsageMode != UsageProduction || value.Webhooks.Ingress.PreviousSecretRef == "" || value.Webhooks.Outbound.PreviousSecretRef == "" {
		t.Fatalf("packaging config = %#v, want production config with rotation references", value)
	}
}

func TestLoad_RejectsInvalidFixtures(t *testing.T) {
	tests := []struct {
		name string
		want error
	}{
		{name: "invalid-duplicate-target.json", want: ErrInvalidConfig},
		{name: "invalid-duration.json", want: contract.ErrInvalidJSON},
		{name: "invalid-http-remote.json", want: ErrInvalidConfig},
		{name: "invalid-infinite-retention.json", want: ErrInvalidConfig},
		{name: "invalid-loopback-production.json", want: ErrInvalidConfig},
		{name: "invalid-path-traversal.json", want: ErrInvalidConfig},
		{name: "invalid-plain-secret.json", want: contract.ErrUnknownField},
		{name: "invalid-production-free.json", want: ErrInvalidConfig},
		{name: "invalid-unknown-field.json", want: contract.ErrUnknownField},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(filepath.Join("testdata", tt.name))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, tt.want)
			}
		})
	}
}

func TestDecode_RejectsDuplicateFields(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("testdata", "invalid-duplicate-field.json"))
	if err != nil {
		t.Fatalf("read duplicate fixture: %v", err)
	}
	_, err = Decode(document)
	if !errors.Is(err, contract.ErrDuplicateField) {
		t.Fatalf("Decode() error = %v, want errors.Is(_, %v)", err, contract.ErrDuplicateField)
	}
}

func TestConfig_ValidateRejectsMissingOrDuplicateAdminIdentities(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("testdata", "valid-production.json"))
	if err != nil {
		t.Fatalf("read valid fixture: %v", err)
	}
	valid, err := Decode(document)
	if err != nil {
		t.Fatalf("Decode() valid fixture error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "missing allowed UID list",
			mutate: func(value *Config) {
				value.Admin.AllowedUIDs = nil
			},
		},
		{
			name: "duplicate allowed GID",
			mutate: func(value *Config) {
				value.Admin.AllowedGIDs = []uint32{1000, 1000}
			},
		},
		{
			name: "target ID traversal",
			mutate: func(value *Config) {
				value.AllowedTargets[0].TargetID = "../escape"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := valid
			tt.mutate(&value)
			if err := value.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidConfig)
			}
		})
	}
}

func TestConfig_ValidateWebhookSecretRotationReferences(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("testdata", "valid-production.json"))
	if err != nil {
		t.Fatalf("read valid fixture: %v", err)
	}
	valid, err := Decode(document)
	if err != nil {
		t.Fatalf("Decode() valid fixture error = %v", err)
	}
	valid.Webhooks.Ingress.PreviousSecretRef = "env:PULSE_AGENT_INGRESS_SECRET_PREVIOUS"
	valid.Webhooks.Outbound.PreviousSecretRef = "env:PULSE_AGENT_OUTBOUND_SECRET_PREVIOUS"
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() rotation references error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "plain previous secret",
			mutate: func(value *Config) {
				value.Webhooks.Ingress.PreviousSecretRef = "plain-secret"
			},
		},
		{
			name: "previous duplicates current",
			mutate: func(value *Config) {
				value.Webhooks.Outbound.PreviousSecretRef = value.Webhooks.Outbound.SecretRef
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := valid
			tt.mutate(&value)
			if err := value.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidConfig)
			}
		})
	}
}

func TestLoad_RejectsOversizeDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversize.json")
	document := []byte(strings.Repeat("x", MaxDocumentBytes+1))
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("write oversize fixture: %v", err)
	}

	_, err := Load(path)
	if !errors.Is(err, ErrConfigTooLarge) {
		t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, ErrConfigTooLarge)
	}
}

func FuzzDecode(f *testing.F) {
	for _, name := range []string{"valid-production.json", "invalid-plain-secret.json", "invalid-duplicate-field.json"} {
		document, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatalf("read seed %q: %v", name, err)
		}
		f.Add(document)
	}

	f.Fuzz(func(t *testing.T, document []byte) {
		_, _ = Decode(document)
	})
}
