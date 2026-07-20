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
