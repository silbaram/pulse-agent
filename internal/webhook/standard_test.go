package webhook

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testVector struct {
	Secret    string `json:"secret"`
	ID        string `json:"webhook_id"`
	Timestamp int64  `json:"webhook_timestamp"`
	Body      string `json:"body"`
	Signature string `json:"webhook_signature"`
}

func TestKeyring_SignMatchesPublicVector(t *testing.T) {
	vector := loadTestVector(t)
	keyring, err := NewKeyring(vector.Secret)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}

	headers, err := keyring.Sign(vector.ID, time.Unix(vector.Timestamp, 0), []byte(vector.Body))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if headers.Timestamp != "1674087231" {
		t.Errorf("timestamp = %q, want %q", headers.Timestamp, "1674087231")
	}
	if headers.Signature != vector.Signature {
		t.Errorf("signature = %q, want %q", headers.Signature, vector.Signature)
	}
	if err := keyring.Verify(headers, []byte(vector.Body), time.Unix(vector.Timestamp+int64(DefaultTolerance/time.Second), 0)); err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
}

func TestKeyring_VerifyUsesExactRawBody(t *testing.T) {
	vector := loadTestVector(t)
	keyring, err := NewKeyring(vector.Secret)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	headers := Headers{ID: vector.ID, Timestamp: "1674087231", Signature: vector.Signature}

	if err := keyring.Verify(headers, []byte(vector.Body+" "), time.Unix(vector.Timestamp, 0)); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("Verify() error = %v, want errors.Is(_, %v)", err, ErrSignatureMismatch)
	}
}

func TestKeyring_VerifyEnforcesTimestampTolerance(t *testing.T) {
	vector := loadTestVector(t)
	keyring, err := NewKeyring(vector.Secret)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	headers := Headers{ID: vector.ID, Timestamp: "1674087231", Signature: vector.Signature}

	tests := []struct {
		name string
		now  int64
		want error
	}{
		{name: "past boundary", now: vector.Timestamp - int64(DefaultTolerance/time.Second), want: nil},
		{name: "future boundary", now: vector.Timestamp + int64(DefaultTolerance/time.Second), want: nil},
		{name: "past outside boundary", now: vector.Timestamp - int64(DefaultTolerance/time.Second) - 1, want: ErrTimestampOutsideTolerance},
		{name: "future outside boundary", now: vector.Timestamp + int64(DefaultTolerance/time.Second) + 1, want: ErrTimestampOutsideTolerance},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := keyring.Verify(headers, []byte(vector.Body), time.Unix(tt.now, 0))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Verify() error = %v, want errors.Is(_, %v)", err, tt.want)
			}
		})
	}
}

func TestKeyring_SignsAndVerifiesSecretRotation(t *testing.T) {
	current := "whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
	previous := "whsec_YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg="
	keyring, err := NewKeyring(current, previous)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	body := []byte(`{"event":"rotation"}`)
	headers, err := keyring.Sign("msg_rotation", time.Unix(1_700_000_000, 0), body)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if got := len(strings.Split(headers.Signature, " ")); got != 2 {
		t.Fatalf("signature count = %d, want 2", got)
	}

	for _, secret := range []string{current, previous} {
		verifier, err := NewKeyring(secret)
		if err != nil {
			t.Fatalf("NewKeyring() error = %v", err)
		}
		if err := verifier.Verify(headers, body, time.Unix(1_700_000_000, 0)); err != nil {
			t.Fatalf("Verify() error = %v, want nil", err)
		}
	}
}

func TestKeyring_RejectsMalformedHeadersWithoutSecretDisclosure(t *testing.T) {
	vector := loadTestVector(t)
	keyring, err := NewKeyring(vector.Secret)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	valid := Headers{ID: vector.ID, Timestamp: "1674087231", Signature: vector.Signature}

	tests := []struct {
		name    string
		headers Headers
		want    error
	}{
		{name: "empty ID", headers: Headers{Timestamp: valid.Timestamp, Signature: valid.Signature}, want: ErrInvalidHeaders},
		{name: "ID contains delimiter", headers: Headers{ID: "msg.invalid", Timestamp: valid.Timestamp, Signature: valid.Signature}, want: ErrInvalidHeaders},
		{name: "invalid timestamp", headers: Headers{ID: valid.ID, Timestamp: "not-a-timestamp", Signature: valid.Signature}, want: ErrInvalidHeaders},
		{name: "unsupported version", headers: Headers{ID: valid.ID, Timestamp: valid.Timestamp, Signature: "v2,AAAA"}, want: ErrUnsupportedSignatureVersion},
		{name: "asymmetric version outside profile", headers: Headers{ID: valid.ID, Timestamp: valid.Timestamp, Signature: "v1a,AAAA"}, want: ErrUnsupportedSignatureVersion},
		{name: "invalid encoding", headers: Headers{ID: valid.ID, Timestamp: valid.Timestamp, Signature: "v1,%%%"}, want: ErrInvalidHeaders},
		{name: "empty signature entry", headers: Headers{ID: valid.ID, Timestamp: valid.Timestamp, Signature: valid.Signature + "  " + valid.Signature}, want: ErrInvalidHeaders},
		{name: "unknown mixed version", headers: Headers{ID: valid.ID, Timestamp: valid.Timestamp, Signature: valid.Signature + " v2,AAAA"}, want: ErrUnsupportedSignatureVersion},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := keyring.Verify(tt.headers, []byte(vector.Body), time.Unix(vector.Timestamp, 0))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Verify() error = %v, want errors.Is(_, %v)", err, tt.want)
			}
			if strings.Contains(err.Error(), vector.Secret) {
				t.Fatalf("Verify() error exposed a secret: %q", err)
			}
		})
	}
}

func TestNewKeyring_RejectsInvalidSecrets(t *testing.T) {
	tests := []struct {
		name    string
		secrets []string
	}{
		{name: "missing", secrets: nil},
		{name: "too many", secrets: []string{"whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=", "whsec_YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg=", "whsec_MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="}},
		{name: "wrong prefix", secrets: []string{"secret"}},
		{name: "malformed base64", secrets: []string{"whsec_%%%"}},
		{name: "too short", secrets: []string{"whsec_c2hvcnQ="}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewKeyring(tt.secrets...)
			if !errors.Is(err, ErrInvalidSecret) {
				t.Fatalf("NewKeyring() error = %v, want errors.Is(_, %v)", err, ErrInvalidSecret)
			}
		})
	}
}

func TestKeyring_StringDoesNotExposeSecrets(t *testing.T) {
	vector := loadTestVector(t)
	keyring, err := NewKeyring(vector.Secret)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	if strings.Contains(keyring.String(), vector.Secret) {
		t.Fatalf("String() exposed a secret: %q", keyring.String())
	}
}

func FuzzKeyring_Verify(f *testing.F) {
	vector := loadTestVectorForFuzz(f)
	f.Add(vector.ID, "1674087231", vector.Signature, vector.Body)
	f.Add("", "invalid", "v2,AAAA", "body")

	f.Fuzz(func(t *testing.T, id, timestamp, signature, body string) {
		keyring, err := NewKeyring(vector.Secret)
		if err != nil {
			t.Fatalf("NewKeyring() error = %v", err)
		}
		_ = keyring.Verify(Headers{ID: id, Timestamp: timestamp, Signature: signature}, []byte(body), time.Unix(1_674_087_231, 0))
	})
}

func loadTestVector(t *testing.T) testVector {
	t.Helper()
	return loadVector(t)
}

func loadTestVectorForFuzz(f *testing.F) testVector {
	f.Helper()
	return loadVector(f)
}

type testHelper interface {
	Helper()
	Fatalf(string, ...any)
}

func loadVector(t testHelper) testVector {
	document, err := os.ReadFile(filepath.Join("testdata", "standard-v1-vector.json"))
	if err != nil {
		t.Fatalf("read test vector: %v", err)
	}
	var vector testVector
	if err := json.Unmarshal(document, &vector); err != nil {
		t.Fatalf("decode test vector: %v", err)
	}
	return vector
}
