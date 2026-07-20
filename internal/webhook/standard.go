// Package webhook implements the Standard Webhooks v1 HMAC-SHA256 profile.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

const (
	// HeaderID is the Standard Webhooks header carrying a stable message ID.
	HeaderID = "webhook-id"
	// HeaderTimestamp is the Standard Webhooks header carrying Unix seconds.
	HeaderTimestamp = "webhook-timestamp"
	// HeaderSignature is the Standard Webhooks header carrying HMAC signatures.
	HeaderSignature = "webhook-signature"
	// SignatureVersionV1 identifies the Standard Webhooks HMAC-SHA256 profile.
	SignatureVersionV1 = "v1"
	// DefaultTolerance is the maximum allowed timestamp difference for verification.
	DefaultTolerance = 5 * time.Minute

	secretPrefix       = "whsec_"
	minimumSecretBytes = 24
	maximumSecretBytes = 64
	maximumMessageID   = 256
)

var (
	// ErrInvalidSecret indicates an invalid Standard Webhooks symmetric secret.
	ErrInvalidSecret = errors.New("invalid webhook secret")
	// ErrInvalidHeaders indicates missing or malformed Standard Webhooks headers.
	ErrInvalidHeaders = errors.New("invalid webhook headers")
	// ErrUnsupportedSignatureVersion indicates a signature version outside this profile.
	ErrUnsupportedSignatureVersion = errors.New("unsupported webhook signature version")
	// ErrTimestampOutsideTolerance indicates a replay-prone webhook timestamp.
	ErrTimestampOutsideTolerance = errors.New("webhook timestamp outside tolerance")
	// ErrInvalidTolerance indicates an unusable timestamp tolerance.
	ErrInvalidTolerance = errors.New("invalid webhook timestamp tolerance")
	// ErrSignatureMismatch indicates that no trusted signature authenticated the payload.
	ErrSignatureMismatch = errors.New("webhook signature mismatch")
)

// Headers contains the three Standard Webhooks signing headers. Body content is
// deliberately excluded because callers must pass the exact raw request bytes
// to Sign and Verify.
type Headers struct {
	ID        string
	Timestamp string
	Signature string
}

// Keyring stores a current secret and, optionally, its previous secret for
// zero-downtime rotation. A Keyring is immutable and safe for concurrent use.
type Keyring struct {
	secrets [][]byte
}

// NewKeyring validates one current secret and an optional previous secret. Each
// secret must use the Standard Webhooks whsec_ base64 serialization.
func NewKeyring(serializedSecrets ...string) (*Keyring, error) {
	if len(serializedSecrets) == 0 || len(serializedSecrets) > 2 {
		return nil, ErrInvalidSecret
	}

	secrets := make([][]byte, 0, len(serializedSecrets))
	for _, serialized := range serializedSecrets {
		secret, err := parseSecret(serialized)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}
	return &Keyring{secrets: secrets}, nil
}

// Sign produces Standard Webhooks headers for the exact raw body. It emits a
// v1 signature for the current secret and, when configured, the previous
// secret as a space-delimited rotation signature.
func (k *Keyring) Sign(id string, timestamp time.Time, rawBody []byte) (Headers, error) {
	if k == nil || len(k.secrets) == 0 || !validMessageID(id) || timestamp.Unix() < 0 {
		return Headers{}, ErrInvalidHeaders
	}

	timestampValue := strconv.FormatInt(timestamp.Unix(), 10)
	content := signingContent(id, timestampValue, rawBody)
	signatures := make([]string, 0, len(k.secrets))
	for _, secret := range k.secrets {
		signatures = append(signatures, signatureValue(secret, content))
	}
	return Headers{
		ID:        id,
		Timestamp: timestampValue,
		Signature: strings.Join(signatures, " "),
	}, nil
}

// Verify authenticates the exact raw body using the default five-minute
// timestamp tolerance.
func (k *Keyring) Verify(headers Headers, rawBody []byte, now time.Time) error {
	return k.VerifyWithTolerance(headers, rawBody, now, DefaultTolerance)
}

// VerifyWithTolerance authenticates the exact raw body using all configured
// current and previous secrets. It rejects malformed headers, unsupported
// versions, and timestamps outside tolerance before accepting a signature.
func (k *Keyring) VerifyWithTolerance(headers Headers, rawBody []byte, now time.Time, tolerance time.Duration) error {
	if k == nil || len(k.secrets) == 0 || !validMessageID(headers.ID) {
		return ErrInvalidHeaders
	}
	if tolerance < time.Second || now.Unix() < 0 {
		return ErrInvalidTolerance
	}

	timestamp, err := parseTimestamp(headers.Timestamp)
	if err != nil {
		return err
	}
	if !withinTolerance(timestamp, now.Unix(), int64(tolerance/time.Second)) {
		return ErrTimestampOutsideTolerance
	}
	signatures, err := parseSignatures(headers.Signature)
	if err != nil {
		return err
	}

	content := signingContent(headers.ID, headers.Timestamp, rawBody)
	matched := 0
	for _, secret := range k.secrets {
		expected := hmacDigest(secret, content)
		for _, signature := range signatures {
			matched |= subtle.ConstantTimeCompare(expected, signature)
		}
	}
	if matched != 1 {
		return ErrSignatureMismatch
	}
	return nil
}

// String returns a secret-free description for accidental diagnostic output.
func (k *Keyring) String() string {
	return "webhook keyring"
}

func parseSecret(serialized string) ([]byte, error) {
	if !strings.HasPrefix(serialized, secretPrefix) {
		return nil, ErrInvalidSecret
	}
	encoded := strings.TrimPrefix(serialized, secretPrefix)
	secret, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(secret) < minimumSecretBytes || len(secret) > maximumSecretBytes {
		return nil, ErrInvalidSecret
	}
	return secret, nil
}

func validMessageID(id string) bool {
	if id == "" || len(id) > maximumMessageID || strings.Contains(id, ".") {
		return false
	}
	for _, value := range id {
		if value <= ' ' || value == 0x7f {
			return false
		}
	}
	return true
}

func parseTimestamp(value string) (int64, error) {
	if value == "" {
		return 0, ErrInvalidHeaders
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, ErrInvalidHeaders
		}
	}
	timestamp, err := strconv.ParseInt(value, 10, 64)
	if err != nil || timestamp < 0 {
		return 0, ErrInvalidHeaders
	}
	return timestamp, nil
}

func withinTolerance(timestamp, now, toleranceSeconds int64) bool {
	if now >= timestamp {
		return now-timestamp <= toleranceSeconds
	}
	return timestamp-now <= toleranceSeconds
}

func parseSignatures(value string) ([][]byte, error) {
	if value == "" || strings.Trim(value, " ") != value || strings.ContainsAny(value, "\t\r\n") {
		return nil, ErrInvalidHeaders
	}

	parts := strings.Split(value, " ")
	signatures := make([][]byte, 0, len(parts))
	for _, part := range parts {
		version, encoded, found := strings.Cut(part, ",")
		if !found || version == "" || encoded == "" || strings.Contains(encoded, ",") {
			return nil, ErrInvalidHeaders
		}
		if version != SignatureVersionV1 {
			return nil, ErrUnsupportedSignatureVersion
		}
		signature, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(signature) != sha256.Size {
			return nil, ErrInvalidHeaders
		}
		signatures = append(signatures, signature)
	}
	return signatures, nil
}

func signingContent(id, timestamp string, rawBody []byte) []byte {
	prefix := []byte(id + "." + timestamp + ".")
	content := make([]byte, 0, len(prefix)+len(rawBody))
	content = append(content, prefix...)
	return append(content, rawBody...)
}

func signatureValue(secret, content []byte) string {
	return SignatureVersionV1 + "," + base64.StdEncoding.EncodeToString(hmacDigest(secret, content))
}

func hmacDigest(secret, content []byte) []byte {
	hasher := hmac.New(sha256.New, secret)
	// hash.Hash.Write is specified to return a nil error.
	_, _ = hasher.Write(content)
	return hasher.Sum(nil)
}
