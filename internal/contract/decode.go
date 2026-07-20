package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxDocumentBytes is the default maximum size for one untrusted JSON contract.
const MaxDocumentBytes = 64 * 1024

var (
	// ErrDocumentTooLarge indicates a JSON document exceeded its configured limit.
	ErrDocumentTooLarge = errors.New("JSON document exceeds size limit")
	// ErrDuplicateField indicates any JSON object repeated a field name.
	ErrDuplicateField = errors.New("duplicate JSON field")
	// ErrUnknownField indicates a JSON field is outside a strict contract.
	ErrUnknownField = errors.New("unknown JSON field")
	// ErrTrailingData indicates content followed one complete JSON value.
	ErrTrailingData = errors.New("trailing JSON data")
	// ErrUnsupportedSchemaVersion indicates a document used an unsupported schema.
	ErrUnsupportedSchemaVersion = errors.New("unsupported schema version")
	// ErrInvalidJSON indicates malformed or type-incompatible JSON.
	ErrInvalidJSON = errors.New("invalid JSON document")
	// ErrInvalidDecodeOptions indicates an incomplete decoder configuration.
	ErrInvalidDecodeOptions = errors.New("invalid JSON decoder options")
)

// DecodeOptions configures strict decoding for one versioned contract.
type DecodeOptions[T any] struct {
	MaxBytes      int
	SchemaVersion string
	Validate      func(T) error
}

// Decode parses one JSON object, rejects ambiguous or unsupported input, and
// applies the caller's domain validation before returning a value.
func Decode[T any](document []byte, options DecodeOptions[T]) (T, error) {
	var zero T
	maxBytes := options.MaxBytes
	if maxBytes == 0 {
		maxBytes = MaxDocumentBytes
	}
	if maxBytes < 0 || options.SchemaVersion == "" || options.Validate == nil {
		return zero, ErrInvalidDecodeOptions
	}
	if len(document) > maxBytes {
		return zero, ErrDocumentTooLarge
	}
	if err := scanDocument(document); err != nil {
		return zero, err
	}

	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(document, &header); err != nil {
		return zero, ErrInvalidJSON
	}
	if header.SchemaVersion != options.SchemaVersion {
		return zero, ErrUnsupportedSchemaVersion
	}

	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return zero, ErrUnknownField
		}
		return zero, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	if err := ensureEnd(decoder); err != nil {
		return zero, err
	}
	if err := options.Validate(value); err != nil {
		return zero, err
	}
	return value, nil
}

func scanDocument(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	if err := scanValue(decoder); err != nil {
		return err
	}
	return ensureEnd(decoder)
}

func scanValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidJSON
	}

	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return ErrInvalidJSON
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidJSON
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrDuplicateField
			}
			seen[key] = struct{}{}
			if err := scanValue(decoder); err != nil {
				return err
			}
		}
		return closeDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := scanValue(decoder); err != nil {
				return err
			}
		}
		return closeDelimiter(decoder, ']')
	default:
		return ErrInvalidJSON
	}
}

func closeDelimiter(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidJSON
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != want {
		return ErrInvalidJSON
	}
	return nil
}

func ensureEnd(decoder *json.Decoder) error {
	_, err := decoder.Token()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return ErrTrailingData
	}
	return ErrInvalidJSON
}
