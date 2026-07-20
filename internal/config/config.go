// Package config loads and validates the standalone Pulse Agent configuration.
package config

import (
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"pulse-agent/internal/contract"
)

const (
	// SchemaVersion is the supported configuration schema version.
	SchemaVersion = contract.SchemaVersionV1
	// MaxDocumentBytes is the largest accepted standalone configuration document.
	MaxDocumentBytes  = contract.MaxDocumentBytes
	maxAllowedTargets = 10_000
	maxRetentionAge   = 365 * 24 * time.Hour
	maxRetentionBytes = 1 << 40
	maxGeminiTimeout  = 2 * time.Minute
)

var (
	// ErrInvalidConfig indicates a configuration that cannot safely start the agent.
	ErrInvalidConfig = errors.New("invalid configuration")
	// ErrConfigTooLarge indicates a configuration document above the configured limit.
	ErrConfigTooLarge = errors.New("configuration document exceeds size limit")
)

var secretReferencePattern = regexp.MustCompile(`^env:[A-Za-z_][A-Za-z0-9_]*$`)

// UsageMode identifies whether a configuration processes production or only
// synthetic development data.
type UsageMode string

const (
	// UsageProduction permits production observations after all production safeguards pass.
	UsageProduction UsageMode = "production"
	// UsageSyntheticDevelopment permits only synthetic development observations.
	UsageSyntheticDevelopment UsageMode = "synthetic_development"
)

// DataProcessingMode describes the operator-declared Gemini project mode.
type DataProcessingMode string

const (
	// DataProcessingBillingEnabled identifies a billing-enabled Gemini project.
	DataProcessingBillingEnabled DataProcessingMode = "billing_enabled"
	// DataProcessingUnpaidOrFree identifies an unpaid or free Gemini project.
	DataProcessingUnpaidOrFree DataProcessingMode = "unpaid_or_free"
)

// SecretReference identifies an allowed secret source without containing a secret.
type SecretReference string

// Config is the single JSON source of truth for standalone runtime settings.
type Config struct {
	SchemaVersion     string          `json:"schema_version"`
	UsageMode         UsageMode       `json:"usage_mode"`
	DataDirectory     string          `json:"data_directory"`
	EvidenceDirectory string          `json:"evidence_directory"`
	Docker            DockerConfig    `json:"docker"`
	Admin             AdminConfig     `json:"admin"`
	Limits            LimitsConfig    `json:"limits"`
	AllowedTargets    []AllowedTarget `json:"allowed_targets"`
	Gemini            GeminiConfig    `json:"gemini"`
	Webhooks          WebhooksConfig  `json:"webhooks"`
}

// DockerConfig identifies the local Docker Engine endpoint.
type DockerConfig struct {
	Endpoint string `json:"endpoint"`
}

// AdminConfig identifies the daemon-owned local administrative socket path.
type AdminConfig struct {
	SocketPath string `json:"socket_path"`
}

// LimitsConfig bounds target registration and locally retained evidence.
type LimitsConfig struct {
	MaxTargets int             `json:"max_targets"`
	Retention  RetentionConfig `json:"retention"`
}

// RetentionConfig bounds the age and total size of retained local evidence.
type RetentionConfig struct {
	MaxAge   contract.Duration `json:"max_age"`
	MaxBytes int64             `json:"max_bytes"`
}

// AllowedTarget identifies a target class allowed by the local configuration.
type AllowedTarget struct {
	TargetID    string `json:"target_id"`
	AdapterType string `json:"adapter_type"`
}

// GeminiConfig contains Gemini settings without ever containing an API key.
type GeminiConfig struct {
	Provider           string             `json:"provider"`
	Model              string             `json:"model"`
	Timeout            contract.Duration  `json:"timeout"`
	DataProcessingMode DataProcessingMode `json:"data_processing_mode"`
	APIKeyRef          SecretReference    `json:"api_key_ref"`
}

// WebhooksConfig contains independent inbound and outbound webhook settings.
type WebhooksConfig struct {
	Ingress  WebhookConfig `json:"ingress"`
	Outbound WebhookConfig `json:"outbound"`
}

// WebhookConfig identifies one webhook endpoint and signing secret reference.
type WebhookConfig struct {
	Endpoint  string          `json:"endpoint"`
	SecretRef SecretReference `json:"secret_ref"`
}

// Load reads one configuration file and applies the same validation used before
// standalone startup. It only reads the supplied file and never resolves secrets.
func Load(path string) (Config, error) {
	document, err := readDocument(path)
	if err != nil {
		return Config{}, err
	}
	return Decode(document)
}

// Decode parses and validates one in-memory configuration document.
func Decode(document []byte) (Config, error) {
	return contract.Decode(document, contract.DecodeOptions[Config]{
		MaxBytes:      MaxDocumentBytes,
		SchemaVersion: SchemaVersion,
		Validate:      func(value Config) error { return value.Validate() },
	})
}

// Validate checks all configuration invariants without accessing the network,
// daemon, database, filesystem paths, or secret sources.
func (c Config) Validate() error {
	if c.SchemaVersion != SchemaVersion || !isUsageMode(c.UsageMode) || !isAbsoluteCleanPath(c.DataDirectory) {
		return ErrInvalidConfig
	}
	if !isContainedCleanPath(c.DataDirectory, c.EvidenceDirectory) || !isContainedCleanPath(c.DataDirectory, c.Admin.SocketPath) {
		return ErrInvalidConfig
	}
	if !isUnixSocketEndpoint(c.Docker.Endpoint) {
		return ErrInvalidConfig
	}
	if c.Limits.MaxTargets < 1 || c.Limits.MaxTargets > maxAllowedTargets {
		return ErrInvalidConfig
	}
	if c.Limits.Retention.MaxAge.Value() <= 0 || c.Limits.Retention.MaxAge.Value() > maxRetentionAge || c.Limits.Retention.MaxBytes < 1 || c.Limits.Retention.MaxBytes > maxRetentionBytes {
		return ErrInvalidConfig
	}
	if err := validateAllowedTargets(c.AllowedTargets, c.Limits.MaxTargets); err != nil {
		return err
	}
	if err := c.Gemini.validate(c.UsageMode); err != nil {
		return err
	}
	if err := c.Webhooks.validate(c.UsageMode); err != nil {
		return err
	}
	return nil
}

func readDocument(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	defer file.Close()

	document, err := io.ReadAll(io.LimitReader(file, MaxDocumentBytes+1))
	if err != nil {
		return nil, ErrInvalidConfig
	}
	if len(document) > MaxDocumentBytes {
		return nil, ErrConfigTooLarge
	}
	return document, nil
}

func isUsageMode(value UsageMode) bool {
	return value == UsageProduction || value == UsageSyntheticDevelopment
}

func isAbsoluteCleanPath(value string) bool {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return false
	}
	return !hasParentSegment(value)
}

func isContainedCleanPath(root, value string) bool {
	if !isAbsoluteCleanPath(value) {
		return false
	}
	relative, err := filepath.Rel(root, value)
	if err != nil || relative == "." || relative == ".." {
		return false
	}
	return !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func hasParentSegment(value string) bool {
	for _, segment := range strings.Split(filepath.ToSlash(value), "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

func isUnixSocketEndpoint(value string) bool {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Scheme != "unix" || endpoint.Host != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.User != nil {
		return false
	}
	return isAbsoluteCleanPath(endpoint.Path)
}

func validateAllowedTargets(targets []AllowedTarget, maxTargets int) error {
	if len(targets) > maxTargets {
		return ErrInvalidConfig
	}
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if target.TargetID == "" || target.AdapterType != "docker" {
			return ErrInvalidConfig
		}
		if _, duplicate := seen[target.TargetID]; duplicate {
			return ErrInvalidConfig
		}
		seen[target.TargetID] = struct{}{}
	}
	return nil
}

func (c GeminiConfig) validate(usageMode UsageMode) error {
	if c.Provider != "gemini" || c.Model == "" || c.Timeout.Value() <= 0 || c.Timeout.Value() > maxGeminiTimeout {
		return ErrInvalidConfig
	}
	if c.DataProcessingMode != DataProcessingBillingEnabled && c.DataProcessingMode != DataProcessingUnpaidOrFree {
		return ErrInvalidConfig
	}
	if usageMode == UsageProduction && c.DataProcessingMode != DataProcessingBillingEnabled {
		return ErrInvalidConfig
	}
	if !isSecretReference(c.APIKeyRef) {
		return ErrInvalidConfig
	}
	return nil
}

func (c WebhooksConfig) validate(usageMode UsageMode) error {
	if !isWebhookEndpoint(c.Ingress.Endpoint, usageMode) || !isSecretReference(c.Ingress.SecretRef) {
		return ErrInvalidConfig
	}
	if !isWebhookEndpoint(c.Outbound.Endpoint, usageMode) || !isSecretReference(c.Outbound.SecretRef) {
		return ErrInvalidConfig
	}
	return nil
}

func isSecretReference(value SecretReference) bool {
	return secretReferencePattern.MatchString(string(value))
}

func isWebhookEndpoint(value string, usageMode UsageMode) bool {
	endpoint, err := url.ParseRequestURI(value)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return false
	}
	loopback := isLoopbackHost(endpoint.Hostname())
	switch endpoint.Scheme {
	case "https":
		return usageMode == UsageSyntheticDevelopment || !loopback
	case "http":
		return usageMode == UsageSyntheticDevelopment && loopback
	default:
		return false
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
