// Package llm provides the bounded ADK model.LLM boundary used by Pulse Agent.
package llm

import (
	"context"
	"errors"
	"iter"
	"net/http"
	"strings"
	"time"

	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/model/gemini"
	"google.golang.org/genai"

	"pulse-agent/internal/config"
)

const (
	maxQuotaAttempts = 3
	maxTimeout       = 2 * time.Minute
)

var (
	// ErrInvalidOptions indicates an incomplete or unsafe model configuration.
	ErrInvalidOptions = errors.New("invalid llm options")
	// ErrSecretUnavailable indicates that a configured secret reference could not
	// be resolved. It intentionally does not expose the resolver error.
	ErrSecretUnavailable = errors.New("llm secret unavailable")
	// ErrUnavailable indicates that the configured model provider could not be used.
	ErrUnavailable = errors.New("llm unavailable")
	// ErrTimeout indicates that model work exceeded its configured context deadline.
	ErrTimeout = errors.New("llm timeout")
	// ErrQuota indicates that the model provider rejected a request for quota.
	ErrQuota = errors.New("llm quota exceeded")
	// ErrMalformedResponse indicates an incomplete or invalid provider response.
	ErrMalformedResponse = errors.New("llm malformed response")
	// ErrToolsForbidden indicates that this model boundary was given executable tools.
	ErrToolsForbidden = errors.New("llm tools are forbidden")
)

// SecretResolver resolves a configured reference at model construction time.
// Implementations must not log or persist the resolved value.
type SecretResolver interface {
	Resolve(ctx context.Context, reference config.SecretReference) (string, error)
}

// SecretResolverFunc adapts a function to SecretResolver.
type SecretResolverFunc func(context.Context, config.SecretReference) (string, error)

// Resolve resolves one secret reference.
func (f SecretResolverFunc) Resolve(ctx context.Context, reference config.SecretReference) (string, error) {
	if f == nil {
		return "", ErrSecretUnavailable
	}
	return f(ctx, reference)
}

// QuotaPolicy bounds the number of provider attempts for one non-streaming
// request. Retries only happen before any response is emitted.
type QuotaPolicy struct {
	MaxAttempts int
}

// GeminiOptions configures the official Gemini model adapter. APIKeyRef is a
// reference only; this type deliberately has no API key value field.
type GeminiOptions struct {
	Provider       string
	ModelName      string
	Timeout        time.Duration
	QuotaPolicy    QuotaPolicy
	APIKeyRef      config.SecretReference
	SecretResolver SecretResolver
	Transport      http.RoundTripper
}

// NewGeminiFromConfig creates the official Gemini model from the validated
// model-related configuration while keeping the resolved API key out of config.
func NewGeminiFromConfig(ctx context.Context, settings config.GeminiConfig, quota QuotaPolicy, resolver SecretResolver, transport http.RoundTripper) (model.LLM, error) {
	return NewGemini(ctx, GeminiOptions{
		Provider:       settings.Provider,
		ModelName:      settings.Model,
		Timeout:        settings.Timeout.Value(),
		QuotaPolicy:    quota,
		APIKeyRef:      settings.APIKeyRef,
		SecretResolver: resolver,
		Transport:      transport,
	})
}

// NewGemini creates a bounded official Gemini implementation of model.LLM.
// A supplied Transport is used verbatim, which makes tests hermetic without
// modifying global HTTP state.
func NewGemini(ctx context.Context, options GeminiOptions) (model.LLM, error) {
	if ctx == nil || !validOptions(options) {
		return nil, ErrInvalidOptions
	}

	apiKey, err := options.SecretResolver.Resolve(ctx, options.APIKeyRef)
	if err != nil || apiKey == "" {
		return nil, ErrSecretUnavailable
	}

	httpClient := &http.Client{Timeout: options.Timeout, Transport: options.Transport}
	delegate, err := gemini.NewModel(ctx, options.ModelName, &genai.ClientConfig{
		APIKey:     apiKey,
		Backend:    genai.BackendGeminiAPI,
		HTTPClient: httpClient,
	})
	if err != nil {
		return nil, ErrUnavailable
	}

	return &boundedModel{
		delegate:    delegate,
		modelName:   options.ModelName,
		timeout:     options.Timeout,
		maxAttempts: options.QuotaPolicy.MaxAttempts,
	}, nil
}

func validOptions(options GeminiOptions) bool {
	return options.Provider == "gemini" && strings.TrimSpace(options.ModelName) != "" &&
		options.Timeout > 0 && options.Timeout <= maxTimeout && options.QuotaPolicy.MaxAttempts >= 1 &&
		options.QuotaPolicy.MaxAttempts <= maxQuotaAttempts && options.APIKeyRef != "" &&
		options.SecretResolver != nil
}

type boundedModel struct {
	delegate    model.LLM
	modelName   string
	timeout     time.Duration
	maxAttempts int
}

// Name returns the fixed model name configured at construction time.
func (m *boundedModel) Name() string {
	if m == nil {
		return ""
	}
	return m.modelName
}

// GenerateContent enforces the configured model name, context deadline, retry
// bound, and tool prohibition before delegating to the official ADK adapter.
func (m *boundedModel) GenerateContent(ctx context.Context, request *model.LLMRequest, stream bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		if m == nil || m.delegate == nil || ctx == nil || request == nil {
			yield(nil, ErrInvalidOptions)
			return
		}
		if len(request.Tools) != 0 {
			yield(nil, ErrToolsForbidden)
			return
		}

		for attempt := 0; attempt < m.maxAttempts; attempt++ {
			callContext, cancel := context.WithTimeout(ctx, m.timeout)
			shouldRetry, completed := m.generateOnce(callContext, request, stream, yield)
			cancel()
			if shouldRetry {
				if attempt+1 < m.maxAttempts {
					continue
				}
				yield(nil, ErrQuota)
				return
			}
			if stream && !completed {
				yield(nil, ErrMalformedResponse)
			}
			return
		}
	}
}

func (m *boundedModel) generateOnce(ctx context.Context, request *model.LLMRequest, stream bool, yield func(*model.LLMResponse, error) bool) (retry bool, completed bool) {
	requestCopy := copyRequest(request, m.modelName)
	emitted := false
	for response, err := range m.delegate.GenerateContent(ctx, &requestCopy, stream) {
		if err != nil {
			classified := classifyError(ctx, err)
			if classified == ErrQuota && !stream && !emitted {
				return true, false
			}
			yield(nil, classified)
			return false, false
		}
		if response == nil {
			yield(nil, ErrMalformedResponse)
			return false, false
		}
		emitted = true
		completed = completed || response.TurnComplete
		if !yield(response, nil) {
			return false, completed
		}
	}
	return false, completed || !stream
}

func copyRequest(request *model.LLMRequest, modelName string) model.LLMRequest {
	copy := *request
	copy.Model = modelName
	copy.Contents = append([]*genai.Content(nil), request.Contents...)
	copy.Tools = nil
	if request.Config == nil {
		return copy
	}

	configCopy := *request.Config
	if request.Config.HTTPOptions != nil {
		httpOptionsCopy := *request.Config.HTTPOptions
		httpOptionsCopy.Headers = request.Config.HTTPOptions.Headers.Clone()
		configCopy.HTTPOptions = &httpOptionsCopy
	}
	copy.Config = &configCopy
	return copy
}

func classifyError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	var apiError genai.APIError
	if errors.As(err, &apiError) && apiError.Code == http.StatusTooManyRequests {
		return ErrQuota
	}
	if errors.Is(err, ErrTimeout) || errors.Is(err, ErrQuota) || errors.Is(err, ErrMalformedResponse) || errors.Is(err, ErrToolsForbidden) {
		return err
	}
	return ErrUnavailable
}

var _ model.LLM = (*boundedModel)(nil)
