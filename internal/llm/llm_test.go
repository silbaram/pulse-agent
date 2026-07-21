package llm

import (
	"context"
	"errors"
	"io"
	"iter"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/adk/v2/model"
	"google.golang.org/genai"

	"pulse-agent/internal/config"
	"pulse-agent/internal/contract"
)

func TestFake_GenerateContentScenarios(t *testing.T) {
	t.Parallel()

	request := &model.LLMRequest{Contents: []*genai.Content{genai.NewContentFromText("synthetic evidence", "user")}}
	tests := []struct {
		name      string
		events    []FakeEvent
		stream    bool
		wantCount int
		wantError error
	}{
		{
			name:      "response",
			events:    []FakeEvent{{Response: response("analysis", false, true)}},
			wantCount: 1,
		},
		{
			name:      "timeout",
			events:    []FakeEvent{{Err: context.DeadlineExceeded}},
			wantError: ErrTimeout,
		},
		{
			name:      "quota",
			events:    []FakeEvent{{Err: ErrQuota}},
			wantError: ErrQuota,
		},
		{
			name:      "malformed",
			events:    []FakeEvent{{}},
			wantError: ErrMalformedResponse,
		},
		{
			name: "stream completes",
			events: []FakeEvent{
				{Response: response("partial", true, false)},
				{Response: response("complete", false, true)},
			},
			stream:    true,
			wantCount: 2,
		},
		{
			name:      "stream without terminal response",
			events:    []FakeEvent{{Response: response("partial", true, false)}},
			stream:    true,
			wantCount: 1,
			wantError: ErrMalformedResponse,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fake, err := NewFake("fake-model", test.events)
			if err != nil {
				t.Fatalf("NewFake() error = %v", err)
			}

			responses, err := collect(fake.GenerateContent(context.Background(), request, test.stream))
			if !errors.Is(err, test.wantError) {
				t.Fatalf("GenerateContent() error = %v, want errors.Is(_, %v)", err, test.wantError)
			}
			if len(responses) != test.wantCount {
				t.Fatalf("response count = %d, want %d", len(responses), test.wantCount)
			}
		})
	}
}

func TestFake_RejectsTools(t *testing.T) {
	t.Parallel()

	fake, err := NewFake("fake-model", []FakeEvent{{Response: response("unused", false, true)}})
	if err != nil {
		t.Fatalf("NewFake() error = %v", err)
	}
	_, err = collect(fake.GenerateContent(context.Background(), &model.LLMRequest{Tools: map[string]any{"shell": "forbidden"}}, false))
	if !errors.Is(err, ErrToolsForbidden) {
		t.Fatalf("GenerateContent() error = %v, want errors.Is(_, ErrToolsForbidden)", err)
	}
}

func TestNewGemini_UsesHermeticTransportAndFixedModel(t *testing.T) {
	t.Parallel()

	transport := &responseTransport{responses: []transportResponse{{
		body: `{"candidates":[{"content":{"role":"model","parts":[{"text":"safe result"}]}}]}`,
	}}}
	llmModel, err := NewGemini(context.Background(), GeminiOptions{
		Provider:    "gemini",
		ModelName:   "gemini-2.5-flash",
		Timeout:     time.Second,
		QuotaPolicy: QuotaPolicy{MaxAttempts: 1},
		APIKeyRef:   config.SecretReference("env:PULSE_AGENT_GEMINI_KEY"),
		SecretResolver: SecretResolverFunc(func(_ context.Context, reference config.SecretReference) (string, error) {
			if reference != "env:PULSE_AGENT_GEMINI_KEY" {
				t.Fatalf("Resolve() reference = %q", reference)
			}
			return "synthetic-api-key", nil
		}),
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("NewGemini() error = %v", err)
	}
	if llmModel.Name() != "gemini-2.5-flash" {
		t.Fatalf("Name() = %q", llmModel.Name())
	}

	request := &model.LLMRequest{
		Model:    "caller-cannot-override",
		Contents: []*genai.Content{genai.NewContentFromText("synthetic evidence", "user")},
	}
	responses, err := collect(llmModel.GenerateContent(context.Background(), request, false))
	if err != nil {
		t.Fatalf("GenerateContent() error = %v", err)
	}
	if len(responses) != 1 || responses[0].Content == nil {
		t.Fatalf("responses = %+v", responses)
	}
	if got := transport.requestPath(); !strings.Contains(got, "gemini-2.5-flash") {
		t.Fatalf("request path = %q, want fixed configured model", got)
	}
	if transport.calls() != 1 {
		t.Fatalf("transport calls = %d, want 1", transport.calls())
	}
}

func TestNewGemini_QuotaRetryIsBounded(t *testing.T) {
	t.Parallel()

	transport := &responseTransport{responses: []transportResponse{
		{status: http.StatusTooManyRequests, body: `{"error":{"code":429,"message":"quota","status":"RESOURCE_EXHAUSTED"}}`},
		{body: `{"candidates":[{"content":{"role":"model","parts":[{"text":"after retry"}]}}]}`},
	}}
	model := newHermeticGemini(t, transport, QuotaPolicy{MaxAttempts: 2})

	responses, err := collect(model.GenerateContent(context.Background(), testRequest(), false))
	if err != nil {
		t.Fatalf("GenerateContent() error = %v", err)
	}
	if len(responses) != 1 || transport.calls() != 2 {
		t.Fatalf("responses = %d, calls = %d, want 1 response after 2 calls", len(responses), transport.calls())
	}
}

func TestNewGemini_QuotaRetryStopsAtPolicyLimit(t *testing.T) {
	t.Parallel()

	transport := &responseTransport{responses: []transportResponse{
		{status: http.StatusTooManyRequests, body: `{"error":{"code":429,"message":"quota","status":"RESOURCE_EXHAUSTED"}}`},
		{status: http.StatusTooManyRequests, body: `{"error":{"code":429,"message":"quota","status":"RESOURCE_EXHAUSTED"}}`},
		{body: `{"candidates":[{"content":{"role":"model","parts":[{"text":"must not be requested"}]}}]}`},
	}}
	model := newHermeticGemini(t, transport, QuotaPolicy{MaxAttempts: 2})

	_, err := collect(model.GenerateContent(context.Background(), testRequest(), false))
	if !errors.Is(err, ErrQuota) {
		t.Fatalf("GenerateContent() error = %v, want errors.Is(_, ErrQuota)", err)
	}
	if transport.calls() != 2 {
		t.Fatalf("transport calls = %d, want 2", transport.calls())
	}
}

func TestNewGemini_RejectsToolsBeforeTransport(t *testing.T) {
	t.Parallel()

	transport := &responseTransport{}
	llmModel := newHermeticGemini(t, transport, QuotaPolicy{MaxAttempts: 1})
	_, err := collect(llmModel.GenerateContent(context.Background(), &model.LLMRequest{Tools: map[string]any{"shell": "forbidden"}}, false))
	if !errors.Is(err, ErrToolsForbidden) {
		t.Fatalf("GenerateContent() error = %v, want errors.Is(_, ErrToolsForbidden)", err)
	}
	if transport.calls() != 0 {
		t.Fatalf("transport calls = %d, want 0", transport.calls())
	}
}

func TestNewGemini_DoesNotExposeSecretWhenUnavailable(t *testing.T) {
	t.Parallel()

	const secret = "synthetic-api-key"
	_, err := NewGemini(context.Background(), GeminiOptions{
		Provider:    "gemini",
		ModelName:   "gemini-2.5-flash",
		Timeout:     time.Second,
		QuotaPolicy: QuotaPolicy{MaxAttempts: 1},
		APIKeyRef:   config.SecretReference("env:PULSE_AGENT_GEMINI_KEY"),
		SecretResolver: SecretResolverFunc(func(context.Context, config.SecretReference) (string, error) {
			return "", errors.New(secret)
		}),
	})
	if !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("NewGemini() error = %v, want errors.Is(_, ErrSecretUnavailable)", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("NewGemini() error leaks secret %q", secret)
	}
}

func TestNewGemini_TimeoutAndUnexpectedTransportFailureAreBounded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport http.RoundTripper
		timeout   time.Duration
		wantError error
	}{
		{
			name: "timeout",
			transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				<-request.Context().Done()
				return nil, request.Context().Err()
			}),
			timeout:   25 * time.Millisecond,
			wantError: ErrTimeout,
		},
		{
			name: "unexpected dial",
			transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("unexpected external network dial synthetic-api-key")
			}),
			timeout:   time.Second,
			wantError: ErrUnavailable,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			model := newHermeticGemini(t, test.transport, QuotaPolicy{MaxAttempts: 1}, test.timeout)
			_, err := collect(model.GenerateContent(context.Background(), testRequest(), false))
			if !errors.Is(err, test.wantError) {
				t.Fatalf("GenerateContent() error = %v, want errors.Is(_, %v)", err, test.wantError)
			}
			if strings.Contains(err.Error(), "synthetic-api-key") {
				t.Fatalf("GenerateContent() error leaks secret: %v", err)
			}
		})
	}
}

func newHermeticGemini(t *testing.T, transport http.RoundTripper, quota QuotaPolicy, timeout ...time.Duration) model.LLM {
	t.Helper()

	requestTimeout := time.Second
	if len(timeout) == 1 {
		requestTimeout = timeout[0]
	}
	configured, err := NewGeminiFromConfig(context.Background(), config.GeminiConfig{
		Provider:  "gemini",
		Model:     "gemini-2.5-flash",
		Timeout:   contract.NewDuration(requestTimeout),
		APIKeyRef: config.SecretReference("env:PULSE_AGENT_GEMINI_KEY"),
	}, quota, SecretResolverFunc(func(context.Context, config.SecretReference) (string, error) {
		return "synthetic-api-key", nil
	}), transport)
	if err != nil {
		t.Fatalf("NewGemini() error = %v", err)
	}
	return configured
}

func testRequest() *model.LLMRequest {
	return &model.LLMRequest{Contents: []*genai.Content{genai.NewContentFromText("synthetic evidence", "user")}}
}

func response(text string, partial, complete bool) *model.LLMResponse {
	return &model.LLMResponse{
		Content:      genai.NewContentFromText(text, "model"),
		Partial:      partial,
		TurnComplete: complete,
	}
}

func collect(sequence iter.Seq2[*model.LLMResponse, error]) ([]*model.LLMResponse, error) {
	responses := make([]*model.LLMResponse, 0)
	for response, err := range sequence {
		if err != nil {
			return responses, err
		}
		responses = append(responses, response)
	}
	return responses, nil
}

type transportResponse struct {
	status int
	body   string
}

type responseTransport struct {
	mu        sync.Mutex
	responses []transportResponse
	paths     []string
}

func (t *responseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if request.URL.Host != "generativelanguage.googleapis.com" {
		return nil, errors.New("unexpected external network dial")
	}
	if len(t.responses) == 0 {
		return nil, errors.New("unexpected transport call")
	}
	response := t.responses[0]
	t.responses = t.responses[1:]
	t.paths = append(t.paths, request.URL.Path)
	status := response.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(response.body)),
		Request:    request,
	}, nil
}

func (t *responseTransport) calls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.paths)
}

func (t *responseTransport) requestPath() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.paths) == 0 {
		return ""
	}
	return t.paths[0]
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
