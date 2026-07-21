package llm

import (
	"context"
	"iter"

	"google.golang.org/adk/v2/model"
)

// FakeEvent is one deterministic response or failure emitted by Fake.
type FakeEvent struct {
	Response *model.LLMResponse
	Err      error
}

// Fake implements model.LLM without network access. Its event slice is copied
// at construction time to keep the configured event order stable.
type Fake struct {
	modelName string
	events    []FakeEvent
}

// NewFake creates a deterministic model.LLM test double.
func NewFake(modelName string, events []FakeEvent) (*Fake, error) {
	if modelName == "" || len(events) == 0 {
		return nil, ErrInvalidOptions
	}
	return &Fake{modelName: modelName, events: append([]FakeEvent(nil), events...)}, nil
}

// Name returns the configured fake model name.
func (f *Fake) Name() string {
	if f == nil {
		return ""
	}
	return f.modelName
}

// GenerateContent returns configured events in order and rejects tools. A
// streaming sequence must end in a TurnComplete response to be well formed.
func (f *Fake) GenerateContent(ctx context.Context, request *model.LLMRequest, stream bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		if f == nil || ctx == nil || request == nil {
			yield(nil, ErrInvalidOptions)
			return
		}
		if len(request.Tools) != 0 {
			yield(nil, ErrToolsForbidden)
			return
		}

		completed := false
		for _, event := range f.events {
			if err := ctx.Err(); err != nil {
				yield(nil, classifyError(ctx, err))
				return
			}
			if event.Err != nil {
				yield(nil, classifyError(ctx, event.Err))
				return
			}
			if event.Response == nil {
				yield(nil, ErrMalformedResponse)
				return
			}
			completed = completed || event.Response.TurnComplete
			if !yield(event.Response, nil) {
				return
			}
			if !stream {
				return
			}
		}
		if stream && !completed {
			yield(nil, ErrMalformedResponse)
		}
	}
}

var _ model.LLM = (*Fake)(nil)
