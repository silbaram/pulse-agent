package docker

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/evidence"
)

func TestAdapterLifecycleUsesBoundedSDKCalls(t *testing.T) {
	fake := &fakeClient{containers: map[string]Container{"web": {ID: "container-web", Running: true, Health: "healthy"}}, logs: "password=top-secret\nready\n"}
	adapter := newAdapter(t, fake)
	target := containerTarget()
	ctx := context.Background()

	values, err := adapter.Observe(ctx, target, availabilityRule())
	if err != nil || values["availability"] != 1 {
		t.Fatalf("Observe() = %v, %v", values, err)
	}
	evidenceResult, err := adapter.CollectEvidence(ctx, target)
	if err != nil {
		t.Fatalf("CollectEvidence() error = %v", err)
	}
	if evidenceResult.Reference.ByteCount > 32 || strings.Contains(evidenceResult.Content, "top-secret") {
		t.Fatalf("CollectEvidence() returned unbounded or unredacted content: %#v", evidenceResult)
	}
	action := contract.TypedAction{ActionType: contract.ActionDockerContainerRestart, TargetSelector: target.Selector, StopTimeout: contract.NewDuration(time.Second)}
	if err := adapter.ValidateAction(ctx, target, action); err != nil {
		t.Fatalf("ValidateAction() error = %v", err)
	}
	if err := adapter.Execute(ctx, target, action); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	verified, err := adapter.Verify(ctx, target)
	if err != nil || !verified.Healthy || fake.restartCalls != 1 {
		t.Fatalf("Verify()/restart = %#v, %v, calls=%d", verified, err, fake.restartCalls)
	}
	if fake.negotiations != 1 || !fake.sawDeadline {
		t.Fatalf("SDK negotiation/deadline = negotiations=%d sawDeadline=%t", fake.negotiations, fake.sawDeadline)
	}
}

func TestAdapter_UnhealthyRunningTargetCanTriggerAndReceiveRestart(t *testing.T) {
	fake := &fakeClient{containers: map[string]Container{"web": {ID: "container-web", Running: true, Health: "unhealthy"}}}
	adapter := newAdapter(t, fake)
	target := containerTarget()
	action := contract.TypedAction{ActionType: contract.ActionDockerContainerRestart, TargetSelector: target.Selector, StopTimeout: contract.NewDuration(time.Second)}

	values, err := adapter.Observe(context.Background(), target, availabilityRule())
	if err != nil || values["availability"] != 0 {
		t.Fatalf("Observe() = %v, %v, want unavailable unhealthy target", values, err)
	}
	if err := adapter.ValidateAction(context.Background(), target, action); err != nil {
		t.Fatalf("ValidateAction() error = %v, want running unhealthy target to be eligible", err)
	}
	if err := adapter.Execute(context.Background(), target, action); err != nil {
		t.Fatalf("Execute() error = %v, want restart", err)
	}
	if fake.restartCalls != 1 {
		t.Fatalf("Restart() calls = %d, want 1", fake.restartCalls)
	}
}

func TestAdapterComposeRestartRequiresExactlyOneLabeledReplica(t *testing.T) {
	target := composeTarget()
	action := contract.TypedAction{ActionType: contract.ActionDockerComposeServiceRestart, TargetSelector: target.Selector}
	for _, test := range []struct {
		name       string
		containers []Container
		want       error
	}{
		{name: "zero replicas", want: ErrAmbiguousTarget},
		{name: "two replicas", containers: []Container{{ID: "one", Running: true, Labels: map[string]string{composeServiceLabel: "web"}}, {ID: "two", Running: true, Labels: map[string]string{composeServiceLabel: "web"}}}, want: ErrAmbiguousTarget},
		{name: "missing label", containers: []Container{{ID: "one", Running: true, Labels: map[string]string{}}}, want: ErrAmbiguousTarget},
		{name: "one healthy replica", containers: []Container{{ID: "one", Running: true, Health: "healthy", Labels: map[string]string{composeServiceLabel: "web"}}}},
		{name: "one unhealthy replica", containers: []Container{{ID: "one", Running: true, Health: "unhealthy", Labels: map[string]string{composeServiceLabel: "web"}}}},
		{name: "stopped replica", containers: []Container{{ID: "one", Running: false, Labels: map[string]string{composeServiceLabel: "web"}}}, want: ErrPrecondition},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeClient{listed: test.containers}
			adapter := newAdapter(t, fake)
			err := adapter.Execute(context.Background(), target, action)
			if !errors.Is(err, test.want) {
				t.Fatalf("Execute() error = %v, want %v", err, test.want)
			}
			if test.want != nil && fake.restartCalls != 0 {
				t.Fatalf("Restart() was called for rejected target")
			}
			if test.want == nil && fake.restartCalls != 1 {
				t.Fatalf("Restart() calls = %d, want 1", fake.restartCalls)
			}
		})
	}
}

func TestAdapterRejectsUnsafeActionsBeforeRestart(t *testing.T) {
	fake := &fakeClient{containers: map[string]Container{"web": {ID: "container-web", Running: true}}}
	adapter := newAdapter(t, fake)
	target := containerTarget()
	for _, action := range []contract.TypedAction{
		{ActionType: "docker.container.exec", TargetSelector: target.Selector},
		{ActionType: contract.ActionDockerComposeServiceRestart, TargetSelector: target.Selector},
		{ActionType: contract.ActionDockerContainerRestart, TargetSelector: "container:other"},
	} {
		if err := adapter.Execute(context.Background(), target, action); !errors.Is(err, ErrUnsafeAction) {
			t.Fatalf("Execute(%q) error = %v, want ErrUnsafeAction", action.ActionType, err)
		}
	}
	if fake.restartCalls != 0 {
		t.Fatalf("Restart() calls = %d, want 0", fake.restartCalls)
	}
}

func TestAdapterMapsDaemonAndTimeoutErrors(t *testing.T) {
	t.Run("daemon unavailable", func(t *testing.T) {
		fake := &fakeClient{inspectErr: errors.New("connection refused")}
		_, err := newAdapter(t, fake).Discover(context.Background(), containerTarget())
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Discover() error = %v, want ErrUnavailable", err)
		}
	})
	t.Run("context deadline", func(t *testing.T) {
		fake := &fakeClient{inspectErr: context.DeadlineExceeded}
		_, err := newAdapter(t, fake).Discover(context.Background(), containerTarget())
		if !errors.Is(err, ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Discover() error = %v, want timeout mapping", err)
		}
	})
	t.Run("caller cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := newAdapter(t, &fakeClient{}).Discover(ctx, containerTarget())
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Discover() error = %v, want cancellation", err)
		}
	})
}

type fakeClient struct {
	containers   map[string]Container
	listed       []Container
	logs         string
	inspectErr   error
	negotiations int
	restartCalls int
	sawDeadline  bool
}

func (c *fakeClient) NegotiateAPIVersion(ctx context.Context) error {
	c.negotiations++
	_, c.sawDeadline = ctx.Deadline()
	return ctx.Err()
}

func (c *fakeClient) Inspect(ctx context.Context, identifier string) (Container, error) {
	_, c.sawDeadline = ctx.Deadline()
	if c.inspectErr != nil {
		return Container{}, c.inspectErr
	}
	container, found := c.containers[identifier]
	if !found {
		return Container{}, errors.New("not found")
	}
	return container, nil
}

func (c *fakeClient) ListByLabel(ctx context.Context, _, _ string) ([]Container, error) {
	_, c.sawDeadline = ctx.Deadline()
	return c.listed, nil
}

func (c *fakeClient) Logs(ctx context.Context, _ string) (io.ReadCloser, error) {
	_, c.sawDeadline = ctx.Deadline()
	return io.NopCloser(strings.NewReader(c.logs)), nil
}

func (c *fakeClient) Restart(ctx context.Context, _ string, _ time.Duration) error {
	_, c.sawDeadline = ctx.Deadline()
	c.restartCalls++
	return nil
}

type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

func newAdapter(t *testing.T, client Client) *Adapter {
	t.Helper()
	collector, err := evidence.NewCollector(evidence.Options{AllowedFields: []string{"message"}, MaxLines: 8, MaxBytes: 32, Retention: time.Hour, Clock: func() time.Time { return time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC) }, NewEvidenceID: func() (string, error) { return "evidence-1", nil }})
	if err != nil {
		t.Fatalf("NewCollector() error = %v", err)
	}
	adapter, err := NewAdapter(Options{Client: client, Evidence: collector, Clock: fakeClock{now: time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)}, MaxLogBytes: 32, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}
	return adapter
}

func containerTarget() contract.ServiceTarget {
	return contract.ServiceTarget{SchemaVersion: contract.SchemaVersionV1, TargetID: "web", AdapterType: AdapterType, Selector: "container:web", Enabled: true, EvidencePolicy: contract.EvidencePolicy{RedactionProfile: "default", MaxBytes: 32}}
}

func composeTarget() contract.ServiceTarget {
	return contract.ServiceTarget{SchemaVersion: contract.SchemaVersionV1, TargetID: "web", AdapterType: AdapterType, Selector: "compose_service:web", Enabled: true, EvidencePolicy: contract.EvidencePolicy{RedactionProfile: "default", MaxBytes: 32}}
}

func availabilityRule() contract.ProbeRule { return contract.ProbeRule{SignalType: "availability"} }
