package observer

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/target"
)

func TestScheduler_RunCycleAppliesIntervalDebounceAndSnapshotVersion(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)}
	source := &fakeTargets{snapshot: testSnapshot(7, testRule())}
	probe := &fakeProbe{results: []map[string]float64{{"availability": 0.5}, {"availability": 0.5}, {"availability": 1}, {"availability": 1}}}
	scheduler := newTestScheduler(t, source, probe, clock)

	first, err := scheduler.RunCycle(context.Background())
	if err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if len(first) != 1 || first[0].NormalizedState != contract.StateUnknown || first[0].TargetSnapshotVersion != 7 {
		t.Fatalf("first observations = %#v", first)
	}
	second, err := scheduler.RunCycle(context.Background())
	if err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("interval observations = %#v, want none", second)
	}
	clock.Advance(time.Minute)
	second, err = scheduler.RunCycle(context.Background())
	if err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if len(second) != 1 || second[0].NormalizedState != contract.StateUnhealthy {
		t.Fatalf("failure observations = %#v", second)
	}
	clock.Advance(time.Minute)
	third, err := scheduler.RunCycle(context.Background())
	if err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if len(third) != 1 || third[0].NormalizedState != contract.StateUnknown {
		t.Fatalf("recovery observations = %#v", third)
	}
	clock.Advance(time.Minute)
	fourth, err := scheduler.RunCycle(context.Background())
	if err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if len(fourth) != 1 || fourth[0].NormalizedState != contract.StateHealthy || fourth[0].Sequence != 4 {
		t.Fatalf("healthy observations = %#v", fourth)
	}
}

func TestScheduler_RunCycleStopsOnCancellationAndProbeTimeout(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)}
	source := &fakeTargets{snapshot: testSnapshot(1, testRule())}
	scheduler := newTestScheduler(t, source, &fakeProbe{observe: func(ctx context.Context, _ contract.ServiceTarget, _ contract.ProbeRule) (map[string]float64, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}, clock)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scheduler.RunCycle(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunCycle(cancelled) error = %v", err)
	}
	if _, err := scheduler.RunCycle(context.Background()); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("RunCycle(timeout) error = %v, want %v", err, ErrProbeFailed)
	}
	inFlightContext, cancelInFlight := context.WithCancel(context.Background())
	inFlight := newTestScheduler(t, source, &fakeProbe{observe: func(ctx context.Context, _ contract.ServiceTarget, _ contract.ProbeRule) (map[string]float64, error) {
		cancelInFlight()
		<-ctx.Done()
		return nil, ctx.Err()
	}}, clock)
	if _, err := inFlight.RunCycle(inFlightContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunCycle(in-flight cancellation) error = %v, want %v", err, context.Canceled)
	}
}

func TestScheduler_StartDuePreventsOverlap(t *testing.T) {
	clock := &fakeClock{now: time.Now()}
	scheduler := newTestScheduler(t, &fakeTargets{}, &fakeProbe{}, clock)
	rule := testRule()
	if !scheduler.startDue("checkout", rule, clock.Now()) {
		t.Fatal("first startDue() = false")
	}
	if scheduler.startDue("checkout", rule, clock.Now()) {
		t.Fatal("overlapping startDue() = true")
	}
	scheduler.finish("checkout", rule.RuleID, clock.Now())
}

func TestScheduler_RunCycleKeepsOneSnapshotDuringTargetChange(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)}
	rule := testRule()
	source := &fakeTargets{snapshot: target.Snapshot{SchemaVersion: contract.SchemaVersionV1, Version: 7, Targets: []contract.ServiceTarget{
		{SchemaVersion: contract.SchemaVersionV1, TargetID: "checkout", Enabled: true, ProbeRules: []contract.ProbeRule{rule}},
		{SchemaVersion: contract.SchemaVersionV1, TargetID: "catalog", Enabled: true, ProbeRules: []contract.ProbeRule{rule}},
	}}}
	probe := &fakeProbe{observe: func(_ context.Context, _ contract.ServiceTarget, _ contract.ProbeRule) (map[string]float64, error) {
		source.snapshot.Version = 8
		return map[string]float64{"availability": 1}, nil
	}}
	scheduler := newTestScheduler(t, source, probe, clock)
	observations, err := scheduler.RunCycle(context.Background())
	if err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if len(observations) != 2 || observations[0].TargetSnapshotVersion != 7 || observations[1].TargetSnapshotVersion != 7 {
		t.Fatalf("observations = %#v, want both from snapshot version 7", observations)
	}
}

func TestBoundedValues_ClampsAndLimits(t *testing.T) {
	values := map[string]float64{"availability": 2_000_000, "bad": 0}
	for index := 0; index < 20; index++ {
		values[string(rune('a'+index))] = float64(index)
	}
	bounded := boundedValues(values)
	if len(bounded) != maxValues {
		t.Fatalf("bounded value count = %d, want %d", len(bounded), maxValues)
	}
	if got := bounded["availability"]; got != maxValue {
		t.Errorf("availability = %v, want %v", got, maxValue)
	}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

type fakeTargets struct{ snapshot target.Snapshot }

func (s *fakeTargets) Snapshot() target.Snapshot { return s.snapshot }

type fakeProbe struct {
	results []map[string]float64
	observe func(context.Context, contract.ServiceTarget, contract.ProbeRule) (map[string]float64, error)
	next    int
}

func (p *fakeProbe) Observe(ctx context.Context, target contract.ServiceTarget, rule contract.ProbeRule) (map[string]float64, error) {
	if p.observe != nil {
		return p.observe(ctx, target, rule)
	}
	if p.next >= len(p.results) {
		return nil, errors.New("no result")
	}
	result := p.results[p.next]
	p.next++
	return result, nil
}

func newTestScheduler(t *testing.T, source TargetSource, probe Probe, clock Clock) *Scheduler {
	t.Helper()
	next := 0
	scheduler, err := NewScheduler(Options{Targets: source, Probe: probe, Clock: clock, NewObservationID: func() (string, error) { next++; return "observation-" + string(rune('0'+next)), nil }})
	if err != nil {
		t.Fatalf("NewScheduler() error = %v", err)
	}
	return scheduler
}

func testRule() contract.ProbeRule {
	return contract.ProbeRule{RuleID: "availability", SignalType: "availability", Interval: contract.NewDuration(time.Minute), Timeout: contract.NewDuration(time.Millisecond), Threshold: 0.9, ConsecutiveFailures: 2, RecoverySamples: 2, SLOWindow: contract.NewDuration(time.Hour)}
}

func testSnapshot(version uint64, rule contract.ProbeRule) target.Snapshot {
	return target.Snapshot{SchemaVersion: contract.SchemaVersionV1, Version: version, Targets: []contract.ServiceTarget{{SchemaVersion: contract.SchemaVersionV1, TargetID: "checkout", Enabled: true, ProbeRules: []contract.ProbeRule{rule}}}}
}
