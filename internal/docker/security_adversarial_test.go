package docker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"pulse-agent/internal/contract"
)

const (
	dockerActionAuthorizationCorpusSize  = 24
	dockerReplicaAuthorizationCorpusSize = 3
	dockerAuthorizationCorpusSize        = dockerActionAuthorizationCorpusSize + dockerReplicaAuthorizationCorpusSize
)

func TestAdapter_AuthorizationCorpusFailsClosedBeforeRestart(t *testing.T) {
	baseTarget := containerTarget()
	baseAction := contract.TypedAction{
		ActionType:     contract.ActionDockerContainerRestart,
		TargetSelector: baseTarget.Selector,
		StopTimeout:    contract.NewDuration(time.Second),
	}
	tests := []struct {
		name   string
		mutate func(*contract.ServiceTarget, *contract.TypedAction)
		want   error
	}{
		{name: "raw selector kind", mutate: func(target *contract.ServiceTarget, action *contract.TypedAction) {
			target.Selector = "raw:web"
			action.TargetSelector = target.Selector
		}, want: ErrUnsafeAction},
		{name: "selector without kind", mutate: func(target *contract.ServiceTarget, action *contract.TypedAction) {
			target.Selector = "web"
			action.TargetSelector = target.Selector
		}, want: ErrUnsafeAction},
		{name: "empty selector value", mutate: func(target *contract.ServiceTarget, action *contract.TypedAction) {
			target.Selector = "container:"
			action.TargetSelector = target.Selector
		}, want: ErrUnsafeAction},
		{name: "selector with extra delimiter", mutate: func(target *contract.ServiceTarget, action *contract.TypedAction) {
			target.Selector = "container:web:latest"
			action.TargetSelector = target.Selector
		}, want: ErrUnsafeAction},
		{name: "selector parent traversal", mutate: func(target *contract.ServiceTarget, action *contract.TypedAction) {
			target.Selector = "container:../web"
			action.TargetSelector = target.Selector
		}, want: ErrUnsafeAction},
		{name: "selector embedded traversal", mutate: func(target *contract.ServiceTarget, action *contract.TypedAction) {
			target.Selector = "container:web..shadow"
			action.TargetSelector = target.Selector
		}, want: ErrUnsafeAction},
		{name: "selector path separator", mutate: func(target *contract.ServiceTarget, action *contract.TypedAction) {
			target.Selector = "container:web/prod"
			action.TargetSelector = target.Selector
		}, want: ErrUnsafeAction},
		{name: "selector shell separator", mutate: func(target *contract.ServiceTarget, action *contract.TypedAction) {
			target.Selector = "container:web;rm"
			action.TargetSelector = target.Selector
		}, want: ErrUnsafeAction},
		{name: "selector whitespace", mutate: func(target *contract.ServiceTarget, action *contract.TypedAction) {
			target.Selector = "container:web prod"
			action.TargetSelector = target.Selector
		}, want: ErrUnsafeAction},
		{name: "selector oversized", mutate: func(target *contract.ServiceTarget, action *contract.TypedAction) {
			target.Selector = "container:" + strings.Repeat("a", 97)
			action.TargetSelector = target.Selector
		}, want: ErrUnsafeAction},
		{name: "unsupported target schema", mutate: func(target *contract.ServiceTarget, _ *contract.TypedAction) { target.SchemaVersion = "v2" }, want: ErrUnsafeAction},
		{name: "unsupported target adapter", mutate: func(target *contract.ServiceTarget, _ *contract.TypedAction) { target.AdapterType = "shell" }, want: ErrUnsafeAction},
		{name: "disabled target", mutate: func(target *contract.ServiceTarget, _ *contract.TypedAction) { target.Enabled = false }, want: ErrUnsafeAction},
		{name: "exec action", mutate: func(_ *contract.ServiceTarget, action *contract.TypedAction) {
			action.ActionType = "docker.container.exec"
		}, want: ErrUnsafeAction},
		{name: "raw command action", mutate: func(_ *contract.ServiceTarget, action *contract.TypedAction) {
			action.ActionType = "docker.raw_command"
		}, want: ErrUnsafeAction},
		{name: "shell action", mutate: func(_ *contract.ServiceTarget, action *contract.TypedAction) { action.ActionType = "shell" }, want: ErrUnsafeAction},
		{name: "remove action", mutate: func(_ *contract.ServiceTarget, action *contract.TypedAction) {
			action.ActionType = "docker.container.remove"
		}, want: ErrUnsafeAction},
		{name: "compose down action", mutate: func(_ *contract.ServiceTarget, action *contract.TypedAction) {
			action.ActionType = "docker.compose.down"
		}, want: ErrUnsafeAction},
		{name: "scale action", mutate: func(_ *contract.ServiceTarget, action *contract.TypedAction) {
			action.ActionType = "docker.compose.scale"
		}, want: ErrUnsafeAction},
		{name: "wrong typed restart", mutate: func(_ *contract.ServiceTarget, action *contract.TypedAction) {
			action.ActionType = contract.ActionDockerComposeServiceRestart
		}, want: ErrUnsafeAction},
		{name: "forged action selector", mutate: func(_ *contract.ServiceTarget, action *contract.TypedAction) {
			action.TargetSelector = "container:other"
		}, want: ErrUnsafeAction},
		{name: "action selector traversal", mutate: func(_ *contract.ServiceTarget, action *contract.TypedAction) {
			action.TargetSelector = "container:../web"
		}, want: ErrUnsafeAction},
		{name: "negative stop timeout", mutate: func(_ *contract.ServiceTarget, action *contract.TypedAction) {
			action.StopTimeout = contract.NewDuration(-time.Second)
		}, want: ErrUnsafeAction},
		{name: "negative cooldown", mutate: func(_ *contract.ServiceTarget, action *contract.TypedAction) {
			action.Cooldown = contract.NewDuration(-time.Second)
		}, want: ErrUnsafeAction},
	}
	if got := len(tests); got != dockerActionAuthorizationCorpusSize {
		t.Fatalf("Docker action authorization corpus size = %d, want %d", got, dockerActionAuthorizationCorpusSize)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := baseTarget
			action := baseAction
			test.mutate(&target, &action)
			client := &fakeClient{containers: map[string]Container{
				"web":      {ID: "container-web", Running: true},
				"../web":   {ID: "container-traversal", Running: true},
				"web/prod": {ID: "container-path", Running: true},
			}}
			err := newAdapter(t, client).Execute(context.Background(), target, action)
			if !errors.Is(err, test.want) {
				t.Fatalf("Execute() error = %v, want errors.Is(_, %v)", err, test.want)
			}
			if client.restartCalls != 0 {
				t.Fatalf("Restart() calls = %d, want 0", client.restartCalls)
			}
		})
	}
}

func TestAdapter_ReplicaSelectorCorpusFailsClosedBeforeRestart(t *testing.T) {
	tests := []struct {
		name       string
		containers []Container
		want       error
	}{
		{name: "zero replicas", containers: nil, want: ErrAmbiguousTarget},
		{name: "two replicas", containers: securityReplicas(2), want: ErrAmbiguousTarget},
		{name: "three replicas", containers: securityReplicas(3), want: ErrAmbiguousTarget},
	}
	if got := len(tests); got != dockerReplicaAuthorizationCorpusSize || dockerAuthorizationCorpusSize != 27 {
		t.Fatalf("Docker replica authorization corpus size = %d, total = %d; want %d and 27", got, dockerAuthorizationCorpusSize, dockerReplicaAuthorizationCorpusSize)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeClient{listed: test.containers}
			action := contract.TypedAction{
				ActionType:     contract.ActionDockerComposeServiceRestart,
				TargetSelector: composeTarget().Selector,
				StopTimeout:    contract.NewDuration(time.Second),
			}
			err := newAdapter(t, client).Execute(context.Background(), composeTarget(), action)
			if !errors.Is(err, test.want) {
				t.Fatalf("Execute() error = %v, want errors.Is(_, %v)", err, test.want)
			}
			if client.restartCalls != 0 {
				t.Fatalf("Restart() calls = %d, want 0", client.restartCalls)
			}
		})
	}
}

func securityReplicas(count int) []Container {
	containers := make([]Container, 0, count)
	for index := range count {
		containers = append(containers, Container{
			ID:      string(rune('a' + index)),
			Running: true,
			Labels:  map[string]string{composeServiceLabel: "web"},
		})
	}
	return containers
}
