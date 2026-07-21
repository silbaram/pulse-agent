package main

import (
	"net/http/httptest"
	"testing"

	"pulse-agent/internal/faultfixture"
)

func TestRun_HealthCheckUsesFixtureEndpoint(t *testing.T) {
	controller, err := faultfixture.New(faultfixture.Options{})
	if err != nil {
		t.Fatalf("faultfixture.New() error = %v", err)
	}
	server := httptest.NewServer(controller.Handler())
	t.Cleanup(server.Close)
	if exitCode := run([]string{"-healthcheck", "-healthcheck-url", server.URL + "/health"}); exitCode != 0 {
		t.Fatalf("run(healthy healthcheck) exit code = %d, want 0", exitCode)
	}
	if err := controller.SetMode(faultfixture.ModeUnhealthy); err != nil {
		t.Fatalf("SetMode(unhealthy) error = %v", err)
	}
	if exitCode := run([]string{"-healthcheck", "-healthcheck-url", server.URL + "/health"}); exitCode != 1 {
		t.Fatalf("run(unhealthy healthcheck) exit code = %d, want 1", exitCode)
	}
}
