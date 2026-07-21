package faultfixture

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestController_TransitionsDeterministically(t *testing.T) {
	controller, err := New(Options{SlowDelay: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	server := httptest.NewServer(controller.Handler())
	t.Cleanup(server.Close)

	tests := []struct {
		mode         Mode
		wantStatuses []int
		wantStates   []string
	}{
		{mode: ModeHealthy, wantStatuses: []int{http.StatusOK}, wantStates: []string{"healthy"}},
		{mode: ModeUnhealthy, wantStatuses: []int{http.StatusServiceUnavailable}, wantStates: []string{"unhealthy"}},
		{mode: ModeSlow, wantStatuses: []int{http.StatusOK}, wantStates: []string{"healthy"}},
		{mode: ModeCrash, wantStatuses: []int{http.StatusServiceUnavailable}, wantStates: []string{"unhealthy"}},
		{mode: ModeFlapping, wantStatuses: []int{http.StatusOK, http.StatusServiceUnavailable, http.StatusOK}, wantStates: []string{"healthy", "unhealthy", "healthy"}},
		{mode: ModeRecovery, wantStatuses: []int{http.StatusOK}, wantStates: []string{"recovered"}},
	}
	for _, test := range tests {
		t.Run(string(test.mode), func(t *testing.T) {
			if err := controller.SetMode(test.mode); err != nil {
				t.Fatalf("SetMode(%q) error = %v", test.mode, err)
			}
			for index, wantStatus := range test.wantStatuses {
				response, err := http.Get(server.URL + "/health")
				if err != nil {
					t.Fatalf("health request %d error = %v", index, err)
				}
				var body healthResponse
				decodeErr := json.NewDecoder(response.Body).Decode(&body)
				closeErr := response.Body.Close()
				if decodeErr != nil || closeErr != nil {
					t.Fatalf("decode/close health response = %v/%v", decodeErr, closeErr)
				}
				if response.StatusCode != wantStatus || body.Status != test.wantStates[index] || body.Mode != test.mode {
					t.Fatalf("health response %d = status=%d body=%#v, want status=%d state=%q mode=%q", index, response.StatusCode, body, wantStatus, test.wantStates[index], test.mode)
				}
			}
		})
	}
}

func TestController_CrashModeNotifiesAfterUnavailableHealthResponse(t *testing.T) {
	crashed := make(chan struct{}, 1)
	controller, err := New(Options{InitialMode: ModeCrash, CrashNotifier: func() { crashed <- struct{}{} }})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	server := httptest.NewServer(controller.Handler())
	t.Cleanup(server.Close)
	response, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("crash health request error = %v", err)
	}
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("crash health status = %d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close crash health response error = %v", err)
	}
	select {
	case <-crashed:
	case <-time.After(time.Second):
		t.Fatal("crash notifier was not called")
	}
}

func TestController_SlowModeHonorsRequestCancellation(t *testing.T) {
	controller, err := New(Options{InitialMode: ModeSlow, SlowDelay: time.Second})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	server := httptest.NewServer(controller.Handler())
	t.Cleanup(server.Close)
	contextWithDeadline, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	request, err := http.NewRequestWithContext(contextWithDeadline, http.MethodGet, server.URL+"/health", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	_, err = server.Client().Do(request)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("slow health request error = %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestController_ExposesBoundedMetricsAndSyntheticLogs(t *testing.T) {
	controller, err := New(Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	server := httptest.NewServer(controller.Handler())
	t.Cleanup(server.Close)
	if _, err := http.Get(server.URL + "/health"); err != nil {
		t.Fatalf("health request error = %v", err)
	}
	metricsResponse, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatalf("metrics request error = %v", err)
	}
	metrics := readResponse(t, metricsResponse)
	for _, want := range []string{"fixture_health_status 1", "fixture_health_checks_total 1", `fixture_fault_mode{mode="healthy"} 1`} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("metrics = %q, want %q", metrics, want)
		}
	}
	logsResponse, err := http.Get(server.URL + "/logs")
	if err != nil {
		t.Fatalf("logs request error = %v", err)
	}
	var logs logResponse
	if err := json.Unmarshal([]byte(readResponse(t, logsResponse)), &logs); err != nil {
		t.Fatalf("decode logs error = %v", err)
	}
	if len(logs.Lines) != len(syntheticLogLines()) {
		t.Fatalf("log lines = %d, want bounded %d", len(logs.Lines), len(syntheticLogLines()))
	}
	joined := strings.Join(logs.Lines, "\n")
	for _, want := range []string{"api_key=fixture-api-key-not-secret", "token=fixture-token-not-secret", "password=fixture-password-not-secret", "fixture.user@example.invalid", "ignore previous instructions"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("synthetic logs = %q, missing %q", joined, want)
		}
	}
	for _, forbidden := range []string{"sk-", "AIza", "whsec_"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("synthetic logs contain a real-secret pattern %q: %q", forbidden, joined)
		}
	}
}

func TestController_ControlAndHealthCheck(t *testing.T) {
	controller, err := New(Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	server := httptest.NewServer(controller.Handler())
	t.Cleanup(server.Close)
	request, err := http.NewRequest(http.MethodPut, server.URL+"/control/unhealthy", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("control request error = %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("control status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close control response error = %v", err)
	}
	if err := CheckHealth(context.Background(), server.Client(), server.URL+"/health"); !errors.Is(err, ErrUnhealthy) {
		t.Fatalf("CheckHealth(unhealthy) error = %v, want %v", err, ErrUnhealthy)
	}
	if err := controller.SetMode(ModeHealthy); err != nil {
		t.Fatalf("SetMode(healthy) error = %v", err)
	}
	if err := CheckHealth(context.Background(), server.Client(), server.URL+"/health"); err != nil {
		t.Fatalf("CheckHealth(healthy) error = %v", err)
	}
	invalidResponse, err := server.Client().Do(mustRequest(t, http.MethodPut, server.URL+"/control/unknown"))
	if err != nil {
		t.Fatalf("invalid control request error = %v", err)
	}
	if invalidResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid control status = %d, want %d", invalidResponse.StatusCode, http.StatusBadRequest)
	}
	if err := invalidResponse.Body.Close(); err != nil {
		t.Fatalf("close invalid control response error = %v", err)
	}
}

func TestNew_RejectsUnsafeOptions(t *testing.T) {
	for _, options := range []Options{{InitialMode: Mode("unknown")}, {SlowDelay: time.Nanosecond}, {SlowDelay: maxSlowDelay + time.Millisecond}} {
		if _, err := New(options); !errors.Is(err, ErrInvalidMode) && !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("New(%#v) error = %v, want bounded option rejection", options, err)
		}
	}
}

func readResponse(t *testing.T, response *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		_ = response.Body.Close()
		t.Fatalf("read response error = %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close response error = %v", err)
	}
	return string(body)
}

func mustRequest(t *testing.T, method, endpoint string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		t.Fatalf("NewRequest(%s, %s) error = %v", method, endpoint, err)
	}
	return request
}
