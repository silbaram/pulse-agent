// Command fault-fixture runs a stateless deterministic HTTP workload for
// Pulse Agent Docker acceptance tests.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pulse-agent/internal/faultfixture"
)

const healthCheckTimeout = 2 * time.Second

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("fault-fixture", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	listenAddress := flags.String("listen", ":8080", "HTTP listen address")
	modeValue := flags.String("mode", string(faultfixture.ModeHealthy), "initial fault mode")
	slowDelay := flags.Duration("slow-delay", 100*time.Millisecond, "bounded slow response delay")
	healthCheck := flags.Bool("healthcheck", false, "request a local health endpoint and exit")
	healthCheckURL := flags.String("healthcheck-url", "http://127.0.0.1:8080/health", "health endpoint for -healthcheck")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *healthCheck {
		ctx, cancel := context.WithTimeout(context.Background(), healthCheckTimeout)
		defer cancel()
		if err := faultfixture.CheckHealth(ctx, &http.Client{}, *healthCheckURL); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	crashed := make(chan struct{}, 1)
	controller, err := faultfixture.New(faultfixture.Options{
		InitialMode: faultfixture.Mode(*modeValue),
		SlowDelay:   *slowDelay,
		CrashNotifier: func() {
			select {
			case crashed <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	server := &http.Server{Addr: *listenAddress, Handler: controller.Handler(), ReadHeaderTimeout: time.Second}
	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverError := make(chan error, 1)
	go func() { serverError <- server.ListenAndServe() }()
	select {
	case <-shutdownContext.Done():
		ctx, cancel := context.WithTimeout(context.Background(), healthCheckTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case <-crashed:
		return 1
	case err := <-serverError:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
}
