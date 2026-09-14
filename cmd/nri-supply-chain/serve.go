// Copyright The nri-supply-chain Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const (
	readTimeout         = 30 * time.Second
	readHeaderTimeout   = 10 * time.Second
	writeTimeout        = 30 * time.Second
	idleTimeout         = 120 * time.Second
	shutdownGracePeriod = 5 * time.Second
	verifierStopTimeout = 30 * time.Second

	// listenRetryInitialBackoff is the first delay before an HTTP server
	// (metrics or health) retries binding its address.
	listenRetryInitialBackoff = time.Second
	// listenRetryMaxBackoff caps the delay between bind attempts.
	listenRetryMaxBackoff = time.Minute
	// listenRetryBackoffFactor multiplies the delay after each failed bind
	// attempt. It is tuned independently from the NRI reconnect backoff.
	listenRetryBackoffFactor = 2
)

// listenRetryPolicy controls how often an HTTP server retries binding its
// address.
type listenRetryPolicy struct {
	initial time.Duration
	maximum time.Duration
	factor  int
}

func defaultListenRetryPolicy() listenRetryPolicy {
	return listenRetryPolicy{
		initial: listenRetryInitialBackoff,
		maximum: listenRetryMaxBackoff,
		factor:  listenRetryBackoffFactor,
	}
}

// next returns the delay that follows backoff, capped at the maximum. A
// factor below one keeps the delay constant.
func (p listenRetryPolicy) next(backoff time.Duration) time.Duration {
	return min(backoff*time.Duration(max(p.factor, 1)), p.maximum)
}

// serveMetrics serves the metrics and health endpoints until ctx is
// cancelled. It never returns an error: the endpoints are auxiliary, and a
// port conflict (likely with host networking) must not stop the NRI
// connection and with it admission verification. Binding is retried with
// backoff instead. liveness is consulted by /healthz.
func serveMetrics(
	ctx context.Context, met *metrics.Metrics, addr string,
	plug *plugin.Plugin, liveness func() error, retry listenRetryPolicy,
) error {
	if addr == "" {
		slog.Info("Metrics server disabled (no address configured)")
		<-ctx.Done()

		return nil
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", met.Handler())
	registerHealthProbes(mux, plug, liveness)

	serveHTTP(ctx, "metrics and health", addr, mux, retry)

	return nil
}

// serveHealth serves only the health endpoints (/healthz, /readyz, /status)
// on a dedicated address until ctx is cancelled, so the kubelet probes do not
// depend on the metrics port, which is more likely to collide with other host
// services under host networking. An empty address disables it. Like
// serveMetrics, it never returns an error.
func serveHealth(
	ctx context.Context, addr string,
	plug *plugin.Plugin, liveness func() error, retry listenRetryPolicy,
) error {
	if addr == "" {
		<-ctx.Done()

		return nil
	}

	mux := http.NewServeMux()
	registerHealthProbes(mux, plug, liveness)

	serveHTTP(ctx, "health", addr, mux, retry)

	return nil
}

// serveHTTP binds addr with retries and serves handler until ctx is
// cancelled.
func serveHTTP(
	ctx context.Context, name, addr string, handler http.Handler, retry listenRetryPolicy,
) {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       readTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	listener, ok := listenWithRetry(ctx, name, addr, retry)
	if !ok {
		return
	}

	//nolint:gosec,contextcheck // parent ctx is already cancelled; fresh context is intentional
	go shutdownOnCancel(ctx.Done(), srv)

	slog.Info("Starting "+name+" server", "addr", addr)

	err := srv.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("HTTP server stopped", "server", name, "addr", addr, "error", err)
	}
}

// listenWithRetry binds addr, retrying with backoff until it succeeds or ctx
// is cancelled. ok is false when ctx ended first.
func listenWithRetry(
	ctx context.Context, name, addr string, retry listenRetryPolicy,
) (listener net.Listener, ok bool) {
	backoff := retry.initial
	listenCfg := net.ListenConfig{} //nolint:exhaustruct_v5 // zero-value config is valid

	for {
		bound, err := listenCfg.Listen(ctx, "tcp", addr)
		if err == nil {
			return bound, true
		}

		if isDone(ctx) {
			return nil, false
		}

		slog.Error("HTTP server cannot listen, retrying; admission verification is unaffected",
			"server", name, "addr", addr, "error", err, "retry_in", backoff,
		)

		if !sleepContext(ctx, backoff) {
			return nil, false
		}

		backoff = retry.next(backoff)
	}
}

func shutdownOnCancel(done <-chan struct{}, srv *http.Server) {
	<-done

	shutdownCtx, shutdownCancel := context.WithTimeout(
		context.Background(), shutdownGracePeriod,
	)
	defer shutdownCancel()

	shutdownErr := srv.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		slog.Error("Failed to shutdown metrics server", "error", shutdownErr)
	}
}

func logEffectiveConfig(configPath string, cfg *config.Config) {
	attrs := []any{
		"config", configPath,
		"mode", cfg.Verification,
		"policy_dir", cfg.PolicyDir,
		"cache_ttl", cfg.CacheTTL.Duration,
		"cache_failure_ttl", cfg.CacheFailureTTL.Duration,
		"fetch_timeout", cfg.FetchTimeout.Duration,
		"digest_resolve_timeout", cfg.DigestResolveTimeout.Duration,
		"fetch_rate_limit", cfg.FetchRateLimit,
		"fetch_failure_policy", cfg.FetchFailurePolicy,
		"circuit_breaker_threshold", cfg.CircuitBreakerThreshold,
		"circuit_breaker_cooldown", cfg.CircuitBreakerCooldown.Duration,
		"metrics_addr", cfg.MetricsAddr,
	}

	if cfg.Policy.Source == config.PolicySourceOCI {
		attrs = append(attrs,
			"policy_source", cfg.Policy.Source,
			"policy_oci_ref", cfg.Policy.OCIRef,
			"policy_poll_interval", cfg.Policy.PollInterval.Duration,
		)
	}

	slog.Info("Effective configuration", attrs...)
}

func startPlugin(
	configPath string, settings nriSettings, cfg *config.Config,
) int {
	met := metrics.New()
	met.SetBuildInfo(version, runtime.Version())

	ctx, cancel := context.WithCancel(context.Background())

	logEffectiveConfig(configPath, cfg)

	cfg.WarnInsecureRegistries()

	transportCache := registry.NewTransportCacheOrNil(cfg.Registries)

	verif, err := createVerifier(ctx, cfg, met, transportCache)
	if err != nil {
		slog.Error("Startup failed", "error", err)

		if transportCache != nil {
			transportCache.CloseIdleConnections()
		}

		cancel()

		return exitError
	}

	plug := plugin.New(
		verif, met, configPath,
		cfg.FetchTimeout.Duration, cfg.DigestResolveTimeout.Duration,
		transportCache,
	)

	if cfg.Remediation.Enabled() {
		plug.SetRemediationMode(cfg.Remediation.Mode)
		plug.SetRemediationConfig(&cfg.Remediation)
		warnEvictDeferred(cfg.Remediation.Mode)
	}

	plug.SetConfigApplier(runtimeConfigApplier(ctx, cfg, verif, met, plug))

	cleanupSignals := setupSignals(ctx, cancel, configPath, verif, met, cfg, plug)

	err = runPlugin(ctx, plug, met, cfg, settings)

	shutdown(cancel, cleanupSignals, verif, verifierStopTimeout)

	if err != nil {
		slog.Error("Plugin exited with error", "error", err)

		return exitError
	}

	slog.Info("Plugin stopped")

	return exitSuccess
}

// runtimeConfigPlugin is the plugin API used to apply a configuration passed
// by the runtime.
type runtimeConfigPlugin interface {
	pluginReloader
	StartContinuousVerifier(ctx context.Context, interval time.Duration)
}

// runtimeConfigApplier returns how the plugin applies a configuration passed
// by the runtime in Configure (a plugin started without a config file). It
// performs the same steps as a config file reload and additionally starts the
// continuous verifier when remediation is enabled, since without a config
// file there is no startup configuration that could have started it.
// metrics_addr only takes effect at startup. ctx is the plugin's lifetime
// context: the apply runs outside the runtime's request deadline.
func runtimeConfigApplier(
	ctx context.Context, startup *config.Config,
	verif *verifier.Verifier, met *metrics.Metrics, plug runtimeConfigPlugin,
) plugin.ConfigApplier {
	return func(_ context.Context, cfg *config.Config) error {
		applyLogLevel(cfg.LogLevel)
		cfg.WarnInsecureRegistries()

		if cfg.MetricsAddr != startup.MetricsAddr {
			slog.Warn("metrics_addr passed by the runtime only takes effect at startup",
				"current", startup.MetricsAddr,
				"proposed", cfg.MetricsAddr,
			)
		}

		err := verif.Reload(ctx, cfg)
		if err != nil {
			met.ConfigReloadErrorsTotal.Inc()

			return fmt.Errorf("reloading verifier: %w", err)
		}

		met.ConfigReloadsTotal.Inc()

		applyPluginSettings(ctx, cfg, verif, plug)

		if cfg.Remediation.Enabled() {
			plug.StartContinuousVerifier(ctx, cfg.Remediation.Interval.Duration)
		}

		return nil
	}
}

// stopper is implemented by components with a blocking Stop method.
type stopper interface {
	Stop()
}

// shutdown stops the plugin in dependency order: cancel the root context so
// the NRI connection, metrics server, file watchers and background loops
// exit, release signal handlers, then stop the verifier. Stopping the
// verifier waits for in-flight verifications, so it is bounded by timeout
// to keep a hung registry from blocking process exit.
func shutdown(
	cancel context.CancelFunc, cleanupSignals func(),
	verif stopper, timeout time.Duration,
) {
	cancel()
	cleanupSignals()

	stopped := make(chan struct{})

	go func() {
		defer close(stopped)

		verif.Stop()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-stopped:
	case <-timer.C:
		slog.Warn("Timed out waiting for in-flight verifications to stop",
			"timeout", timeout,
		)
	}
}

func createVerifier(
	ctx context.Context,
	cfg *config.Config,
	met *metrics.Metrics,
	transportCache *registry.TransportCache,
) (*verifier.Verifier, error) {
	var fetcher attestation.Fetcher

	if cfg.Enabled() {
		var err error

		fetcher, err = verifier.NewFetcher(ctx, cfg, transportCache)
		if err != nil {
			return nil, fmt.Errorf("creating fetcher: %w", err)
		}
	}

	verif, err := verifier.New(ctx, cfg, met, fetcher)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	return verif, nil
}

func runPlugin(
	ctx context.Context, plug *plugin.Plugin, met *metrics.Metrics,
	cfg *config.Config, settings nriSettings,
) error {
	group, gctx := errgroup.WithContext(ctx)
	conn := newNRIConnection(time.Now())

	policy := defaultReconnectPolicy(settings.socketPath)

	group.Go(func() error {
		return runNRI(gctx, plug, settings, newNRIStub, os.Getenv, policy, conn)
	})

	liveness := func() error {
		return conn.liveness(settings.disconnectTimeout, time.Now(), policy.socketExists)
	}

	group.Go(func() error {
		return serveMetrics(gctx, met, cfg.MetricsAddr, plug, liveness, defaultListenRetryPolicy())
	})

	group.Go(func() error {
		return serveHealth(gctx, settings.healthAddr, plug, liveness, defaultListenRetryPolicy())
	})

	if cfg.Remediation.Enabled() {
		group.Go(func() error {
			plug.RunContinuousVerifier(gctx, cfg.Remediation.Interval.Duration)

			return nil
		})
	}

	err := group.Wait()
	if err != nil {
		return fmt.Errorf("plugin services: %w", err)
	}

	return nil
}

// registerHealthProbes adds /healthz, /readyz, and /status. /healthz fails
// when liveness returns an error (for example after a prolonged NRI
// disconnect), so the kubelet restarts a wedged plugin; a nil liveness
// function always reports healthy.
func registerHealthProbes(mux *http.ServeMux, plug *plugin.Plugin, liveness func() error) {
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		if liveness != nil {
			err := liveness()
			if err != nil {
				writer.WriteHeader(http.StatusServiceUnavailable)
				_, _ = writer.Write([]byte("unhealthy: " + err.Error()))

				return
			}
		}

		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok"))
	})

	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) {
		if !plug.Connected() {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte("not ready: NRI not connected"))

			return
		}

		if ready, reason := plug.VerifierReady(); !ready {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte("not ready: " + reason))

			return
		}

		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok"))
	})

	mux.HandleFunc("GET /status", func(writer http.ResponseWriter, _ *http.Request) {
		status := plug.Status()

		data, marshalErr := json.Marshal(status)
		if marshalErr != nil {
			http.Error(writer, "internal server error", http.StatusInternalServerError)
			slog.Error("Failed to encode status response", "error", marshalErr)

			return
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(data)
	})
}

func warnEvictDeferred(mode config.RemediationMode) {
	if mode == config.RemediationModeEvict {
		slog.Warn("remediation.mode=evict is configured but eviction is deferred: " +
			"the upstream NRI stub does not yet expose EvictContainers(); " +
			"the state machine will stop at Throttled until the API is available")
	}
}
