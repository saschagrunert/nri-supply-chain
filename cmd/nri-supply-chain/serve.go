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
	"net/http"
	"runtime"
	"time"

	"github.com/containerd/nri/pkg/stub"
	"golang.org/x/sync/errgroup"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const (
	readHeaderTimeout   = 10 * time.Second
	writeTimeout        = 30 * time.Second
	idleTimeout         = 120 * time.Second
	shutdownGracePeriod = 5 * time.Second
)

func serveMetrics(
	ctx context.Context, met *metrics.Metrics, addr string,
	plug *plugin.Plugin,
) error {
	if addr == "" {
		slog.Info("Metrics server disabled (no address configured)")
		<-ctx.Done()

		return nil
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", met.Handler())
	registerHealthProbes(mux, plug)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	//nolint:gosec,contextcheck // parent ctx is already cancelled; fresh context is intentional
	go shutdownOnCancel(ctx.Done(), srv)

	slog.Info("Starting metrics and health server", "addr", addr)

	err := srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("metrics server: %w", err)
	}

	return nil
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
	configPath, pluginName, pluginIdx string, cfg *config.Config,
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

	defer cancel()
	defer verif.Stop()

	plug := plugin.New(
		verif, met, configPath,
		cfg.FetchTimeout.Duration, cfg.DigestResolveTimeout.Duration,
		transportCache,
	)

	cleanupSignals := setupSignals(ctx, cancel, configPath, verif, met, cfg, plug)
	defer cleanupSignals()

	err = runPlugin(ctx, plug, met, cfg.MetricsAddr, pluginName, pluginIdx, cancel)
	if err != nil {
		slog.Error("Plugin exited with error", "error", err)

		return exitError
	}

	return exitSuccess
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
	metricsAddr, pluginName, pluginIdx string, cancel context.CancelFunc,
) error {
	nriStub, err := stub.New(plug,
		stub.WithPluginName(pluginName),
		stub.WithPluginIdx(pluginIdx),
		stub.WithOnClose(func() {
			slog.Error("NRI connection lost")
			plug.SetDisconnected()
			cancel()
		}),
	)
	if err != nil {
		return fmt.Errorf("creating NRI stub: %w", err)
	}

	group, gctx := errgroup.WithContext(ctx)

	group.Go(func() error {
		slog.Info("Starting NRI plugin",
			"name", pluginName, "index", pluginIdx,
		)

		return nriStub.Run(gctx)
	})

	group.Go(func() error {
		return serveMetrics(gctx, met, metricsAddr, plug)
	})

	err = group.Wait()
	if err != nil {
		return fmt.Errorf("plugin services: %w", err)
	}

	return nil
}

func registerHealthProbes(mux *http.ServeMux, plug *plugin.Plugin) {
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
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
