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
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
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
