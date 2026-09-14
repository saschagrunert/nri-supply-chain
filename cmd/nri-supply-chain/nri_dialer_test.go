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
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// listenUnixSocket returns the path of a unix socket that accepts
// connections for the duration of the test.
func listenUnixSocket(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "nri.sock")

	listenCfg := net.ListenConfig{} //nolint:exhaustruct_v5 // zero-value config is valid

	listener, err := listenCfg.Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatalf("listening on unix socket: %v", err)
	}

	t.Cleanup(func() { _ = listener.Close() })

	return path
}

func TestTrackedDialerUsesParentContext(t *testing.T) {
	t.Parallel()

	path := listenUnixSocket(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	dialer := &trackedDialer{} //nolint:exhaustruct_v5 // zero-value dialer is valid

	conn, err := dialer.dialFunc(ctx, time.Minute)(path)
	if err == nil {
		_ = conn.Close()

		t.Fatal("expected dialing with a cancelled context to fail")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestTrackedDialerBoundsDial(t *testing.T) {
	t.Parallel()

	path := listenUnixSocket(t)
	dialer := &trackedDialer{} //nolint:exhaustruct_v5 // zero-value dialer is valid

	conn, err := dialer.dialFunc(t.Context(), time.Nanosecond)(path)
	if err == nil {
		_ = conn.Close()

		t.Fatal("expected dialing past the dial timeout to fail")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestTrackedDialerTracksConnection(t *testing.T) {
	t.Parallel()

	path := listenUnixSocket(t)
	dialer := &trackedDialer{} //nolint:exhaustruct_v5 // zero-value dialer is valid

	conn, err := dialer.dialFunc(t.Context(), nriDialTimeout)(path)
	if err != nil {
		t.Fatalf("dialing: %v", err)
	}

	dialer.close()

	_, writeErr := conn.Write([]byte("x"))
	if writeErr == nil {
		t.Error("expected close to release the tracked connection")
	}
}
