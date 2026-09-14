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
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"

	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
)

const (
	nriReconnectInitialBackoff = time.Second
	nriReconnectMaxBackoff     = 30 * time.Second
	// nriStableConnection is how long a connection must last before the
	// reconnect backoff is reset to its initial value.
	nriStableConnection = time.Minute
	// nriReconnectBackoffFactor multiplies the backoff after each failed
	// connection attempt.
	nriReconnectBackoffFactor = 2
	// nriConfigureTimeout bounds the time from connecting until the runtime
	// has configured the plugin. The runtime's registration timeout is 5s by
	// default; the margin covers slower runtimes and a Configure that applies
	// an inline configuration.
	nriConfigureTimeout = 30 * time.Second
	// defaultNRIDisconnectTimeout is how long the NRI connection may be down
	// before /healthz reports the plugin as unhealthy.
	defaultNRIDisconnectTimeout = 5 * time.Minute
	// nriMaxAbandonedConnections bounds how many connection attempts stuck
	// before Configure may be abandoned. The vendored NRI stub keeps a
	// goroutine blocked for each of them, so the plugin exits (and is
	// restarted) instead of leaking without bound.
	nriMaxAbandonedConnections = 10
	// nriSocketPollInterval is how often a reconnect backoff checks whether
	// a missing NRI socket has reappeared.
	nriSocketPollInterval = 250 * time.Millisecond
	// nriDialTimeout bounds connecting to the NRI socket. It matches the
	// runtime's default plugin registration timeout: a socket that does not
	// accept a connection within it would fail registration anyway.
	nriDialTimeout = stub.DefaultRegistrationTimeout
)

var (
	// errNRIConnectionLost is returned when the connection to a runtime that
	// launched the plugin itself (pre-installed plugin) is lost. Such plugins
	// cannot reconnect because the runtime owns the socket.
	errNRIConnectionLost = errors.New("NRI connection lost")

	// errNRIConfigureTimeout is returned when the runtime does not configure
	// the plugin in time after it connected and registered.
	errNRIConfigureTimeout = errors.New("timed out waiting for the runtime to configure the plugin")

	// errNRIConnectionClosed is returned when an established connection ends.
	errNRIConnectionClosed = errors.New("NRI connection closed")

	// errNRIDisconnectedTooLong is reported by /healthz when the NRI
	// connection has been down longer than the disconnect timeout.
	errNRIDisconnectedTooLong = errors.New("NRI disconnected too long")

	// errStaleNRIConnection is returned to a Configure request of a
	// connection attempt that was abandoned or replaced.
	errStaleNRIConnection = errors.New("NRI connection attempt is no longer current")

	// errTooManyAbandonedNRIConnections is returned when too many connection
	// attempts got stuck before Configure.
	errTooManyAbandonedNRIConnections = errors.New(
		"too many NRI connection attempts abandoned before Configure",
	)
)

// nriSettings holds the NRI connection settings from the command line.
type nriSettings struct {
	pluginName string
	pluginIdx  string
	socketPath string
	// disconnectTimeout is how long the connection may be down before
	// /healthz fails. Zero disables the check.
	disconnectTimeout time.Duration
	// healthAddr is the address of the dedicated health probe server; empty
	// serves the probes only on the metrics address.
	healthAddr string
}

// nriStub is the subset of the NRI stub used by the plugin runtime.
type nriStub interface {
	plugin.StubUpdater

	Start(ctx context.Context) error
	Stop()
	Wait()
}

// nriHandler is the NRI plugin implementation passed to the stub.
type nriHandler interface {
	Configure(ctx context.Context, cfg, runtimeName, runtimeVersion string) (stub.EventMask, error)
}

// nriStubFactory creates an NRI stub for a plugin handler. Tests replace it.
type nriStubFactory func(handler nriHandler, opts ...stub.Option) (nriStub, error)

// connectionHandler is the NRI plugin handler of one connection attempt. A
// Configure of an attempt that was abandoned (for example by the configure
// watchdog) or replaced by a newer attempt is rejected, so a late request of
// a stale stub cannot mark the plugin connected or apply a configuration.
type connectionHandler struct {
	*plugin.Plugin

	conn *nriConnection
	gen  uint64
}

func newConnectionHandler(
	plug *plugin.Plugin, conn *nriConnection, gen uint64,
) *connectionHandler {
	return &connectionHandler{Plugin: plug, conn: conn, gen: gen}
}

// Configure configures the plugin unless the connection attempt is stale.
func (h *connectionHandler) Configure(
	ctx context.Context, cfg, runtimeName, runtimeVersion string,
) (stub.EventMask, error) {
	if !h.conn.current(h.gen) {
		slog.WarnContext(ctx, "Ignoring Configure of a stale NRI connection attempt")

		return 0, errStaleNRIConnection
	}

	mask, err := h.Plugin.Configure(ctx, cfg, runtimeName, runtimeVersion)
	if err != nil {
		return mask, fmt.Errorf("configuring plugin: %w", err)
	}

	return mask, nil
}

// reconnectPolicy controls the backoff between NRI connection attempts.
type reconnectPolicy struct {
	initial time.Duration
	maximum time.Duration
	stable  time.Duration
	// configureTimeout bounds how long a connection attempt may wait for the
	// runtime to configure the plugin.
	configureTimeout time.Duration
	// maxAbandoned is how many attempts stuck before Configure may be
	// abandoned before runNRI gives up. Zero means no limit.
	maxAbandoned int
	// socketExists reports whether the NRI socket exists; nil assumes it
	// does. While it is missing, a reconnect backoff ends as soon as it
	// appears.
	socketExists func() bool
}

func defaultReconnectPolicy(socketPath string) reconnectPolicy {
	return reconnectPolicy{
		initial:          nriReconnectInitialBackoff,
		maximum:          nriReconnectMaxBackoff,
		stable:           nriStableConnection,
		configureTimeout: nriConfigureTimeout,
		maxAbandoned:     nriMaxAbandonedConnections,
		socketExists:     nriSocketExists(socketPath),
	}
}

// nriSocketExists returns a function reporting whether a unix socket exists
// at path (the default NRI socket when path is empty). It only inspects the
// file: connecting would make the runtime log a failed plugin registration.
func nriSocketExists(path string) func() bool {
	if path == "" {
		path = api.DefaultSocketPath
	}

	return func() bool {
		info, err := os.Stat(path)

		return err == nil && info.Mode()&os.ModeSocket != 0
	}
}

// nriConnection tracks the current NRI connection attempt and since when the
// plugin has been disconnected.
type nriConnection struct {
	generation atomic.Uint64
	// disconnectedSince holds the Unix time in nanoseconds at which the
	// plugin lost (or has not yet established) its connection; zero while
	// connected.
	disconnectedSince atomic.Int64
	// abandoned counts connection attempts abandoned before Configure.
	abandoned atomic.Int64
}

func newNRIConnection(now time.Time) *nriConnection {
	conn := &nriConnection{} //nolint:exhaustruct_v5 // atomics are zero-value ready
	conn.disconnectedSince.Store(now.UnixNano())

	return conn
}

// begin starts a new connection attempt and returns its generation.
func (c *nriConnection) begin() uint64 {
	return c.generation.Add(1)
}

// current reports whether gen is the latest connection attempt.
func (c *nriConnection) current(gen uint64) bool {
	return c.generation.Load() == gen
}

func (c *nriConnection) markConnected() {
	c.disconnectedSince.Store(0)
}

// markDisconnected records the loss of connection gen. A late report from a
// previous connection is ignored and false is returned.
func (c *nriConnection) markDisconnected(gen uint64, now time.Time) bool {
	if !c.current(gen) {
		return false
	}

	c.disconnectedSince.CompareAndSwap(0, now.UnixNano())

	return true
}

// retire invalidates connection attempt gen, so late requests of its stub
// are rejected even before the next attempt begins.
func (c *nriConnection) retire(gen uint64) {
	c.generation.CompareAndSwap(gen, gen+1)
}

// liveness returns an error when the plugin has been disconnected for longer
// than timeout while the NRI socket exists (socketExists; nil assumes it
// does). A runtime that is down has no socket: restarting the plugin cannot
// help then and would only add a crash-loop backoff for when the runtime
// returns. A zero timeout disables the check.
func (c *nriConnection) liveness(
	timeout time.Duration, now time.Time, socketExists func() bool,
) error {
	since := c.disconnectedSince.Load()
	if timeout <= 0 || since == 0 {
		return nil
	}

	down := now.Sub(time.Unix(0, since))
	if down <= timeout {
		return nil
	}

	if socketExists != nil && !socketExists() {
		slog.Debug("NRI disconnected but the runtime socket is missing, staying live",
			"down", down.Truncate(time.Second),
		)

		return nil
	}

	return fmt.Errorf("%w: %s", errNRIDisconnectedTooLong, down.Truncate(time.Second))
}

//nolint:ireturn // returns the stub behind the narrow interface used by runNRI
func newNRIStub(handler nriHandler, opts ...stub.Option) (nriStub, error) {
	nriStub, err := stub.New(handler, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating NRI stub: %w", err)
	}

	return nriStub, nil
}

// stubOptions builds the NRI stub options. The plugin name and index flags
// are only applied when the runtime did not provide them through the
// environment: a pre-installed plugin is launched with NRI_PLUGIN_NAME and
// NRI_PLUGIN_IDX set, and the stub rejects setting them twice.
func stubOptions(
	settings nriSettings, getenv func(string) string, onClose func(),
) []stub.Option {
	opts := []stub.Option{stub.WithOnClose(onClose)}

	if env := getenv(api.PluginNameEnvVar); env == "" {
		opts = append(opts, stub.WithPluginName(settings.pluginName))
	} else {
		slog.Info("Using NRI plugin name from runtime environment", "name", env)
	}

	if env := getenv(api.PluginIdxEnvVar); env == "" {
		opts = append(opts, stub.WithPluginIdx(settings.pluginIdx))
	} else {
		slog.Info("Using NRI plugin index from runtime environment", "index", env)
	}

	if settings.socketPath != "" {
		opts = append(opts, stub.WithSocketPath(settings.socketPath))
	}

	return opts
}

// trackedDialer dials the NRI socket and remembers the connection so an
// attempt that is stuck waiting for Configure can release it.
type trackedDialer struct {
	mu   sync.Mutex
	conn net.Conn
}

// dialFunc returns the dialer passed to the NRI stub, whose dialer signature
// has no context: the returned function dials within ctx and bounds the
// connect by timeout, so a socket that never accepts cannot block shutdown.
func (d *trackedDialer) dialFunc(
	ctx context.Context, timeout time.Duration,
) func(string) (net.Conn, error) {
	return func(path string) (net.Conn, error) {
		return d.dial(ctx, path, timeout)
	}
}

func (d *trackedDialer) dial(
	ctx context.Context,
	path string,
	timeout time.Duration,
) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := net.Dialer{} //nolint:exhaustruct_v5 // zero-value dialer is valid

	conn, err := dialer.DialContext(dialCtx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("dialing NRI socket: %w", err)
	}

	d.mu.Lock()
	d.conn = conn
	d.mu.Unlock()

	return conn, nil
}

func (d *trackedDialer) close() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.conn != nil {
		_ = d.conn.Close()
	}
}

// runNRI connects the plugin to the NRI runtime and keeps it connected until
// ctx is cancelled. A lost connection marks the plugin as disconnected (so
// /readyz reports not ready) and is retried with exponential backoff while
// caches and background loops keep running. A plugin launched by the runtime
// (pre-installed, NRI_PLUGIN_SOCKET set) cannot reconnect and returns
// errNRIConnectionLost instead. Returns nil when ctx is cancelled.
func runNRI(
	ctx context.Context, plug *plugin.Plugin, settings nriSettings,
	factory nriStubFactory, getenv func(string) string, policy reconnectPolicy,
	conn *nriConnection,
) error {
	preinstalled := getenv(api.PluginSocketEnvVar) != ""
	backoff := policy.initial

	for {
		started := time.Now()

		runErr, err := connectOnce(ctx, plug, settings, factory, getenv, policy, conn)
		if err != nil {
			return err
		}

		if policy.maxAbandoned > 0 && conn.abandoned.Load() >= int64(policy.maxAbandoned) {
			return fmt.Errorf("%w (%d): %w", errTooManyAbandonedNRIConnections,
				policy.maxAbandoned, runErr)
		}

		if isDone(ctx) {
			return nil
		}

		if preinstalled {
			return fmt.Errorf("%w: %w", errNRIConnectionLost, runErr)
		}

		if time.Since(started) >= policy.stable {
			backoff = policy.initial
		}

		slog.Error("NRI connection lost, reconnecting",
			"error", runErr, "retry_in", backoff,
		)

		if !waitForRetry(ctx, backoff, policy.socketExists, nriSocketPollInterval) {
			return nil
		}

		backoff = min(backoff*nriReconnectBackoffFactor, policy.maximum)
	}
}

// connectOnce runs a single NRI connection attempt until the connection ends
// or ctx is cancelled and returns why it ended (runErr). err is only set when
// the stub cannot be created.
func connectOnce(
	ctx context.Context, plug *plugin.Plugin, settings nriSettings,
	factory nriStubFactory, getenv func(string) string, policy reconnectPolicy,
	conn *nriConnection,
) (runErr, err error) {
	gen := conn.begin()
	dialer := &trackedDialer{} //nolint:exhaustruct_v5 // zero-value dialer is valid

	opts := stubOptions(settings, getenv, func() {
		handleNRIClose(ctx, plug, conn, gen)
	})
	opts = append(opts, stub.WithDialer(dialer.dialFunc(ctx, nriDialTimeout)))

	nriStub, err := factory(newConnectionHandler(plug, conn, gen), opts...)
	if err != nil {
		return nil, err
	}

	slog.Info("Starting NRI plugin",
		"name", settings.pluginName, "index", settings.pluginIdx,
	)

	runErr = runStub(ctx, nriStub, policy.configureTimeout, func() {
		// Publish the stub to the continuous verifier only once Start has
		// returned, so UpdateContainers never races with the stub setting
		// up its runtime client.
		plug.SetStub(nriStub)
		conn.markConnected()
	})

	plug.SetStub(nil)
	plug.SetDisconnected()
	conn.markDisconnected(gen, time.Now())
	conn.retire(gen)

	if errors.Is(runErr, errNRIConfigureTimeout) {
		// The stub keeps waiting for Configure while holding its lock and
		// cannot be closed; release the connection instead. Its goroutine
		// stays blocked, which is why abandoned attempts are bounded.
		conn.abandoned.Add(1)
		dialer.close()
	}

	return runErr, nil
}

// runStub runs one NRI connection. It starts the stub, calls onStarted once
// the runtime has configured the plugin, and returns when the connection
// ends or ctx is cancelled. When the runtime does not configure the plugin
// within configureTimeout (for example because the connection dropped after
// registration, which leaves the NRI stub waiting forever), it returns
// errNRIConfigureTimeout without waiting for the stuck stub.
func runStub(
	ctx context.Context, nriStub nriStub, configureTimeout time.Duration, onStarted func(),
) error {
	startErr := make(chan error, 1)

	go func() {
		startErr <- nriStub.Start(ctx)
	}()

	timer := time.NewTimer(configureTimeout)
	defer timer.Stop()

	select {
	case err := <-startErr:
		if err != nil {
			return fmt.Errorf("starting NRI plugin: %w", err)
		}
	case <-ctx.Done():
		// Stop blocks while a stuck Start holds the stub lock, so it must
		// not delay shutdown.
		go nriStub.Stop()

		return fmt.Errorf("starting NRI plugin: %w", ctx.Err())
	case <-timer.C:
		return errNRIConfigureTimeout
	}

	onStarted()

	stopped := make(chan struct{})

	go func() {
		defer close(stopped)

		nriStub.Wait()
	}()

	select {
	case <-stopped:
		return errNRIConnectionClosed
	case <-ctx.Done():
		nriStub.Stop()

		return fmt.Errorf("running NRI plugin: %w", ctx.Err())
	}
}

// handleNRIClose is the stub's connection-close callback for connection gen.
// A close of a previous connection that arrives after a newer connection was
// established is ignored. A close during shutdown is expected and only logged
// at debug level.
func handleNRIClose(ctx context.Context, plug *plugin.Plugin, conn *nriConnection, gen uint64) {
	if !conn.markDisconnected(gen, time.Now()) {
		slog.Debug("Ignoring close of a previous NRI connection")

		return
	}

	plug.SetStub(nil)
	plug.SetDisconnected()

	if ctx.Err() != nil {
		slog.Debug("NRI connection closed during shutdown")

		return
	}

	slog.Warn("NRI connection lost")
}

// isDone reports whether ctx has been cancelled.
func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// waitForRetry waits for the reconnect backoff. When the NRI socket is
// missing at the start (the runtime is down), it returns as soon as the
// socket appears instead, so the plugin reconnects right after the runtime
// comes back. Returns false if ctx ended first.
func waitForRetry(
	ctx context.Context, backoff time.Duration, socketExists func() bool, poll time.Duration,
) bool {
	if socketExists == nil || socketExists() {
		return sleepContext(ctx, backoff)
	}

	timer := time.NewTimer(backoff)
	defer timer.Stop()

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		case <-ticker.C:
			if socketExists() {
				slog.Info("NRI socket appeared, reconnecting")

				return true
			}
		}
	}
}

// sleepContext waits for d or until ctx is done. Returns false if ctx ended
// first.
func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
