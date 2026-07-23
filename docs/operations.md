# Operations

This document covers metrics, health probes, config reload, troubleshooting,
internal limits, and security considerations.

<!-- toc -->

- [Metrics](#metrics)
- [Health and Readiness Probes](#health-and-readiness-probes)
- [Config Reload](#config-reload)
- [Logging](#logging)
- [Troubleshooting](#troubleshooting)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Internal Limits](#internal-limits)
- [Security Considerations](#security-considerations)

<!-- /toc -->

## Metrics

The plugin exposes Prometheus metrics at the configured
[`metrics_addr`](config.md):

| Metric                                           | Type      | Labels                        | Description                                                                          |
| ------------------------------------------------ | --------- | ----------------------------- | ------------------------------------------------------------------------------------ |
| `nri_supply_chain_verification_total`            | Counter   | `type`, `result`, `namespace` | Total verification attempts. `result`: `pass`, `warn`, `fail`                        |
| `nri_supply_chain_verification_duration_seconds` | Histogram | `type`                        | Verification latency                                                                 |
| `nri_supply_chain_cache_hits_total`              | Counter   |                               | Cache hits                                                                           |
| `nri_supply_chain_cache_misses_total`            | Counter   |                               | Cache misses                                                                         |
| `nri_supply_chain_cache_entries`                 | Gauge     |                               | Current number of cached entries                                                     |
| `nri_supply_chain_verification_skipped_total`    | Counter   | `reason`, `namespace`         | Containers allowed without verification. `reason`: `excluded`, `missing_annotations` |
| `nri_supply_chain_fetch_errors_total`            | Counter   | `type`, `registry`            | Attestation fetch errors                                                             |
| `nri_supply_chain_inflight_dedup_total`          | Counter   |                               | Deduplicated inflight verifications                                                  |
| `nri_supply_chain_circuit_breaker_trips_total`   | Counter   | `registry`                    | Circuit breaker open events                                                          |
| `nri_supply_chain_trusted_root_stale_total`      | Counter   |                               | Stale trusted root served from cache                                                 |
| `nri_supply_chain_cache_failure_hits_total`      | Counter   |                               | Cache hits returning a cached failure                                                |

## Health and Readiness Probes

The metrics server exposes `/healthz` and `/readyz` endpoints for Kubernetes
liveness and readiness probes.

- **`/healthz`** (liveness): Always returns HTTP 200. The plugin is considered
  alive as long as the metrics server is running.
- **`/readyz`** (readiness): Returns HTTP 200 only when both conditions are
  met: (1) the plugin is connected to the NRI runtime, and (2) at least one
  policy is loaded (when verification is enabled). Returns HTTP 503 with a
  reason string otherwise. The NRI connection is required regardless of
  verification mode, since the plugin must receive container events to
  function. Before the NRI runtime connects, or if no policies are loaded in
  `warn` or `enforce` mode, the readiness probe fails.

## Config Reload

Send `SIGHUP` to reload the config file and policies without restarting:

```console
kill -HUP $(pidof nri-supply-chain)
```

Or with systemd:

```console
systemctl reload nri-supply-chain
```

A reload re-reads the [TOML config file](config.md) and all
[policy files](policy.md) from disk. The verification cache is cleared only
when cache-affecting config fields changed (`verification`, `policy_dir`,
`cache_ttl`, `cache_failure_ttl`, `fetch_failure_policy`, `fetch_timeout`) or
when the content of any policy file
changed. If the config and policies are identical, the cache is preserved. To
force a cache clear when nothing else needs to change, temporarily modify
`cache_ttl` (for example, change it from `24h` to `23h59m`), send SIGHUP, then
change it back and send SIGHUP again.

The plugin also watches the config file and policy directory for changes using
fsnotify. When a file is written, created, or removed, the plugin automatically
reloads after a 500ms debounce window. Rapid successive writes within that
window are collapsed into a single reload, so editors that perform atomic saves
(write-then-rename) do not trigger duplicate reloads.

## Logging

The plugin outputs structured JSON logs to stderr. Set `--log-level debug` for
detailed verification traces.

## Troubleshooting

- **Container rejected unexpectedly**: Check logs at debug level. Verify the
  policy file for the namespace is correct. Confirm attestations exist in the
  registry (`cosign tree <image>`). The plugin tries the OCI Referrers API
  first, then falls back to cosign tag-based discovery
  (`sha256-<digest>.att`). Debug logs show which path was used.
- **Fetch errors**: Check network connectivity from the node to the registry.
  Set `fetch_failure_policy = "allow"` temporarily to unblock while
  investigating.
- **Stale cache**: Reduce `cache_ttl` or set to `0s` to disable caching during
  debugging. Send SIGHUP to reload; the cache is cleared only when
  cache-affecting config fields (`verification`, `policy_dir`, `cache_ttl`,
  `cache_failure_ttl`, `fetch_failure_policy`, `fetch_timeout`) or policy file
  contents have changed. A SIGHUP with unchanged config and policies does not
  clear the cache. To force a clear, change `cache_ttl` temporarily before
  sending SIGHUP.

## Monitoring and Alerting

Example Prometheus alert rules for key failure conditions:

```yaml
groups:
  - name: nri-supply-chain
    rules:
      - alert: CircuitBreakerTripped
        expr: sum(increase(nri_supply_chain_circuit_breaker_trips_total[5m])) > 0
        for: 5m
        annotations:
          summary: Circuit breaker opened, fetch failures bypass verification.

      - alert: HighFetchErrorRate
        expr: sum(rate(nri_supply_chain_fetch_errors_total[5m])) > 0.1
        for: 5m
        annotations:
          summary: Sustained attestation fetch errors from the registry.

      - alert: VerificationFailures
        expr: sum(rate(nri_supply_chain_verification_total{result="fail"}[5m])) > 0
        for: 1m
        annotations:
          summary: Verification checks are failing (rejected in enforce, logged in warn).

      - alert: HighVerificationLatency
        expr: |
          histogram_quantile(0.99,
            sum(rate(nri_supply_chain_verification_duration_seconds_bucket[5m])) by (le)
          ) > 5
        for: 5m
        annotations:
          summary: p99 verification latency exceeds 5 seconds.
```

## Internal Limits

The plugin enforces several hardcoded limits that are not configurable. These
protect against resource exhaustion and unbounded processing.

| Limit                       | Value                     | Behavior when exceeded                                                                                                   |
| --------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Cache capacity              | 10,000 entries            | Expired entries are evicted first. If the cache is still full, the oldest entry is evicted to make room.                 |
| Concurrent fetch limit      | 50                        | Additional verification requests block until a slot becomes available or the context is canceled.                        |
| Fetch retry count           | 2 retries (3 total)       | Uses exponential backoff starting at 500ms. Only transient errors (network timeouts, HTTP 5xx) trigger retries.          |
| Attestation size limit      | 10 MiB                    | Attestation bundles larger than 10 MiB are rejected. A warning is logged with the actual size.                           |
| Max referrers per image     | 100                       | Only the first 100 bundle-type referrers are processed. Additional referrers are skipped with a warning.                 |
| Sigstore trusted root cache | 1h TTL, 24h max staleness | The root is refreshed every hour. If the Sigstore TUF mirror is unreachable, the stale root is used for up to 24 hours.  |
| VSA clock skew tolerance    | 60 seconds                | A VSA with `timeVerified` up to 60 seconds in the future is accepted. Beyond that, it is rejected as a future timestamp. |

**Sigstore trusted root refresh.** For keyless (Fulcio) verification, the
plugin fetches the Sigstore trusted root from the TUF mirror on startup and
refreshes it every hour. If the mirror becomes unreachable, the cached root
continues to be used for up to 24 hours. After 24 hours without a successful
refresh, keyless verification fails with an error indicating the root is stale.
Key-based verification is not affected by this limit.

## Security Considerations

**fetch_failure_policy default is fail-open.** The default value `"warn"` allows
containers through when attestation fetches fail, even in `enforce` mode. If the
registry is unreachable, every image passes verification. The per-host circuit
breaker amplifies this: once the failure threshold is reached for a given
registry, all subsequent fetch attempts to that registry short-circuit to
`fetch_failure_policy` until the cooldown expires. Set
`fetch_failure_policy = "deny"` in production to ensure fetch failures block
container creation. Note that `"deny"` means registry outages will prevent all
new containers from starting, trading availability for security. Choose based on
your threat model.

**Enforce-mode startup warnings.** When running in `enforce` mode, the plugin
logs warnings at startup if permissive defaults are still in place. It warns
when `fetch_failure_policy` is `warn` or `allow` (since fetch failures would let
containers through), and when any policy has `slsa.missingPolicy` or
`vex.missingPolicy` set to `allow`. Review these warnings and tighten the
settings before relying on enforce mode in production.

**SAN patterns for keyless verification.** In `enforce` mode, `trust.sanPatterns`
is required when `trust.issuers` is configured. The plugin rejects the policy at
startup and reload if this requirement is not met. In `warn` mode, omitting
`sanPatterns` accepts any certificate issued by the trusted OIDC provider (with a
log warning). Always pair `issuers` with `sanPatterns` (for example,
`["*@example.com"]`) to restrict accepted identities.

**Annotation trust model.** The plugin reads image identity from container
annotations set by the container runtime (CRI-O or containerd), not from
Kubernetes pod annotations. CRI-O generates `io.kubernetes.cri-o.*` annotations
from the actual image pull result, and containerd generates
`io.kubernetes.cri.*` annotations from its CRI plugin. A Kubernetes user cannot
override these values through pod spec annotations because the runtime writes
them after processing the CRI request, overwriting any user-supplied keys with
the same name. Additionally, digests are validated for strict `algorithm:hex`
format, and Sigstore bundle verification cryptographically binds each
attestation to the image digest, so forged annotation values would fail
signature verification. The primary risk is not annotation injection but
annotation absence: a runtime version that does not set the expected annotations
causes the plugin to skip verification in `warn` mode (logged and counted via
the `missing_annotations` metric) or reject the container in `enforce` mode.

**Digest resolution TOCTOU.** When the container runtime does not provide an
image digest in annotations (common with containerd), the plugin resolves the
digest via a registry HEAD request. Between this resolution and the subsequent
attestation fetch, a registry could update the tag to point to a different image.
The container runtime may pull the new image while the plugin verifies
attestations for the old one. A compromised or malicious registry could also
intentionally serve a different digest for the HEAD request than the content it
serves to the container runtime, causing the plugin to verify attestations for
one image while a different image runs. CRI-O is not affected because it always
provides the digest in annotations. For containerd deployments in enforce mode,
consider pinning images by digest (`image@sha256:...`) rather than by tag to
eliminate this window entirely.

**Cached fetch failures.** When attestation fetches fail and `fetch_failure_policy`
is `allow` or `warn`, the result is cached for `cache_failure_ttl` (default 5
minutes). During that window, subsequent containers with the same digest are
admitted without contacting the registry. If a registry outage is short-lived,
containers may pass verification for up to 5 minutes after the registry recovers,
because the cached "allowed" result has not yet expired. Set
`fetch_failure_policy = "deny"` to prevent this, or reduce `cache_failure_ttl`
to shorten the window.

**Metrics exposure.** The default `metrics_addr` binds to `127.0.0.1:9090`
(loopback only). Changing this to a non-loopback address (for example,
`0.0.0.0:9090`) exposes metrics externally. Prometheus metrics include image
references, namespace labels, and verification outcomes, which could aid
reconnaissance. The plugin logs a warning at startup when `metrics_addr` is not
a loopback address. Use a NetworkPolicy or firewall rule to restrict access when
exposing the metrics endpoint to a Prometheus scraper on another host.
