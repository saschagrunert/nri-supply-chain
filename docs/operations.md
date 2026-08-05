# Operations

This document covers metrics, health probes, config reload, troubleshooting,
internal limits, and security considerations.

<!-- toc -->

- [Metrics](#metrics)
- [Health and Readiness Probes](#health-and-readiness-probes)
- [Status Endpoint](#status-endpoint)
- [Config Reload](#config-reload)
- [Logging](#logging)
  - [Audit Logging](#audit-logging)
- [Troubleshooting](#troubleshooting)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Internal Limits](#internal-limits)
- [Security Considerations](#security-considerations)

<!-- /toc -->

## Metrics

The plugin exposes Prometheus metrics at the configured
[`metrics_addr`](config.md):

| Metric                                            | Type      | Labels                        | Description                                                                                          |
| ------------------------------------------------- | --------- | ----------------------------- | ---------------------------------------------------------------------------------------------------- |
| `nri_supply_chain_verification_total`             | Counter   | `type`, `result`, `namespace` | Total verification attempts. `result`: `pass`, `warn`, `fail`                                        |
| `nri_supply_chain_verification_duration_seconds`  | Histogram | `type`                        | Verification latency                                                                                 |
| `nri_supply_chain_cache_hits_total`               | Counter   |                               | Cache hits                                                                                           |
| `nri_supply_chain_cache_misses_total`             | Counter   |                               | Cache misses                                                                                         |
| `nri_supply_chain_cache_entries`                  | Gauge     |                               | Current number of cached entries                                                                     |
| `nri_supply_chain_cache_evictions_total`          | Counter   | `reason`                      | Cache entry evictions. `reason`: `expired`, `capacity`                                               |
| `nri_supply_chain_verification_skipped_total`     | Counter   | `reason`, `namespace`         | Containers allowed without verification. `reason`: `excluded`, `missing_annotations`, `not_included` |
| `nri_supply_chain_fetch_duration_seconds`         | Histogram | `registry`                    | Attestation fetch latency per registry                                                               |
| `nri_supply_chain_fetch_errors_total`             | Counter   | `type`, `registry`            | Attestation fetch errors                                                                             |
| `nri_supply_chain_inflight_dedup_total`           | Counter   |                               | Deduplicated inflight verifications                                                                  |
| `nri_supply_chain_circuit_breaker_trips_total`    | Counter   | `registry`                    | Circuit breaker open events                                                                          |
| `nri_supply_chain_trusted_root_stale_total`       | Counter   |                               | Stale trusted root served from cache                                                                 |
| `nri_supply_chain_cache_failure_hits_total`       | Counter   |                               | Cache hits returning a cached failure                                                                |
| `nri_supply_chain_build_info`                     | Gauge     | `version`, `goversion`        | Build metadata (set once at startup)                                                                 |
| `nri_supply_chain_config_reloads_total`           | Counter   |                               | Successful config reloads                                                                            |
| `nri_supply_chain_verification_interrupted_total` | Counter   |                               | Verifications interrupted by context cancellation                                                    |
| `nri_supply_chain_config_reload_errors_total`     | Counter   |                               | Failed config reload attempts                                                                        |
| `nri_supply_chain_prewarm_duration_seconds`       | Histogram | `result`                      | Cache prewarm latency (buckets: 1, 5, 10, 30, 60, 120, 300)                                          |
| `nri_supply_chain_mirror_fallback_total`          | Counter   | `registry`, `type`            | Mirror fallback events. `type`: `digest`, `attestation`                                              |
| `nri_supply_chain_container_lifetime_seconds`     | Histogram | `namespace`                   | Duration containers run before removal (buckets: exponential 0.5s \* 2^n, n=0..20)                   |

When `include` is configured, the include check runs before the exclude check.
Images that do not match any include pattern are counted as `not_included` even
if they also match an exclude pattern.

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

## Status Endpoint

The metrics server exposes a `GET /status` endpoint that returns a JSON object
with operational details about the running plugin.

Example response:

```json
{
  "ready": true,
  "mode": "warn",
  "policies": {
    "count": 2,
    "namespaces": ["kube-system", "production"],
    "source": "local"
  },
  "cache": {
    "size": 42,
    "maxSize": 10000
  },
  "circuitBreakers": {
    "ghcr.io": "closed",
    "docker.io": "open"
  },
  "nri": {
    "connected": true
  }
}
```

| Field                 | Type              | Description                                                              |
| --------------------- | ----------------- | ------------------------------------------------------------------------ |
| `ready`               | bool              | Whether the plugin is ready (NRI connected and verifier ready)           |
| `mode`                | string            | Current verification mode (`warn`, `enforce`, or `disabled`)             |
| `policies.count`      | int               | Number of loaded policy files (includes the default cluster-wide policy) |
| `policies.namespaces` | string[]          | Namespaces with namespace-specific policies                              |
| `policies.source`     | string            | Policy source (`local` or `oci`)                                         |
| `cache.size`          | int               | Current number of cached verification results                            |
| `cache.maxSize`       | int               | Maximum cache capacity                                                   |
| `circuitBreakers`     | map[string]string | Per-registry circuit breaker state (`closed`, `open`, `half-open`)       |
| `nri.connected`       | bool              | Whether the plugin is connected to the NRI runtime                       |

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
`cache_ttl`, `cache_failure_ttl`, `fetch_failure_policy`, `fetch_timeout`,
`sigstore.tuf_mirror`, `sigstore.tuf_root`, `registries`,
`policy.source`, `policy.oci_ref`) or
when the content of any policy file
changed. If the config and policies are identical, the cache is preserved. To
force a cache clear when nothing else needs to change, temporarily modify
`cache_ttl` (for example, change it from `24h` to `23h59m`), send SIGHUP, then
change it back and send SIGHUP again.

When `policy.source = "oci"` is configured, SIGHUP stops the running OCI
poller and starts a new one with the updated configuration. This allows
changing the `oci_ref`, `poll_interval`, or switching between `local` and `oci`
sources without restarting the plugin.

When the OCI policy registry is unreachable at startup (connection refused, DNS
failure, timeout, TLS handshake error, or server error), the plugin starts in a
pending state instead of crashing. Non-transient errors such as invalid OCI
references, signature verification failures, or malformed policy content still
cause a hard failure.
In pending state the plugin reports not-ready via `/readyz` and begins polling
for policies in the background. Containers are handled according to the
configured verification mode: in `warn` mode they are allowed through
(unverified), in `enforce` mode they are rejected. Once the registry becomes
reachable and policies are loaded, the plugin transitions to ready and begins
normal verification.

The plugin also watches the config file and policy directory for changes using
fsnotify. When a file is written, created, removed, or renamed, the plugin automatically
reloads after a 500ms debounce window. Rapid successive writes within that
window are collapsed into a single reload, so editors that perform atomic saves
(write-then-rename) do not trigger duplicate reloads.

## Logging

The plugin outputs structured JSON logs to stderr. Set `--log-level debug` for
detailed verification traces.

### Audit Logging

Every verification decision emits a structured log entry with the message
`"Supply chain audit"`. Filter for this message to build an audit trail of
all container verification outcomes.

| Field               | Description                                                      |
| ------------------- | ---------------------------------------------------------------- |
| `image`             | Full image reference                                             |
| `digest`            | Image digest                                                     |
| `namespace`         | Kubernetes namespace                                             |
| `allowed`           | Whether the container was allowed                                |
| `check`             | Check type (e.g. `slsa`, `vex`, `vsa`), present for check events |
| `status`            | Check result status                                              |
| `detail`            | Human-readable check detail                                      |
| `decision`          | `allowed` or `denied`, present for decision events               |
| `reason`            | Human-readable decision reason                                   |
| `policyHash`        | SHA-256 hash of the policy file used for verification            |
| `nodeName`          | Node where the container was scheduled                           |
| `podServiceAccount` | Kubernetes service account of the pod                            |
| `verificationMode`  | Effective verification mode (`warn`, `enforce`)                  |

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
  `cache_failure_ttl`, `fetch_failure_policy`, `fetch_timeout`,
  `sigstore.tuf_mirror`, `sigstore.tuf_root`, `registries`,
  `policy.source`, `policy.oci_ref`) or policy file
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

      - alert: VerificationInterrupted
        expr: sum(increase(nri_supply_chain_verification_interrupted_total[5m])) > 0
        for: 5m
        annotations:
          summary: Verifications are being interrupted by context cancellation.

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

| Limit                       | Value                            | Behavior when exceeded                                                                                                                                                                                      |
| --------------------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cache capacity              | 10,000 entries (default)         | Configurable via `cache_max_entries` (100 to 1,000,000). Expired entries are evicted first. If the cache is still full, the oldest entry is evicted to make room.                                           |
| Concurrent fetch limit      | 50                               | Additional verification requests block until a slot becomes available or the context is canceled.                                                                                                           |
| Per-host fetch limit        | 10                               | At most 10 of the 50 global fetch slots can be used by a single registry host. Prevents one slow or unresponsive registry from starving fetches to other registries.                                        |
| Fetch retry count           | 2 retries (3 total)              | Uses exponential backoff starting at 500ms. Only transient errors (network timeouts, HTTP 5xx) trigger retries.                                                                                             |
| Attestation size limit      | 10 MiB per attestation (default) | Configurable via `max_attestation_size` (1 MiB to 100 MiB). Attestation bundles exceeding the limit are rejected. A warning is logged with the actual size.                                                 |
| Aggregate attestation limit | 50 MiB per image                 | Total attestation payload per image is capped at 50 MiB. Once exceeded, remaining referrers or cosign layers are skipped with a warning.                                                                    |
| Max referrers per image     | 50                               | Only the first 50 bundle-type referrers are processed. Additional referrers are skipped with a warning.                                                                                                     |
| Policy file size limit      | 1 MiB per file                   | Policy files larger than 1 MiB are rejected during loading. The file is read through a size-limited reader and an error is returned if the limit is exceeded.                                               |
| Circuit breaker registry    | 1,000 hosts                      | At most 1,000 per-host circuit breakers are tracked. When full, closed breakers are evicted first. If all remaining breakers are open or half-open, a shared overflow breaker is used for additional hosts. |
| Sigstore trusted root cache | 1h TTL, 24h max staleness        | The root is refreshed every hour. If the Sigstore TUF mirror is unreachable, the stale root is used for up to 24 hours.                                                                                     |
| VSA clock skew tolerance    | 60 seconds                       | A VSA with `timeVerified` up to 60 seconds in the future is accepted. Beyond that, it is rejected as a future timestamp.                                                                                    |
| Digest resolve timeout      | 1 second                         | Image digest resolution during NRI callbacks is capped at 1 second to stay under containerd's ttrpc timeout. The `verify` CLI path uses the configured `fetch_timeout` instead.                             |
| Policy file count limit     | 1,000 files                      | At most 1,000 JSON policy files are loaded from the policy directory. If the count exceeds this limit, policy loading fails with an error.                                                                  |
| Glob pattern cache          | 10,000 patterns                  | Compiled glob patterns are cached for reuse. Once the cache holds 10,000 entries, new patterns still compile and match but are not cached.                                                                  |
| OCI policy layer size       | 1 MiB per layer                  | Individual OCI policy layers larger than 1 MiB are rejected during fetch. The layer is read through a size-limited reader and an error is returned if the limit is exceeded.                                |
| OCI policy layer count      | 1,000 layers                     | At most 1,000 layers are processed from an OCI policy artifact. If the artifact contains more layers, policy loading fails with an error.                                                                   |
| Credential file size        | 1 MiB per file                   | PEM public key files, CA certificate bundles, and TUF root files are read through a size-limited reader. Files exceeding 1 MiB are rejected.                                                                |
| Config file size            | 10 MiB                           | The TOML config file is read through a size-limited reader. Files exceeding 10 MiB are rejected at load time.                                                                                               |
| Symlink restriction         | Not allowed                      | The `policy_dir`, `sigstore.tuf_root`, and registry `ca_cert` paths must not be symbolic links. Symlinks are detected via `Lstat` and rejected during runtime validation.                                   |

**Sigstore trusted root refresh.** For keyless (Fulcio) verification, the
plugin fetches the Sigstore trusted root from the TUF mirror on startup and
refreshes it every hour. If the mirror becomes unreachable, the cached root
continues to be used for up to 24 hours. After 24 hours without a successful
refresh, keyless verification fails with an error indicating the root is stale.
Key-based verification is not affected by this limit.

## Security Considerations

**fetch_failure_policy in enforce mode defaults to deny.** In enforce mode,
`fetch_failure_policy` defaults to `"deny"` so that registry outages cannot
silently bypass verification. In warn mode the default remains `"warn"`. You
can override this by setting `fetch_failure_policy` explicitly in the config.
The per-host circuit breaker amplifies the effect: once the failure threshold
is reached for a given registry, all subsequent fetch attempts short-circuit to
`fetch_failure_policy` until the cooldown expires. With `"deny"`, registry
outages will prevent new containers from starting, trading availability for
security. Set `fetch_failure_policy = "allow"` or `"warn"` explicitly if your
threat model favors availability.

**Metrics label cardinality.** Several metrics use `namespace` and `registry`
labels whose cardinality depends on the cluster. In multi-tenant clusters with
many namespaces or images pulled from many registries, these labels can cause
significant Prometheus memory growth. Monitor the cardinality of
`nri_supply_chain_verification_total`, `nri_supply_chain_fetch_errors_total`,
and `nri_supply_chain_fetch_duration_seconds` (a histogram producing ~16 series
per registry: bucket counters + sum + count) and consider Prometheus recording
rules to pre-aggregate if the series count grows large.

**Enforce-mode startup warnings.** When running in `enforce` mode, the plugin
logs warnings at startup if permissive settings are in place. It warns
when `fetch_failure_policy` is explicitly set to `warn` or `allow` (since
fetch failures would let containers through), and when any policy has
`slsa.missingPolicy` or `vex.missingPolicy` set to `allow`. It also warns when
a policy uses key-only verification (verifiers with keys and no OIDC issuers)
while `signatures.requireTransparencyLog` is false, because compromised keys
cannot be time-bounded without transparency log entries. Review these warnings
and tighten the settings before relying on enforce mode in production.

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
because the cached "allowed" result has not yet expired. In enforce mode the
default `fetch_failure_policy` is `deny`, which prevents this. In warn mode,
set `fetch_failure_policy = "deny"` explicitly or reduce `cache_failure_ttl`
to shorten the window.

**Metrics exposure.** The default `metrics_addr` binds to `127.0.0.1:9090`
(loopback only). Changing this to a non-loopback address (for example,
`0.0.0.0:9090`) exposes metrics externally. Prometheus metrics include image
references, namespace labels, and verification outcomes, which could aid
reconnaissance. The plugin logs a warning at startup when `metrics_addr` is not
a loopback address. Use a NetworkPolicy or firewall rule to restrict access when
exposing the metrics endpoint to a Prometheus scraper on another host.
