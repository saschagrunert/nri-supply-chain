# Configuration Reference

This document covers the operational configuration and CLI flags for the
nri-supply-chain plugin.

<!-- toc -->

- [Operational Config](#operational-config)
  - [GUAC](#guac)
  - [Remediation](#remediation)
  - [Runtime reload](#runtime-reload)
  - [Offline Bundles](#offline-bundles)
- [Private Sigstore Instances](#private-sigstore-instances)
  - [Multiple Sigstore Trusted Roots](#multiple-sigstore-trusted-roots)
- [Registries](#registries)
- [Policy Distribution](#policy-distribution)
  - [Policy Signature Verification](#policy-signature-verification)
- [Policy Files](#policy-files)
- [CLI](#cli)
  - [Batch Verification](#batch-verification)
  - [Exit Codes](#exit-codes)
  - [Preview](#preview)
  - [Effective Policy](#effective-policy)
  - [Inspect](#inspect)
  - [JSON Schema](#json-schema)
  - [Bundle Management](#bundle-management)

<!-- /toc -->

## Operational Config

The TOML parser uses strict mode: unknown keys cause a startup error. If the
config file contains fields that are not listed below (for example, leftover
keys from an older version or custom annotations), the plugin will refuse to
start. Remove or comment out any unrecognized keys before upgrading.

```toml
# config_version = 1
verification = "warn"
log_level = "info"
fetch_timeout = "30s"
# digest_resolve_timeout = "1s"
# fetch_failure_policy = "warn"
cache_ttl = "24h"
cache_failure_ttl = "5m"
policy_dir = "/etc/nri-supply-chain/policies"
metrics_addr = "127.0.0.1:9090"
circuit_breaker_threshold = 5
circuit_breaker_cooldown = "30s"
# verification_timeout = "5m"
# check_timeout = "2m"
# fetch_rate_limit = 0
# audit_log = ""

# allowlist_digests = [
#   "sha256:a1b2c3d4...",
#   "docker.io/library/nginx@sha256:e5f6a7b8...",
# ]

# [policy]
# source = "oci"
# oci_ref = "ghcr.io/myorg/supply-chain-policies:v1"
# poll_interval = "5m"

# [sigstore]
# tuf_mirror = "https://tuf.internal.example.com"
# tuf_root = "/etc/sigstore/root.json"

# [offline]
# mode = "disabled"
# attestation_store = "/var/lib/nri-supply-chain/bundles"
# bundle_max_age = "720h"
# bundle_expiry_policy = "warn"
# require_bundle_signature = false
# bundle_signature_key = ""
```

| Field                       | Default                          | Description                                                                                                                                                                                                                                                                                                |
| --------------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `config_version`            | `1`                              | Schema version of the config file. Omitting defaults to 1. The plugin rejects versions newer than it supports.                                                                                                                                                                                             |
| `verification`              | `disabled`                       | Global mode: `disabled`, `warn` (log-only), `enforce` (reject on failure). Per-namespace overrides are set in policy files via the `mode` field (see [policy.md](policy.md)).                                                                                                                              |
| `log_level`                 | (CLI flag)                       | Log verbosity override: `debug`, `info`, `warn`, `error`                                                                                                                                                                                                                                                   |
| `fetch_timeout`             | `30s`                            | Per-request timeout for attestation fetches. Max 5m. Also used for digest resolution in the CLI `verify` command (the NRI plugin uses `digest_resolve_timeout` instead).                                                                                                                                   |
| `digest_resolve_timeout`    | `1s`                             | Timeout for resolving an image tag to its digest when the runtime does not provide one. Max 5s. Keep below containerd's ~2s ttrpc deadline.                                                                                                                                                                |
| `fetch_failure_policy`      | `warn` (`deny` in enforce mode)  | Behavior when attestation fetch fails: `allow`, `warn`, `deny`. In enforce mode, defaults to `deny` unless explicitly set. Setting `allow` in enforce mode is rejected during config validation. If upgrading from a version that permitted this combination, change to `warn` or `deny` before upgrading. |
| `cache_ttl`                 | `24h`                            | TTL for cached verification results (`0s` disables caching). Max 7d.                                                                                                                                                                                                                                       |
| `cache_failure_ttl`         | `5m`                             | TTL for cached failure results, so transient errors retry sooner. Max 1h.                                                                                                                                                                                                                                  |
| `policy_dir`                | `/etc/nri-supply-chain/policies` | Directory containing JSON policy files                                                                                                                                                                                                                                                                     |
| `metrics_addr`              | `127.0.0.1:9090`                 | Prometheus metrics HTTP listen address                                                                                                                                                                                                                                                                     |
| `circuit_breaker_threshold` | `5`                              | Consecutive fetch failures before a per-host circuit breaker opens                                                                                                                                                                                                                                         |
| `circuit_breaker_cooldown`  | `30s`                            | Duration the circuit breaker stays open before allowing a probe. Max 10m.                                                                                                                                                                                                                                  |
| `verification_timeout`      | `5m`                             | Maximum time for a single image verification. Must be positive, maximum 30m.                                                                                                                                                                                                                               |
| `check_timeout`             | `2m`                             | Maximum time for a single attestation check (e.g. SLSA, VEX, SBOM) within a verification. Must not exceed `verification_timeout`.                                                                                                                                                                          |
| `fetch_rate_limit`          | `0` (unlimited)                  | Maximum registry fetch requests per second (max 10,000)                                                                                                                                                                                                                                                    |
| `max_attestation_size`      | `10485760` (10 MiB)              | Maximum allowed size in bytes for a single attestation bundle. Min 1 MiB, max 100 MiB.                                                                                                                                                                                                                     |
| `cache_max_entries`         | `10000`                          | Maximum number of entries in the verification result cache. Min 100, max 1,000,000.                                                                                                                                                                                                                        |
| `allowlist_digests`         | `[]`                             | Global list of trusted image digests that skip verification in all namespaces, overriding per-namespace policies. Accepts bare digests (`sha256:...`) or full references (`image@sha256:...`). Reloaded with the config on SIGHUP.                                                                         |
| `audit_log`                 | (empty)                          | Absolute path for a dedicated audit log file. When set, supply chain audit events are written as JSON to this file instead of the application logger. Reloaded on SIGHUP.                                                                                                                                  |

### GUAC

[GUAC](https://guac.sh/) (Graph for Understanding Artifact Composition) can be
used as a supplemental data source for vulnerability correlation, dependency
analysis, and Scorecard queries. GUAC is not an attestation format; it runs as
a separate service that the plugin queries in parallel with the OCI attestation
fetch.

```toml
[guac]
endpoint = "https://guac.internal:8443"
# auth_token_path = "/var/run/secrets/guac/token"
# ca_cert = "/etc/guac/ca.pem"
# timeout = "5s"
# fallback_policy = "warn"
# max_dependencies = 5
# checks = ["certify_vuln", "certify_scorecard", "is_dependency"]
```

GUAC is enabled when `endpoint` is set (no separate toggle).

| Field              | Default                                                  | Description                                                                                                                                        |
| ------------------ | -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `endpoint`         | (empty)                                                  | GUAC API base URL. Setting this enables GUAC queries.                                                                                              |
| `auth_token_path`  | (empty)                                                  | Absolute path to a bearer token file. Cached and re-read when the file changes, to support K8s secret rotation.                                    |
| `ca_cert`          | (empty)                                                  | Absolute path to a PEM-encoded CA certificate for TLS verification against a private CA.                                                           |
| `timeout`          | `5s`                                                     | Per-query timeout for GUAC API requests. Max 30s.                                                                                                  |
| `fallback_policy`  | `warn`                                                   | Behavior when GUAC is unreachable: `allow` (skip), `warn` (default), `deny` (fail)                                                                 |
| `checks`           | `["certify_vuln", "certify_scorecard", "is_dependency"]` | Which GUAC query types to run. See [verification.md](verification.md#guac-graph-for-understanding-artifact-composition) for details on each check. |
| `max_dependencies` | `5`                                                      | Maximum number of dependency PURLs returned from the dependency query (1-20)                                                                       |

The GUAC client has its own circuit breaker (separate from the per-registry
breakers) using the global `circuit_breaker_threshold` and
`circuit_breaker_cooldown` settings.

See [operations.md](operations.md) for the metrics reference, config reload
behavior, and health/readiness probes.

### Remediation

Continuous verification periodically re-evaluates running containers and applies
graduated remediation when verification state degrades.

```toml
[remediation]
mode = "throttle"
interval = "5m"
batch_size = 10
cooldown = "5m"
feed_dir = "/etc/nri-supply-chain/feeds"

[remediation.throttle]
cpu_quota_percent = 10
memory_limit_percent = 50

[remediation.triggers]
on_new_cve = true
on_attestation_revoked = true
on_policy_change = true
```

Remediation is disabled by default (no `mode` set). Setting `mode` to `warn`, `throttle`, or `evict` enables continuous verification. A background loop re-verifies tracked containers at the configured interval. If verification degrades, the plugin applies graduated responses based on the `mode` ceiling.

| Field                                         | Default | Description                                                                                                                                                |
| --------------------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `remediation.mode`                            | (empty) | Maximum remediation action: `warn` (log only), `throttle` (reduce cgroup limits), `evict` (terminate; pending upstream NRI support). Empty means disabled. |
| `remediation.interval`                        | `5m`    | Time between timer-triggered verification cycles. Min 30s, max 1h.                                                                                         |
| `remediation.batch_size`                      | `10`    | Number of containers re-verified per batch before yielding. Max 100.                                                                                       |
| `remediation.cooldown`                        | `5m`    | Minimum time between successive remediation actions on the same container. Min 30s, max 1h.                                                                |
| `remediation.feed_dir`                        | (empty) | Absolute path to a directory watched for OSV JSON vulnerability feed files. Changes trigger PURL-filtered re-verification of affected containers.          |
| `remediation.throttle.cpu_quota_percent`      | `10`    | Percentage of the container's original CPU quota to allow after throttling. Range: 1-100.                                                                  |
| `remediation.throttle.memory_limit_percent`   | `50`    | Percentage of the container's original memory limit to allow after throttling. Range: 1-100.                                                               |
| `remediation.triggers.on_new_cve`             | `true`  | Re-verify when new CVE feed files appear in `feed_dir`.                                                                                                    |
| `remediation.triggers.on_attestation_revoked` | `true`  | Re-verify when attestation state changes.                                                                                                                  |
| `remediation.triggers.on_policy_change`       | `true`  | Re-verify after a config or policy reload (SIGHUP or file watch).                                                                                          |

The state machine progresses: Verified -> Degraded -> Throttled. A container
must be in the Degraded state for at least one full verification cycle before
being escalated to Throttled. When verification recovers, the container
returns to Verified and its original cgroup limits are restored. Containers
recovered after a plugin restart skip rollback on their first recovery because
the stored resources may reflect pre-restart throttled values. After the first
successful non-degraded re-verification, subsequent throttle/recover cycles
work normally.

Timer-triggered cycles use cached verification results when available. Feed
and manual triggers invalidate the cache before re-verification to ensure
fresh attestation data is fetched.

Setting `mode = "evict"` requires `verification = "enforce"`. Eviction is
accepted in the config but logs a warning that it is deferred until the
upstream NRI API exposes `EvictContainers()`. The state machine stops at
Throttled in the meantime.

### Runtime reload

The plugin reloads its configuration on SIGHUP or when the config file changes
on disk. Most fields take effect immediately. The following fields require a
full restart:

| Field                       | Reason                                                       |
| --------------------------- | ------------------------------------------------------------ |
| `config_version`            | Schema version is structural                                 |
| `metrics_addr`              | The HTTP listener is already bound at start                  |
| `remediation.mode` (enable) | The continuous verifier goroutine is started only on boot    |
| `remediation.interval`      | The verification ticker interval is set at goroutine startup |

When a non-reloadable field changes during a reload, the plugin logs a warning
and keeps the original value.

### Offline Bundles

For air-gapped environments, the plugin can verify attestations from portable bundles stored on disk instead of fetching them from OCI registries. Bundles use OCI layout on disk and contain all attestation data, trust material, and optional revocation snapshots.

```toml
[offline]
mode = "prefer-bundle"
attestation_store = "/var/lib/nri-supply-chain/bundles"
bundle_max_age = "720h"
bundle_expiry_policy = "warn"
require_bundle_signature = true
bundle_signature_key = "/etc/nri-supply-chain/bundle-key.pub"
```

| Field                              | Default                             | Description                                                                                                                              |
| ---------------------------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `offline.mode`                     | `disabled`                          | Offline mode: `disabled` (registry only), `prefer-bundle` (try bundle first, fall back to registry), `offline` (bundle only, no network) |
| `offline.attestation_store`        | `/var/lib/nri-supply-chain/bundles` | Absolute path to the on-disk bundle store directory                                                                                      |
| `offline.bundle_max_age`           | `720h` (30 days)                    | Maximum acceptable bundle age. Bundles older than this are considered stale.                                                             |
| `offline.bundle_expiry_policy`     | `warn`                              | Behavior for stale bundles: `allow` (accept silently), `warn` (accept with log warning), `deny` (reject)                                 |
| `offline.require_bundle_signature` | `false`                             | Require bundles to have a valid cryptographic signature                                                                                  |
| `offline.bundle_signature_key`     | (empty)                             | Absolute path to PEM-encoded public key for bundle signature verification. Required when `require_bundle_signature` is true.             |

The three modes control how the plugin sources attestation data:

**disabled** (default): All attestations are fetched from OCI registries via the Referrers API. The bundle store is ignored. This is the standard mode for environments with registry connectivity.

**prefer-bundle**: The plugin tries the local bundle store first. If no attestations are found for an image in the bundle, it falls back to the OCI registry. This is useful during transitions from connected to air-gapped operation, or when bundles cover most but not all images.

**offline**: The plugin reads attestations exclusively from the bundle store. No network calls are made to OCI registries. If an image is not in the bundle, verification fails. Use this in fully disconnected environments.

When `offline.mode` is changed via config reload, the plugin creates a new fetcher and invalidates the verification cache. The file watcher also monitors the `attestation_store` directory so that bundle updates trigger a reload automatically.

The `attestation_store` path must be absolute and must not be a symbolic link. In `offline` and `prefer-bundle` modes, the directory must exist at startup (validated during runtime validation).

**Important:** When a bundle does not contain an embedded Sigstore trusted root
(e.g. it was created without `--trusted-root`), the plugin cannot perform
Sigstore signature verification on individual attestations. In this case,
attestation payloads are extracted from the DSSE envelope without verifying the
Sigstore signature chain. Bundle-level integrity (blob SHA-256 checksums) still
applies, but the cryptographic link to a Sigstore identity is absent. To ensure
full verification in this scenario, set `require_bundle_signature = true` and
provide a `bundle_signature_key` so that at least the bundle as a whole is
cryptographically authenticated.

## Private Sigstore Instances

By default, keyless verification uses the public Sigstore instance (public
Fulcio CA, public Rekor transparency log). Organizations running a private
Sigstore deployment can point the plugin at their internal TUF mirror:

```toml
[sigstore]
tuf_mirror = "https://tuf.internal.example.com"
tuf_root = "/etc/sigstore/root.json"
```

| Field                 | Default         | Description                                                                                                  |
| --------------------- | --------------- | ------------------------------------------------------------------------------------------------------------ |
| `sigstore.tuf_mirror` | (empty, public) | **Deprecated.** URL of a custom TUF mirror for the Sigstore trusted root. Use `[[sigstore.roots]]` instead.  |
| `sigstore.tuf_root`   | (empty)         | **Deprecated.** Path to a custom TUF root.json for private root key trust. Use `[[sigstore.roots]]` instead. |

The trusted root fetched from the custom TUF mirror contains the Fulcio CA
certificates and Rekor transparency log keys for the private deployment.

There are three usage patterns:

**CDN mirror of public Sigstore** (tuf_mirror only): When only `tuf_mirror` is
set, the mirror is treated as a CDN replica of the public Sigstore TUF
repository. The embedded public Sigstore root.json is used as the TUF trust
anchor. This is suitable for air-gapped environments that mirror the public
Sigstore infrastructure but use the same root keys.

**Fully private Sigstore deployment** (tuf_mirror + tuf_root): When both fields
are set, `tuf_root` provides the TUF trust anchor (root.json) for a private
Sigstore deployment that uses its own root keys. Without this, TUF
verification fails because the default public Sigstore root keys do not match
the private deployment's keys. The path must be absolute and the file must
exist and be non-empty at startup.

**Pre-seeded trusted root fallback** (tuf_root only): When only `tuf_root` is
set without `tuf_mirror`, the plugin tries the public Sigstore CDN first for
each verification request. If the CDN is unreachable (DNS failure, connection
timeout, TLS error), it falls back to the pre-seeded trusted root from the
local file. This supports air-gapped environments where the trusted root is
pre-provisioned on disk but connectivity to the public CDN may be restored
later. The pre-seeded root is not cached, but after a CDN failure the plugin
skips retries for 5 minutes (negative cache) before re-attempting the CDN.

The `tuf_mirror` URL must use the `https` scheme. Reachability is
not validated at config load time; a failure to reach the mirror is handled at
verification time through the normal fetch failure policy. The plugin does not
fall back to the public Sigstore instance when a configured mirror is
unreachable.

When `tuf_mirror` or `tuf_root` is changed via config reload, the plugin
creates a new fetcher with the updated settings and invalidates the
verification cache. Changes to the file content at the same `tuf_root` path
are not detected; update the config value to force a re-read.

### Multiple Sigstore Trusted Roots

Some environments need to verify attestations signed by more than one Sigstore
infrastructure. For example, images may carry attestations from both the public
Sigstore instance and GitHub's private Sigstore deployment (used by
`actions/attest-build-provenance`). The `[[sigstore.roots]]` array lets you
configure multiple trusted roots:

```toml
[sigstore]
include_public_root = true

[[sigstore.roots]]
name = "github"
tuf_mirror = "https://tuf-repo.github.com"
tuf_root = "/etc/sigstore/github-tuf-root.json"

[[sigstore.roots]]
name = "internal"
tuf_mirror = "https://tuf.internal.example.com"
```

| Field                          | Default                   | Description                                                             |
| ------------------------------ | ------------------------- | ----------------------------------------------------------------------- |
| `sigstore.roots[].name`        | (required)                | Human-readable label, must be unique across entries                     |
| `sigstore.roots[].tuf_mirror`  | (empty = public Sigstore) | HTTPS URL of the TUF mirror for this root                               |
| `sigstore.roots[].tuf_root`    | (empty)                   | Absolute path to a custom root.json for TUF trust anchor initialization |
| `sigstore.include_public_root` | `true`                    | Include the public Sigstore trusted root alongside custom roots         |

Each entry creates an independent trusted root cache that refreshes from its
TUF mirror on the same schedule as the single-root case (1h TTL, 24h max
staleness). During verification, the plugin builds a combined trusted material
set from all configured roots. A bundle is accepted if it validates against any
one of the trusted roots.

When `include_public_root` is true (the default), the public Sigstore trusted
root is automatically prepended to the list. Set it to false when you only
want to accept attestations signed by your configured private roots.

**Note:** `include_public_root` only takes effect when `[[sigstore.roots]]` is
used. When using the legacy scalar `tuf_mirror`/`tuf_root` fields, it has no
effect; the scalar path always uses only the configured private mirror (matching
pre-roots behavior).

**Migrating from scalar fields.** The scalar `[sigstore]` fields (`tuf_mirror`,
`tuf_root`) and the `[[sigstore.roots]]` array are mutually exclusive. To
migrate, replace the scalar fields with a single `[[sigstore.roots]]` entry.
The following two configurations are equivalent:

```toml
# Old (scalar):
[sigstore]
tuf_mirror = "https://tuf.internal.example.com"
tuf_root = "/etc/sigstore/root.json"

# New (roots array):
[sigstore]
include_public_root = false

[[sigstore.roots]]
name = "internal"
tuf_mirror = "https://tuf.internal.example.com"
tuf_root = "/etc/sigstore/root.json"
```

**GitHub attestations example.** To verify attestations produced by GitHub
Actions `actions/attest-build-provenance`, add the GitHub TUF root and
configure a policy that trusts the GitHub OIDC issuer:

```toml
[sigstore]
include_public_root = true

[[sigstore.roots]]
name = "github"
tuf_mirror = "https://tuf-repo.github.com"
tuf_root = "/etc/sigstore/github-tuf-root.json"
```

Pair this with a policy file that trusts the GitHub Actions OIDC issuer and
restricts SAN patterns to your organization (see
[`deploy/examples/policies/github-attestations.json`](../deploy/examples/policies/github-attestations.json)).

## Registries

Use the `[[registries]]` TOML array to configure registry mirrors, custom TLS
CA certificates, and insecure connections. Each entry matches images by their
registry host prefix.

```toml
[[registries]]
prefix = "ghcr.io"
mirror = "mirror.internal.example.com"

[[registries]]
prefix = "registry.internal.example.com"
ca_cert = "/etc/ssl/certs/internal-ca.pem"

[[registries]]
prefix = "dev-registry.local"
insecure = true
```

| Field      | Default | Description                                                       |
| ---------- | ------- | ----------------------------------------------------------------- |
| `prefix`   | (none)  | Registry host to match exactly (required)                         |
| `mirror`   | (none)  | Replacement registry host for matched images                      |
| `ca_cert`  | (none)  | Absolute path to a PEM-encoded CA certificate bundle              |
| `insecure` | `false` | Skip TLS certificate verification (not recommended in production) |

When multiple `[[registries]]` entries are present, the first entry whose
`prefix` matches the image's registry host exactly is used. For example,
a prefix of `ghcr.io` matches images from `ghcr.io` but not from
`ghcr.io.example.com`. Each prefix must be unique across all entries.

When `mirror` is set, the plugin rewrites the image reference to pull from the
mirror registry while preserving the repository path, tag, and digest. For
example, `ghcr.io/myorg/myimage:v1.0` with mirror `mirror.internal.example.com`
becomes `mirror.internal.example.com/myorg/myimage:v1.0`.

When `ca_cert` is set, the plugin loads the PEM-encoded certificates and adds
them to the system certificate pool for connections to the matched registry. The
path must be absolute and the file must exist at startup (validated during
runtime validation).

Setting `insecure = true` disables TLS certificate verification for the matched
registry. A warning is logged at startup. This should only be used for
development and testing. In `enforce` mode, `insecure = true` is rejected
during config validation because insecure connections undermine the integrity
guarantees that enforcement provides. Use `ca_cert` instead for registries with
custom certificate authorities.

**Trust considerations for mirrors:** When configuring a mirror, be aware that
the mirror serves both images and their supply chain attestations. A compromised
or misconfigured mirror could serve valid-looking attestations for tampered
images. Ensure mirror registries are operated with the same level of trust as
the original registry. Use `ca_cert` to pin trusted CA certificates for mirrors
that use internal PKI, and avoid `insecure = true` for mirrors serving images
verified in `enforce` mode.

**Transport settings and mirrors:** The `ca_cert` and `insecure` fields on a
registry entry apply to the actual connection target. When a `mirror` is set,
that target is the mirror host, not the original registry. Configure `ca_cert`
with the mirror's CA certificate when the mirror uses internal PKI.

**Mirror fallback:** When a mirror is configured, the plugin automatically
retries requests against the original registry if the mirror is unreachable.
Fallback triggers on connection-level errors such as DNS failures, TCP
connection refused, TLS handshake errors, timeouts, and server errors (HTTP
5xx). Application-level errors (401, 403, 404) do not trigger fallback
because the mirror responded successfully at the transport layer.

## Policy Distribution

By default, policy files are read from the local `policy_dir` directory. As an
alternative, policies can be distributed as OCI artifacts stored in a container
registry. This enables centralized policy management without requiring filesystem
access on every node.

```toml
[policy]
source = "oci"
oci_ref = "ghcr.io/myorg/supply-chain-policies:v1"
poll_interval = "5m"
```

| Field                  | Default | Description                                                                                                                                             |
| ---------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `policy.source`        | `local` | Policy source: `local` (read from `policy_dir`) or `oci` (fetch from registry)                                                                          |
| `policy.oci_ref`       | (empty) | OCI image reference containing policy layers (required when source is `oci`). Using a digest reference is recommended over a mutable tag for integrity. |
| `policy.poll_interval` | `5m`    | How often to poll the OCI registry for policy updates (minimum 30s)                                                                                     |

### Policy Signature Verification

OCI-distributed policies can be signed with Sigstore to ensure only trusted
policy artifacts are loaded. When trust material (`issuers` or `keys`) is
configured, the plugin verifies that the policy artifact has a valid Sigstore
signature before extracting policies. If verification fails, the artifact is
rejected and the plugin retains the last known-good policy (or fails to start
if no policy was loaded yet).

```toml
[policy]
source = "oci"
oci_ref = "ghcr.io/myorg/supply-chain-policies:v1"
issuers = ["https://accounts.google.com"]
san_patterns = ["policy-signer@myorg.iam.gserviceaccount.com"]
# keys = ["/etc/keys/policy-signing.pub"]  # cannot be used together with issuers
```

| Field                 | Default | Description                                                                                  |
| --------------------- | ------- | -------------------------------------------------------------------------------------------- |
| `policy.issuers`      | (empty) | Trusted OIDC issuers for keyless signature verification                                      |
| `policy.san_patterns` | (empty) | Subject Alternative Name patterns to match against signing certificates (requires `issuers`) |
| `policy.keys`         | (empty) | Absolute paths to PEM-encoded public key files for key-based signature verification          |

The `issuers` and `keys` fields are mutually exclusive: set `issuers` for
keyless (OIDC-based) verification or `keys` for key-based verification, but not
both. The `san_patterns` field requires `issuers` to be set. In enforce mode,
configuring `issuers` without `san_patterns` is rejected at validation. Key
paths must be absolute.

When trust material is configured but the policy source is not `oci`, a warning
is logged but no error is returned (signature verification only applies to OCI
policies).

When `source = "oci"` is set, the `policy_dir` field is ignored for policy
loading. The plugin fetches the OCI image at startup and polls for changes at
the configured interval. Each layer in the OCI image is treated as a policy
JSON file. The filename is determined by the `org.opencontainers.image.title`
annotation on the layer descriptor. Layers whose media type is not one of the recognized policy types are skipped.
The accepted media types are: `application/vnd.nri-supply-chain.policy.v1+json`,
`application/json`, `application/vnd.oci.image.layer.v1.tar+gzip`,
`application/vnd.oci.image.layer.v1.tar`, and empty (unset).

Policy changes are detected by comparing the image manifest digest. When a new
digest is found, the plugin reloads all policies from the updated image
atomically. The verification cache is invalidated on reload to ensure the new
policies take effect immediately.

**Authentication.** The plugin authenticates to OCI registries using a
multi-keychain that chains several credential sources. Credentials are resolved
in the following order (first match wins):

1. Docker config file (`~/.docker/config.json`, or the path in the
   `DOCKER_CONFIG` environment variable)
2. Podman auth file (`$XDG_RUNTIME_DIR/containers/auth.json`)
3. Credential helpers configured in the Docker/Podman config
4. Google Cloud (GCR / Artifact Registry) application default credentials
5. AWS ECR credential helper (uses the standard AWS credential chain)
6. Azure ACR credential helper (uses the Azure SDK default credential chain:
   environment variables, workload identity, managed identity, Azure CLI)

No additional configuration is needed when the node already has registry
credentials configured for image pulls. On cloud-managed Kubernetes clusters,
the built-in cloud provider keychains authenticate automatically using the
node's service account or workload identity. The same credentials are used for
fetching images, attestations, and policy artifacts.

To build and push an OCI policy artifact, use a tool like `oras` or
`go-containerregistry` to create an image with one layer per policy file:

```console
oras push ghcr.io/myorg/supply-chain-policies:v1 \
  --artifact-type application/vnd.nri-supply-chain.policies \
  default.json:application/vnd.nri-supply-chain.policy.v1+json \
  production.json:application/vnd.nri-supply-chain.policy.v1+json
```

## Policy Files

Policy files are JSON documents in `policy_dir`. The file `default.json`
applies to all namespaces. A file named `<namespace>.json` overrides the
default for that namespace. By default this is a full replacement; set
`"inherits": true` to inherit unset fields from the default policy.

```json
{
  "trust": {
    "builders": [{ "id": "https://github.com/actions/runner", "maxLevel": 3 }],
    "verifiers": [
      {
        "id": "https://example.com/verifier",
        "keys": ["/etc/keys/verifier.pub"]
      }
    ],
    "issuers": ["https://accounts.google.com"],
    "sanPatterns": ["*@myorg.com", "https://github.com/myorg/*"],
    "sources": ["https://github.com/myorg/*"],
    "buildTypes": ["https://actions.github.io/buildtypes/workflow/v1"]
  },
  "exclude": ["test-*", "registry.k8s.io/**"],
  "slsa": {
    "missingPolicy": "deny",
    "rejectUnknownParameters": true,
    "knownParameters": ["source", "repository"]
  },
  "vex": {
    "missingPolicy": "allow",
    "underInvestigationPolicy": "allow"
  },
  "vsa": {
    "minimumLevel": 2,
    "maxAge": "24h",
    "policy": "https://example.com/policy"
  },
  "signatures": {
    "requireTransparencyLog": true
  }
}
```

When no policy file matches a container's namespace (no `<namespace>.json` and
no `default.json`), the verifier denies the container with "no policy found for
namespace and no default policy configured." In `enforce` mode, an empty policy
directory blocks all containers. Always provide at least a `default.json` when
verification is enabled. An empty policy `{}` allows all containers without
performing any verification checks.

For the complete field reference, pattern matching semantics, and scenario-based
examples, see [policy.md](policy.md).

## CLI

The binary uses subcommands. Running without a subcommand starts the NRI plugin
daemon.

```text
nri-supply-chain                         Run the NRI plugin daemon
nri-supply-chain verify <image> [...]    Verify one or more images
nri-supply-chain validate                Validate config and policies
nri-supply-chain effective-policy        Show effective policy for a namespace
nri-supply-chain inspect <image>         List attestations attached to an image
nri-supply-chain version                 Print the version
nri-supply-chain json-schema <type>      Print JSON Schema (policy, result, config)
nri-supply-chain bundle create           Create a portable attestation bundle
nri-supply-chain bundle inspect          Show bundle contents
nri-supply-chain bundle verify           Verify bundle integrity and signature
nri-supply-chain bundle import           Import a bundle into the attestation store
```

Global flags (available on all subcommands):

```text
-c, --config       Path to TOML config file (default: /etc/nri-supply-chain/config.toml)
-l, --log-level    Log level: debug, info, warn, error (default: info)
```

Plugin flags (root command only):

```text
--plugin-name      NRI plugin name (default: supply-chain)
--plugin-idx       NRI plugin index (default: 10)
```

The `validate` subcommand loads the config, parses all policy files, and runs
`ValidateRuntime()` on each policy (checking that referenced key and certificate
files exist and are readable). In enforce mode it also runs `ValidateEnforce()`
to verify that trust roots, SAN patterns, and required fields are properly
configured. Finally, it emits warnings for permissive defaults (such as
`missingPolicy=allow` or key-only verification without a transparency log).

Verify flags:

```text
-n, --namespace        Namespace for verification (default: default)
-o, --output           Output format: table, json (default: table)
-q, --quiet            Suppress all output except the exit code
-v, --verbose          Show step-by-step diagnostic output
    --preview-policy   Path to a policy JSON file for dry-run verification
```

The `--quiet` and `--output` flags are mutually exclusive.

The `--verbose` flag enables debug-level logging during verification. This shows
intermediate steps including registry connectivity, digest resolution, discovered
attestations, trust chain evaluation, and policy resolution.

To verify a single image:

```console
nri-supply-chain verify ghcr.io/myorg/myimage:v1.0
```

The default output is a colored table:

```text
Image: ghcr.io/myorg/myimage:v1.0
Digest: sha256:abc123...
Namespace: default
Policy: /etc/nri-supply-chain/policies/default.json
Mode: warn
Result: ALLOWED

TYPE   STATUS   DETAIL
SLSA   pass     SLSA level 3 verified
VEX    pass     no known vulnerabilities
```

Use `--output json` (or `-o json`) for machine-readable JSON output:

```json
{
  "image": "ghcr.io/myorg/myimage:v1.0",
  "digest": "sha256:abc123...",
  "namespace": "default",
  "allowed": true,
  "checkResults": [
    {
      "type": "slsa",
      "passed": true,
      "status": "pass",
      "detail": "..."
    },
    { "type": "vex", "passed": true, "status": "pass", "detail": "..." }
  ]
}
```

### Batch Verification

The verify command accepts multiple images as positional arguments. When more
than one image is provided, the output switches from a single JSON object to a
JSON array of results:

```console
nri-supply-chain verify alpine:latest nginx:1.25 --output json
```

```json
[
  {"image": "alpine:latest", "digest": "sha256:...", "namespace": "default", "allowed": true, "checkResults": [...]},
  {"image": "nginx:1.25", "digest": "sha256:...", "namespace": "default", "allowed": true, "checkResults": [...]}
]
```

### Exit Codes

The verify command uses distinct exit codes for CI/CD integration:

| Exit code | Meaning                                                  |
| --------- | -------------------------------------------------------- |
| 0         | Verification passed                                      |
| 1         | Verification denied (policy violation)                   |
| 2         | Internal/infrastructure error (config, network, parsing) |

When verifying multiple images, the exit code is the worst (highest) across all
images. If any image is denied (exit 1), the overall exit is 1. If any image
hits an infrastructure error (exit 2), the overall exit is 2.

Use `--quiet` in CI pipelines when only the exit code matters:

```console
nri-supply-chain verify --quiet ghcr.io/myorg/myimage:v1.0
```

### Preview

The `preview` subcommand verifies a batch of images against the current policy
set without blocking workloads. This lets operators assess the impact of policy
changes before enabling enforce mode.

```console
nri-supply-chain preview alpine:latest nginx:1.25 --output json
```

Images can also be loaded from a file (one per line, comments with `#`):

```console
nri-supply-chain preview --images-file images.txt
```

Use `--compare-policy` to diff results between two policy directories:

```console
nri-supply-chain preview --compare-policy /path/to/proposed-policies alpine:latest
```

The diff mode shows which images would change status (allowed/denied) under the
proposed policy set.

Preview flags:

```text
-n, --namespace        Namespace for policy resolution (default: default)
-o, --output           Output format: table, json (default: table)
    --images-file      File containing image references (one per line)
    --compare-policy   Path to alternative policy directory for comparison
```

### Effective Policy

The `effective-policy` subcommand shows the fully resolved policy for a given
namespace after inheritance and rule matching.

```console
nri-supply-chain effective-policy --namespace production
```

When `--image` is specified, the first matching image rule is applied on top of
the base policy:

```console
nri-supply-chain effective-policy --namespace production --image ghcr.io/org/app:latest
```

The default output is JSON containing the namespace, effective mode, policy
source ("default" or "namespace"), matched rule index (or -1 if no rule
matched), matched rule patterns, and the fully resolved policy object. Use
`--output table` for a human-readable summary.

Effective-policy flags:

```text
-n, --namespace    Namespace to resolve (default: default)
-i, --image        Image reference to match against rules
-o, --output       Output format: table, json (default: json)
```

### Inspect

The `inspect` subcommand lists all attestations attached to a container image
without running policy evaluation.

```console
nri-supply-chain inspect ghcr.io/myorg/myimage:v1.0
```

This resolves the image digest, discovers all OCI referrer attestations, and
displays their predicate types and signature types. Use `--output json` for
machine-readable output.

Inspect flags:

```text
-o, --output       Output format: table, json (default: table)
```

### JSON Schema

The full JSON Schema for the verify result can be generated via:

```console
nri-supply-chain json-schema result
```

<details>
<summary>JSON Schema output</summary>

<!-- verify-jsonschema-start -->

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/verifyOutput",
  "$defs": {
    "CheckResult": {
      "properties": {
        "type": {
          "type": "string"
        },
        "passed": {
          "type": "boolean"
        },
        "status": {
          "type": "string"
        },
        "detail": {
          "type": "string"
        },
        "metadata": {
          "type": "object"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": ["type", "passed", "status"]
    },
    "verifyOutput": {
      "properties": {
        "image": {
          "type": "string"
        },
        "digest": {
          "type": "string"
        },
        "namespace": {
          "type": "string"
        },
        "previewPolicy": {
          "type": "string"
        },
        "allowed": {
          "type": "boolean"
        },
        "reason": {
          "type": "string"
        },
        "checkResults": {
          "items": {
            "$ref": "#/$defs/CheckResult"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": ["image", "digest", "namespace", "allowed"]
    }
  },
  "title": "nri-supply-chain Verify Result",
  "description": "JSON output of the verify command."
}
```

<!-- verify-jsonschema-end -->

</details>

The config file schema is also available:

```console
nri-supply-chain json-schema config
```

### Bundle Management

The `bundle` subcommand group manages portable attestation bundles for air-gapped environments. Bundles package attestation data, trust material, and optional revocation snapshots into a tar.gz file that can be transferred to disconnected systems.

**bundle create**: Fetch attestations from OCI registries and package them into a bundle.

```console
nri-supply-chain bundle create \
  --image ghcr.io/myorg/app:v1.0 \
  --image ghcr.io/myorg/sidecar:v2.0 \
  --output bundle.tar.gz \
  --sign-key /path/to/private-key.pem
```

Create flags:

```text
    --image           Image reference to include (repeatable)
-o, --output          Output file path for the bundle tar.gz (required)
    --sign-key        Path to private key PEM for signing the bundle manifest
    --from-policy     Path to policy file to extract image references from
    --trusted-root    Path to trusted root JSON to embed in the bundle
    --revocation      Path to CRL or TSA file to embed (repeatable)
```

When `--from-policy` is specified, concrete image references from the policy's `include` and `rules[].images` fields are added to the bundle. Glob patterns are skipped. This can be combined with `--image` flags.

If `--trusted-root` is not specified, the command embeds the cached Sigstore trusted root from the warmed OCI fetcher (if available).

**bundle inspect**: Show the contents of a bundle store directory.

```console
nri-supply-chain bundle inspect /var/lib/nri-supply-chain/bundles
```

Inspect flags:

```text
-o, --output       Output format: table, json (default: table)
```

**bundle verify**: Verify the integrity, signature, and expiry of a bundle.

```console
nri-supply-chain bundle verify /var/lib/nri-supply-chain/bundles \
  --key /path/to/public-key.pem \
  --max-age 720h
```

Verify flags:

```text
    --key          Path to public key PEM for signature verification
    --max-age      Maximum acceptable bundle age (e.g. 720h, 24h)
```

Verification checks blob integrity (all referenced blobs exist and match their declared digest and size), optionally verifies the manifest signature, and checks bundle age against `--max-age` if specified.

**bundle import**: Extract a bundle tar.gz into the local attestation store.

```console
nri-supply-chain bundle import bundle.tar.gz \
  --store /var/lib/nri-supply-chain/bundles \
  --key /path/to/public-key.pem
```

Import flags:

```text
    --store        Path to the local attestation store directory (required)
    --key          Path to public key PEM for signature verification during import
```

Import always verifies blob integrity (all referenced blobs must exist and match their declared digest and size). When `--key` is specified, the manifest signature is also verified. If any check fails, the import is rolled back and the store path remains untouched.
