# Configuration Reference

This document covers the operational configuration and CLI flags for the
nri-supply-chain plugin.

<!-- toc -->

- [Operational Config](#operational-config)
- [Private Sigstore Instances](#private-sigstore-instances)
- [Registries](#registries)
- [Policy Files](#policy-files)
- [CLI](#cli)
  - [Batch Verification](#batch-verification)
  - [Exit Codes](#exit-codes)

<!-- /toc -->

## Operational Config

The TOML parser uses strict mode: unknown keys cause a startup error. If the
config file contains fields that are not listed below (for example, leftover
keys from an older version or custom annotations), the plugin will refuse to
start. Remove or comment out any unrecognized keys before upgrading.

```toml
verification = "warn"
log_level = "info"
fetch_timeout = "30s"
# fetch_failure_policy = "warn"
cache_ttl = "24h"
cache_failure_ttl = "5m"
policy_dir = "/etc/nri-supply-chain/policies"
metrics_addr = "127.0.0.1:9090"
circuit_breaker_threshold = 5
circuit_breaker_cooldown = "30s"
# fetch_rate_limit = 50

# [sigstore]
# tuf_mirror = "https://tuf.internal.example.com"
# tuf_root = "/etc/sigstore/root.json"
```

| Field                       | Default                          | Description                                                                                                                                                                   |
| --------------------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `verification`              | `disabled`                       | Global mode: `disabled`, `warn` (log-only), `enforce` (reject on failure). Per-namespace overrides are set in policy files via the `mode` field (see [policy.md](policy.md)). |
| `log_level`                 | (CLI flag)                       | Log verbosity override: `debug`, `info`, `warn`, `error`                                                                                                                      |
| `fetch_timeout`             | `30s`                            | Per-request timeout for attestation fetches and digest resolution                                                                                                             |
| `fetch_failure_policy`      | `warn` (`deny` in enforce mode)  | Behavior when attestation fetch fails: `allow`, `warn`, `deny`. In enforce mode, defaults to `deny` unless explicitly set.                                                    |
| `cache_ttl`                 | `24h`                            | TTL for cached verification results (`0s` disables caching)                                                                                                                   |
| `cache_failure_ttl`         | `5m`                             | TTL for cached failure results, so transient errors retry sooner                                                                                                              |
| `policy_dir`                | `/etc/nri-supply-chain/policies` | Directory containing JSON policy files                                                                                                                                        |
| `metrics_addr`              | `127.0.0.1:9090`                 | Prometheus metrics HTTP listen address                                                                                                                                        |
| `circuit_breaker_threshold` | `5`                              | Consecutive fetch failures before a per-host circuit breaker opens                                                                                                            |
| `circuit_breaker_cooldown`  | `30s`                            | Duration the circuit breaker stays open before allowing a probe                                                                                                               |
| `fetch_rate_limit`          | `0` (unlimited)                  | Maximum registry fetch requests per second (max 10,000)                                                                                                                       |

See [operations.md](operations.md) for the metrics reference, config reload
behavior, and health/readiness probes.

## Private Sigstore Instances

By default, keyless verification uses the public Sigstore instance (public
Fulcio CA, public Rekor transparency log). Organizations running a private
Sigstore deployment can point the plugin at their internal TUF mirror:

```toml
[sigstore]
tuf_mirror = "https://tuf.internal.example.com"
tuf_root = "/etc/sigstore/root.json"
```

| Field                 | Default         | Description                                               |
| --------------------- | --------------- | --------------------------------------------------------- |
| `sigstore.tuf_mirror` | (empty, public) | URL of a custom TUF mirror for the Sigstore trusted root  |
| `sigstore.tuf_root`   | (empty)         | Path to a custom TUF root.json for private root key trust |

The trusted root fetched from the custom TUF mirror contains the Fulcio CA
certificates and Rekor transparency log keys for the private deployment.

There are two usage patterns:

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

The `tuf_mirror` URL must use the `http` or `https` scheme. Reachability is
not validated at config load time; a failure to reach the mirror is handled at
verification time through the normal fetch failure policy. The plugin does not
fall back to the public Sigstore instance when a configured mirror is
unreachable.

When `tuf_mirror` or `tuf_root` is changed via config reload, the plugin
creates a new fetcher with the updated settings and invalidates the
verification cache. Changes to the file content at the same `tuf_root` path
are not detected; update the config value to force a re-read.

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
development and testing. When running in `enforce` mode, an additional warning
is emitted because insecure connections undermine the integrity guarantees that
enforcement provides.

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
    "sources": ["github.com/myorg/*"],
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
nri-supply-chain version                 Print the version
nri-supply-chain json-schema <type>      Print JSON Schema (policy, result)
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

Verify flags:

```text
-n, --namespace    Namespace for verification (default: default)
-o, --output       Output format: table, json (default: table)
```

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

The full JSON Schema for this output can be generated via:

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
