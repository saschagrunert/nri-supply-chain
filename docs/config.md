# Configuration Reference

This document covers the operational configuration and CLI flags for the
nri-supply-chain plugin.

<!-- toc -->

- [Operational Config](#operational-config)
- [Private Sigstore Instances](#private-sigstore-instances)
- [Policy Files](#policy-files)
- [CLI Flags](#cli-flags)

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
fetch_failure_policy = "warn"
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
| `fetch_failure_policy`      | `warn`                           | Behavior when attestation fetch fails: `allow`, `warn`, `deny`                                                                                                                |
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
      { "id": "https://example.com/verifier", "key": "/etc/keys/verifier.pub" }
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

## CLI Flags

```text
--config              Path to TOML config file
--metrics-addr        Metrics HTTP listen address (overrides config)
--plugin-name         NRI plugin name (default: supply-chain)
--plugin-idx          NRI plugin index (default: 10)
--log-level           Log level: debug, info, warn, error (default: info)
--version             Print version and exit
--validate            Validate config and policies, then exit
--verify-image        Verify a specific image and exit (requires --config)
--verify-namespace    Namespace for verification (default: default)
--output              Output format for --verify-image: table, json (default: table)
--json-schema         Print JSON Schema and exit (policy, result)
```

To verify a single image without running the plugin (requires `--config` with
verification enabled):

```console
nri-supply-chain --config config.toml --verify-image ghcr.io/myorg/myimage:v1.0
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

Use `--output json` for machine-readable JSON output:

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

The `--verify-image` command uses distinct exit codes for CI/CD integration:

| Exit code | Meaning                                                  |
| --------- | -------------------------------------------------------- |
| 0         | Verification passed                                      |
| 1         | Verification denied (policy violation)                   |
| 2         | Internal/infrastructure error (config, network, parsing) |

The full JSON Schema for this output can be generated via:

```console
nri-supply-chain --json-schema result
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
  "description": "JSON output of the --verify-image command."
}
```

<!-- verify-jsonschema-end -->

</details>
