# Configuration Reference

This document covers the operational configuration and CLI flags for the
nri-supply-chain plugin.

<!-- toc -->

- [Operational Config](#operational-config)
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
```

| Field                       | Default                          | Description                                                        |
| --------------------------- | -------------------------------- | ------------------------------------------------------------------ |
| `verification`              | `disabled`                       | Mode: `disabled`, `warn` (log-only), `enforce` (reject on failure) |
| `log_level`                 | (CLI flag)                       | Log verbosity override: `debug`, `info`, `warn`, `error`           |
| `fetch_timeout`             | `30s`                            | Per-request timeout for attestation fetches and digest resolution  |
| `fetch_failure_policy`      | `warn`                           | Behavior when attestation fetch fails: `allow`, `warn`, `deny`     |
| `cache_ttl`                 | `24h`                            | TTL for cached verification results (`0s` disables caching)        |
| `cache_failure_ttl`         | `5m`                             | TTL for cached failure results, so transient errors retry sooner   |
| `policy_dir`                | `/etc/nri-supply-chain/policies` | Directory containing JSON policy files                             |
| `metrics_addr`              | `127.0.0.1:9090`                 | Prometheus metrics HTTP listen address                             |
| `circuit_breaker_threshold` | `5`                              | Consecutive fetch failures before a per-host circuit breaker opens |
| `circuit_breaker_cooldown`  | `30s`                            | Duration the circuit breaker stays open before allowing a probe    |
| `fetch_rate_limit`          | `0` (unlimited)                  | Maximum registry fetch requests per second                         |

See [operations.md](operations.md) for the metrics reference, config reload
behavior, and health/readiness probes.

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
  "exclude": ["test-*", "dev-*"],
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
```

To verify a single image without running the plugin (requires `--config` with
verification enabled):

```console
nri-supply-chain --config config.toml --verify-image ghcr.io/myorg/myimage:v1.0
```

The output is JSON with per-check details:

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
