# nri-supply-chain

[![ci](https://github.com/saschagrunert/nri-supply-chain/actions/workflows/ci.yml/badge.svg)](https://github.com/saschagrunert/nri-supply-chain/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/saschagrunert/nri-supply-chain/graph/badge.svg)](https://codecov.io/gh/saschagrunert/nri-supply-chain)
[![Go Reference](https://pkg.go.dev/badge/github.com/saschagrunert/nri-supply-chain.svg)](https://pkg.go.dev/github.com/saschagrunert/nri-supply-chain)

An [NRI](https://github.com/containerd/nri) plugin for supply chain attestation
verification. It intercepts container creation events on
[CRI-O](https://cri-o.io) or [containerd](https://containerd.io) and verifies
SLSA provenance, VEX, VSA, and signatures before a container is allowed to run.

## How It Works

The plugin registers with the container runtime via the Node Resource Interface
(NRI). When a new container is created, the plugin:

1. Extracts the image reference and digest from CRI-O container annotations
2. Looks up the per-namespace policy (or falls back to `default.json`)
3. Verifies attestations against the policy (SLSA provenance, VEX, VSA,
   signatures)
4. In `enforce` mode, rejects the container if verification fails
5. In `warn` mode, logs the failure but allows the container

## Installation

### Build from source

```console
make build
```

The binary is placed at `build/nri-supply-chain`.

### Pre-installed NRI plugin

Copy the binary to the NRI plugin directory:

```console
cp build/nri-supply-chain /opt/nri/plugins/10-supply-chain
```

### External NRI plugin

Run the binary directly and it connects to the NRI socket:

```console
./nri-supply-chain --config /etc/nri-supply-chain/config.toml
```

## Configuration

The plugin uses two layers of configuration:

- **Operational config** (TOML): controls the plugin's behavior (verification
  mode, timeouts, cache, metrics)
- **Policy files** (JSON): define per-namespace trust and verification
  requirements

### Operational Config

See [`examples/config.toml`](examples/config.toml) for a complete example.

```toml
verification = "warn"
fetch_timeout = "30s"
fetch_failure_policy = "warn"
cache_ttl = "24h"
policy_dir = "/etc/nri-supply-chain/policies"
metrics_addr = ":9090"
```

| Field | Default | Description |
|---|---|---|
| `verification` | `disabled` | `disabled`, `warn` (log-only), `enforce` (reject) |
| `fetch_timeout` | `30s` | Per-fetch timeout for retrieving attestations |
| `fetch_failure_policy` | `warn` | Behavior on network errors: `allow`, `warn`, `deny` |
| `cache_ttl` | `24h` | TTL for cached verification results (`0s` to disable) |
| `policy_dir` | `/etc/nri-supply-chain/policies` | Directory containing JSON policy files |
| `metrics_addr` | `:9090` | Prometheus metrics HTTP listen address |

### Policy Files

Policy files are JSON documents placed in `policy_dir`. The file
`default.json` applies to all namespaces. A file named `<namespace>.json`
overrides the default for that namespace.

See [`examples/policies/`](examples/policies/) for sample policies.

```json
{
  "trust": {
    "builders": [
      {"id": "https://github.com/actions/runner", "maxLevel": 3}
    ],
    "verifiers": [
      {"id": "sigstore", "key": "/etc/keys/cosign.pub"}
    ]
  },
  "provenance": {
    "missingPolicy": "deny"
  },
  "vex": {
    "severityThreshold": "high",
    "missingPolicy": "warn"
  }
}
```

## CLI Flags

```
--config         Path to TOML config file
--metrics-addr   Metrics HTTP listen address (overrides config)
--plugin-name    NRI plugin name (default: supply-chain)
--plugin-idx     NRI plugin index (default: 10)
--log-level      Log level: debug, info, warn, error (default: info)
--version        Print version and exit
```

## Metrics

The plugin exposes Prometheus metrics at the configured address:

| Metric | Type | Labels | Description |
|---|---|---|---|
| `nri_supply_chain_verification_total` | Counter | `type`, `result` | Total verification attempts |
| `nri_supply_chain_verification_duration_seconds` | Histogram | `type` | Verification latency |
| `nri_supply_chain_cache_hits_total` | Counter | | Cache hits |
| `nri_supply_chain_cache_misses_total` | Counter | | Cache misses |
| `nri_supply_chain_fetch_errors_total` | Counter | `type` | Attestation fetch errors |

## Config Reload

Send `SIGHUP` to reload the config file and policies without restarting:

```console
kill -HUP $(pidof nri-supply-chain)
```

## Runtime Requirements

- CRI-O or containerd with NRI enabled (`enable_nri = true` in CRI-O config)
- NRI socket at `/var/run/nri/nri.sock` (for external plugins)

## Development

```console
make help        # Show all targets
make build       # Build the binary
make test        # Run unit tests with coverage
make lint        # Run golangci-lint
make integration # Run bats integration tests
make snapshot    # Run goreleaser snapshot build
make govulncheck # Run vulnerability scanner
make tidy        # Run go mod tidy
make clean       # Remove build artifacts
```

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
