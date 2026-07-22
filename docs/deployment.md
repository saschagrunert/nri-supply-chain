# Deployment

This document covers the deployment options, runtime requirements, and example
configurations for the nri-supply-chain plugin.

<!-- toc -->

- [Pre-installed NRI Plugin](#pre-installed-nri-plugin)
- [External NRI Plugin](#external-nri-plugin)
- [Kubernetes DaemonSet](#kubernetes-daemonset)
- [Systemd Service](#systemd-service)
- [DEB/RPM Packages](#debrpm-packages)
- [Container Image](#container-image)
- [NRI Runtime Configuration](#nri-runtime-configuration)
- [Runtime Requirements](#runtime-requirements)
- [Examples](#examples)
  - [Gradual Rollout](#gradual-rollout)
  - [Strict Production](#strict-production)
  - [VSA-Accelerated Verification](#vsa-accelerated-verification)

<!-- /toc -->

## Pre-installed NRI Plugin

Copy the binary to the NRI plugin directory. The filename encodes the plugin
index and name:

```console
cp build/nri-supply-chain /opt/nri/plugins/10-supply-chain
```

The runtime invokes the plugin automatically on container creation.

## External NRI Plugin

Run as a standalone process that connects to the NRI socket:

```console
./nri-supply-chain --config /etc/nri-supply-chain/config.toml
```

## Kubernetes DaemonSet

Deploy as a DaemonSet to run the plugin on every node in the cluster:

```console
kubectl apply -f deploy/kubernetes/
```

The manifests in `deploy/kubernetes/` include a Namespace, ServiceAccount,
ConfigMap with example config and policy, NetworkPolicy, and the DaemonSet.
Edit the ConfigMap to match your environment before deploying. See
[config.md](config.md) for the full field reference.

## Systemd Service

A systemd unit file is provided at `deploy/systemd/nri-supply-chain.service`.
Install it and enable the service:

```console
cp deploy/systemd/nri-supply-chain.service /usr/lib/systemd/system/
systemctl daemon-reload
systemctl enable --now nri-supply-chain
```

Reload configuration without restarting (see
[operations.md](operations.md#config-reload) for reload behavior details):

```console
systemctl reload nri-supply-chain
```

## DEB/RPM Packages

Release builds include `.deb` and `.rpm` packages that install the binary,
systemd unit, and example configuration. Install with your package manager:

```console
# Debian/Ubuntu
sudo dpkg -i nri-supply-chain_*.deb

# RHEL/Fedora
sudo rpm -i nri-supply-chain-*.rpm
```

The packages enable the systemd service on install and stop it on removal.

## Container Image

Multi-arch container images (amd64, arm64) are published to
`ghcr.io/saschagrunert/nri-supply-chain`. Images are signed with cosign and
built on distroless for a minimal attack surface.

- **Tagged releases** (`v1.0.0`, etc.) are published by the release workflow
- **`latest`** is automatically built and pushed on every merge to main

```console
docker pull ghcr.io/saschagrunert/nri-supply-chain:latest
```

GitHub releases also include Kubernetes manifests, systemd service files, and
example configurations as downloadable assets.

## NRI Runtime Configuration

When the plugin is deployed as a pre-installed NRI plugin (without the
`--config` flag), the container runtime can pass configuration inline via the
NRI `Configure` callback. The plugin parses this string as TOML using the same
format as the config file. This allows the runtime to manage plugin
configuration directly, for example through CRI-O's NRI plugin config or
containerd's NRI host configuration. If the `--config` flag is provided, the
inline NRI configuration is ignored.

## Runtime Requirements

- CRI-O with NRI enabled (`enable_nri = true` in CRI-O config), or
  containerd v2 (NRI is enabled by default; v1.7+ requires explicit NRI
  configuration).
- NRI socket at `/var/run/nri/nri.sock` (for external plugins).
- Registry access from the node to fetch OCI Referrers and to resolve image
  digests (required on containerd where NRI annotations may omit the digest).

## Examples

See [`deploy/examples/policies/`](../deploy/examples/policies/) for
ready-to-use policy files covering keyless, key-based, VEX-strict,
VSA-accelerated, and other scenarios.

### Gradual Rollout

Start with `warn` mode and permissive policies to observe what would be
blocked, then switch to `enforce` once the supply chain is fully attested.

```toml
verification = "warn"
fetch_failure_policy = "allow"
policy_dir = "/etc/nri-supply-chain/policies"
```

```json
{
  "provenance": { "missingPolicy": "warn" },
  "vex": { "missingPolicy": "allow" }
}
```

### Strict Production

Enforce all verification with trusted builders only, deny on missing
attestations.

```toml
verification = "enforce"
fetch_failure_policy = "deny"
policy_dir = "/etc/nri-supply-chain/policies"
```

```json
{
  "trust": {
    "builders": [{ "id": "https://github.com/actions/runner", "maxLevel": 3 }],
    "verifiers": [
      { "id": "https://example.com/verifier", "key": "/etc/keys/verifier.pub" }
    ],
    "sources": ["github.com/myorg/*"]
  },
  "provenance": {
    "missingPolicy": "deny",
    "rejectUnknownParameters": true
  },
  "vex": {
    "missingPolicy": "deny"
  },
  "vsa": {
    "minimumLevel": 2,
    "maxAge": "24h"
  },
  "signatures": {
    "requireTransparencyLog": true
  }
}
```

### VSA-Accelerated Verification

Use VSA from a trusted verifier to skip per-image SLSA/VEX checks. This
reduces verification latency to a single VSA lookup when the verifier has
already attested the image.

```json
{
  "trust": {
    "builders": [{ "id": "https://github.com/actions/runner", "maxLevel": 3 }],
    "verifiers": [
      {
        "id": "https://verifier.internal/prod",
        "key": "/etc/keys/verifier.pub"
      }
    ]
  },
  "provenance": { "missingPolicy": "deny" },
  "vsa": {
    "minimumLevel": 2,
    "maxAge": "12h",
    "policy": "https://example.com/strict-policy"
  }
}
```
