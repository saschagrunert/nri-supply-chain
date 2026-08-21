# Deployment

This document covers the deployment options, runtime requirements, and example
configurations for the nri-supply-chain plugin.

<!-- toc -->

- [Pre-installed NRI Plugin](#pre-installed-nri-plugin)
- [External NRI Plugin](#external-nri-plugin)
- [Kubernetes DaemonSet](#kubernetes-daemonset)
  - [Helm Chart](#helm-chart)
- [Systemd Service](#systemd-service)
- [DEB/RPM Packages](#debrpm-packages)
- [Container Image](#container-image)
- [NRI Runtime Configuration](#nri-runtime-configuration)
- [Runtime Requirements](#runtime-requirements)
- [Examples](#examples)
  - [Gradual Rollout](#gradual-rollout)
  - [Strict Production](#strict-production)
  - [VSA-Accelerated Verification](#vsa-accelerated-verification)
  - [Air-Gapped Deployment](#air-gapped-deployment)

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

The single manifest `deploy/kubernetes/daemonset.yaml` bundles a Namespace,
ServiceAccount, ConfigMap with example config and policy, NetworkPolicy,
PodDisruptionBudget, and the DaemonSet.
Edit the ConfigMap to match your environment before deploying. See
[config.md](config.md) for the full field reference.

### Helm Chart

The Helm chart provides a parameterized DaemonSet deployment:

```console
helm upgrade --install nri-supply-chain deploy/helm/nri-supply-chain \
  --namespace nri-supply-chain --create-namespace \
  --set config.verification=enforce \
  --set-file policies.default\\.json=./default.json
```

It exposes operational configuration, local or OCI policy sources, registry
mirrors, resource settings, node selectors, tolerations, NetworkPolicy, and
optional Prometheus Operator resources. See
[`deploy/helm/nri-supply-chain/README.md`](../deploy/helm/nri-supply-chain/README.md)
for the values reference and security notes.

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
ready-to-use policy files covering keyless, key-based, Notation, SBOM, SCAI,
VEX-strict, VSA-accelerated, CEL, and other scenarios.

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
  "slsa": { "missingPolicy": "warn" },
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
      {
        "id": "https://example.com/verifier",
        "keys": ["/etc/keys/verifier.pub"]
      }
    ],
    "sources": ["https://github.com/myorg/*"]
  },
  "slsa": {
    "missingPolicy": "deny",
    "rejectUnknownParameters": true
  },
  "vex": {
    "missingPolicy": "deny",
    "underInvestigationPolicy": "deny"
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
        "keys": ["/etc/keys/verifier.pub"]
      }
    ]
  },
  "slsa": { "missingPolicy": "deny" },
  "vsa": {
    "minimumLevel": 2,
    "maxAge": "12h",
    "policy": "https://example.com/strict-policy"
  }
}
```

### Air-Gapped Deployment

For fully disconnected environments (military, FedRAMP, healthcare, edge/IoT), attestation bundles provide offline supply chain verification without any registry connectivity.

**Step 1: Create a bundle on a connected system.**

On a system with registry access, create a signed bundle containing attestations for all required images:

```console
nri-supply-chain bundle create \
  --from-policy /etc/nri-supply-chain/policies/default.json \
  --image registry.example.com/extra-app:v1.0 \
  --output attestation-bundle.tar.gz \
  --sign-key /path/to/private-key.pem \
  --trusted-root /path/to/trusted-root.json
```

The `--from-policy` flag extracts concrete image references from the policy file automatically. Additional images can be added with `--image`. The `--sign-key` flag signs the bundle manifest so the air-gapped system can verify authenticity.

**Step 2: Transfer the bundle to the air-gapped system.**

Copy `attestation-bundle.tar.gz` to the disconnected environment via removable media, one-way data diode, or other approved transfer mechanism.

**Step 3: Import the bundle on the air-gapped system.**

```console
nri-supply-chain bundle import attestation-bundle.tar.gz \
  --store /var/lib/nri-supply-chain/bundles \
  --key /etc/nri-supply-chain/bundle-key.pub
```

Import always verifies blob integrity. The `--key` flag additionally verifies the bundle manifest signature.

**Step 4: Configure offline mode.**

```toml
verification = "enforce"

[offline]
mode = "offline"
attestation_store = "/var/lib/nri-supply-chain/bundles"
bundle_max_age = "720h"
bundle_expiry_policy = "deny"
require_bundle_signature = true
bundle_signature_key = "/etc/nri-supply-chain/bundle-key.pub"
```

With `mode = "offline"`, the plugin reads attestations exclusively from the bundle store. No network calls are made. If an image is not in the bundle, verification fails and the container is rejected (in enforce mode).

To update attestations, repeat the create/transfer/import cycle. The file watcher detects changes to the bundle store directory and triggers a reload automatically.
