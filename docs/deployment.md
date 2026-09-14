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
- [Failing Closed](#failing-closed)
- [Bootstrapping and System Components](#bootstrapping-and-system-components)
- [Sizing](#sizing)
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

The runtime starts the plugin and passes the plugin name and index from the
filename via the `NRI_PLUGIN_NAME` and `NRI_PLUGIN_IDX` environment variables.
When they are set, the `--plugin-name` and `--plugin-idx` flags are ignored.
The runtime owns the connection of a pre-installed plugin, so the plugin exits
with code 2 when that connection is lost instead of reconnecting.
When `--config` is not set and `/etc/nri-supply-chain/config.toml` does not
exist, or when `--config ""` is passed, the plugin starts from the built-in
defaults (verification disabled) and applies the configuration the runtime
passes inline (see [NRI Runtime Configuration](#nri-runtime-configuration)).

A pre-installed plugin is started by the runtime itself, so it does not depend
on the Kubernetes control plane or the pod network. It is still subject to the
fail-open defaults described in [Failing Closed](#failing-closed).

## External NRI Plugin

Run as a standalone process that connects to the NRI socket
(`/var/run/nri/nri.sock` unless `--nri-socket` is set):

```console
./nri-supply-chain --config /etc/nri-supply-chain/config.toml
```

When the connection to the runtime is lost (for example while the runtime
restarts), the plugin keeps its caches, reports not ready on `/readyz`, sets
`nri_supply_chain_nri_connected` to `0`, and reconnects with exponential
backoff (1s up to 30s). While the NRI socket is missing (the runtime is down),
the plugin reconnects as soon as the socket reappears instead of waiting for
the backoff. A connection attempt that the runtime does not configure within
30s (for example because the connection dropped right after registration) is
abandoned and retried; a late `Configure` of an abandoned attempt is rejected.
The NRI stub keeps a blocked goroutine for every abandoned attempt, so after 10
abandoned attempts the plugin exits with code 2 and is restarted instead of
leaking. When the connection stays down longer than `--nri-disconnect-timeout`
(default `5m`, `0` disables the check) while the NRI socket exists, `/healthz`
fails so that a liveness probe restarts a stuck plugin. While the socket is
missing, `/healthz` keeps succeeding: restarting the plugin cannot help while
the runtime is down and would only add a crash-loop backoff for when it comes
back. `SIGTERM` and `SIGINT` stop the plugin with exit code 0; startup and
runtime errors exit with code 2.

The metrics and health server is independent of admission: when its address is
already in use, the plugin logs an error, keeps verifying containers, and
retries binding with backoff (1s up to 1m). `--health-addr` serves `/healthz`,
`/readyz` and `/status` on a separate address (the shipped manifests use
`:9091`), so a metrics port conflict does not fail the probes and restart the
pod. With host networking, choose ports that no host service uses (`9090` is
also the default of Prometheus and Cockpit).

## Kubernetes DaemonSet

Deploy as a DaemonSet to run the plugin on every node in the cluster:

```console
kubectl apply -f deploy/kubernetes/daemonset.yaml
```

The single manifest [`deploy/kubernetes/daemonset.yaml`](../deploy/kubernetes/daemonset.yaml) bundles a Namespace,
ServiceAccount, ConfigMap with example config and policy, and the DaemonSet.
Edit the ConfigMap to match your environment before deploying. See
[config.md](config.md) for the full field reference.

The DaemonSet is configured as follows:

- **Runs as UID 0 without capabilities.** The runtime creates the NRI socket
  owned by root and not accessible to other users, so the container runs as
  UID 0. All capabilities are dropped,
  privilege escalation is disabled, the root filesystem is read-only, and the
  `RuntimeDefault` seccomp profile applies. Without `CAP_DAC_OVERRIDE`, root in
  the container cannot bypass file permissions. Writable `emptyDir` volumes
  back `HOME` (the Sigstore TUF cache) and `/tmp`.
- **Uses the host network.** The plugin must reach registries while CNI pods
  are created, before the pod network exists on the node (see
  [Bootstrapping and System Components](#bootstrapping-and-system-components)).
  `dnsPolicy: Default` resolves registry names through the node's resolver,
  which works before cluster DNS is running. Use `ClusterFirstWithHostNet` if
  the plugin must resolve in-cluster services, for example an in-cluster
  registry or GUAC endpoint. NetworkPolicies do not apply to host network pods,
  so the manifest ships none. The metrics port (`9090`) and the health port
  (`9091`) listen on every node address; restrict them with host firewall
  rules. To run on the pod network instead, remove `hostNetwork` and
  `dnsPolicy` and add a NetworkPolicy (the
  Helm chart renders one when `daemonSet.hostNetwork=false`), accepting that
  the plugin then depends on the CNI plugin being ready.
- **Namespace Pod Security level `privileged`.** The `hostPath` mount and the
  host network are not allowed by the `baseline` and `restricted` levels.
- **`system-node-critical` priority, all tolerations, Linux nodes only.**
- **No CPU limit.** See [Sizing](#sizing).
- **No PodDisruptionBudget.** Node drains skip DaemonSet pods and DaemonSet
  rolling updates do not consult PodDisruptionBudgets, so a budget would not
  protect the plugin.

The ConfigMap is mounted as two directories, `/etc/nri-supply-chain/config`
(the `config.toml` key) and `/etc/nri-supply-chain/policies` (the policy
keys), without `subPath`. The kubelet propagates ConfigMap edits into the pod
within its sync period and the plugin reloads them automatically, so no
restart is needed. Symlinks created by the kubelet are followed only while they
resolve inside the mounted directory.

Pin the image by digest in production and verify it before deploying, see
[Verifying Releases](../README.md#verifying-releases).

For Prometheus Operator monitoring (ServiceMonitor, PrometheusRule, and a
headless metrics Service), also apply the monitoring manifest:

```console
kubectl apply -f deploy/kubernetes/monitoring.yaml
```

A pre-built Grafana dashboard is available at
[`deploy/grafana/dashboard.json`](../deploy/grafana/dashboard.json). Import it
into Grafana or provision it via a ConfigMap with the `grafana_dashboard: "1"`
label.

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
optional Prometheus Operator resources. The chart renders the same hardened
DaemonSet and default policy as the raw manifest (`make verify-manifests`
checks for drift). Set `image.digest` to pin the image by digest. With
`--create-namespace`, Helm creates the namespace without Pod Security labels.
If your cluster enforces a stricter default level, create and label the
namespace first:

```console
kubectl create namespace nri-supply-chain
kubectl label namespace nri-supply-chain pod-security.kubernetes.io/enforce=privileged
```

The ConfigMap is mounted as directories, so the plugin reloads configuration
and policy changes from `helm upgrade` without a restart. Pods are not rolled
on configuration changes by default, because every rollout briefly leaves the
node without the plugin. Set `daemonSet.restartOnConfigChange=true` to add the
`checksum/config` pod annotation and roll the DaemonSet on each change
instead. See
[`deploy/helm/nri-supply-chain/README.md`](../deploy/helm/nri-supply-chain/README.md)
for the values reference and security notes.

## Systemd Service

A systemd unit file is provided at [`deploy/systemd/nri-supply-chain.service`](../deploy/systemd/nri-supply-chain.service).
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
- **`latest`** is built on every merge to main and tagged only after the image
  was scanned, attested, and verified by the release workflow

```console
docker pull ghcr.io/saschagrunert/nri-supply-chain:latest
```

GitHub releases also include Kubernetes manifests, systemd service files, and
example configurations as downloadable assets.

## NRI Runtime Configuration

When the plugin runs without a config file (`--config ""`, or no `--config`
and no default config file), the container runtime can pass the configuration
inline via the NRI `Configure` callback, for example through CRI-O's NRI plugin
config or containerd's NRI host configuration. The plugin parses the string as
TOML with the same keys as the config file and applies it like a config file
reload: the verifier and its policies, registries and their credentials,
`fetch_timeout`, `digest_resolve_timeout`, `log_level`, and the remediation
settings (the continuous verifier starts when remediation is enabled).
`metrics_addr` only takes effect at startup, and without a config file there is
no SIGHUP or file-watch reload: a changed inline configuration is applied when
the runtime passes it again on the next connection. If the `--config` flag
points to a file, the inline configuration is ignored.

Parsing and runtime validation errors fail `Configure`. The rest (creating the
attestation fetcher, loading or fetching policies) can take longer than the
runtime's request deadline, so it runs in the background: `Configure` returns
promptly and `/readyz` reports not ready until the configuration is applied
(or with the reason when applying it failed). While an inline configuration is
not applied, the previous configuration (by default verification disabled)
would admit every container, so the plugin rejects containers in every
namespace the new configuration enforces: all namespaces with
`verification = "enforce"`, and with `verification = "warn"` the namespaces
whose local policy (or `default.json`) sets `"mode": "enforce"`. Local
policies are read synchronously in `Configure` for this; OCI policies can
only be inspected after they are fetched, so a pending `warn` configuration
with `policy.source = "oci"` rejects containers in every namespace, as does a
local policy directory that fails to load.

A failed apply is retried in the background with exponential backoff (1s up
to 1m) until it succeeds or the runtime passes a different configuration.
While it fails, `nri_supply_chain_runtime_config_apply_failed` is `1` and
`/readyz` reports the last error; `/healthz` is not affected, so the kubelet
does not restart the plugin. When the runtime passes the same configuration
again on a reconnect, the plugin keeps the applied configuration and its state
instead of applying it again.

## Runtime Requirements

- CRI-O with NRI enabled (`enable_nri = true` in CRI-O config), or
  containerd v2 (NRI is enabled by default; v1.7+ requires explicit NRI
  configuration).
- NRI socket at `/var/run/nri/nri.sock` (for external plugins).
- Registry access from the node to fetch OCI Referrers and to resolve image
  digests (required on containerd where NRI annotations may omit the digest).
- For fail-closed enforcement: NRI validation support (containerd 2.2+ or
  CRI-O 1.34+), see [Failing Closed](#failing-closed).

## Failing Closed

By default, NRI runtimes create containers without the plugin's verdict in
these situations, even in `enforce` mode:

| Situation                                                                                   | Runtime behavior                                                                                                                                                    |
| ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Plugin not registered (not started yet, crashed, OOM killed, restarting, DaemonSet rollout) | Containers are created without calling the plugin.                                                                                                                  |
| Plugin does not answer within the NRI request timeout (default `2s`)                        | The runtime treats the timeout as fatal, closes the connection to the plugin, and creates the container. Later containers skip the plugin until it registers again. |

Two settings close these gaps. Both are needed for `enforce` mode.

**1. Keep the plugin below the request timeout.** `admission_timeout` (default
`1500ms`) bounds the whole `CreateContainer` hook. When it expires in `enforce`
mode, the plugin rejects the container and the kubelet retries the creation
with backoff. Keep `admission_timeout`
below the runtime's request timeout, with enough margin for scheduling delays
on a busy node. If you raise the runtime timeout, raise `admission_timeout`
with it, but keep in mind that the runtime serializes NRI requests per node, so
a slow plugin delays every container creation on that node:

```toml
# containerd (config.toml, version 3)
[plugins."io.containerd.nri.v1.nri"]
  plugin_request_timeout = "2s"
```

```toml
# CRI-O (crio.conf or a drop-in in /etc/crio/crio.conf.d/)
[crio.nri]
nri_plugin_request_timeout = "2s"
```

**2. Require the plugin.** The NRI default validator rejects containers when a
required plugin is not registered. The plugin registers under the name
`supply-chain` by default (`--plugin-name`):

```toml
# containerd 2.2+ (config.toml, version 3)
[plugins."io.containerd.nri.v1.nri".default_validator]
  enable = true
  required_plugins = ["supply-chain"]
  tolerate_missing_plugins_annotation = "tolerate-missing-nri-plugins.noderesource.dev"
```

```toml
# CRI-O 1.34+
[crio.nri.default_validator]
nri_enable_default_validator = true
nri_validator_required_plugins = ["supply-chain"]
nri_validator_tolerate_missing_plugins_annotation = "tolerate-missing-nri-plugins.noderesource.dev"
```

The validator only checks that the plugin is registered. A request that times
out is still counted as handled by the plugin, which is why the
`admission_timeout` from step 1 is required as well.

A globally required plugin also blocks every container that has to start
before the plugin, including the plugin's own pod. Pods annotated with the
configured toleration annotation are exempt from the check (but not from
verification when the plugin is running):

- The shipped DaemonSet and Helm chart set
  `tolerate-missing-nri-plugins.noderesource.dev: "true"` on the plugin pod.
- Static pods (kube-apiserver, etcd, and so on) must carry the annotation in
  their manifests on the node.
- CNI and kube-proxy pods need the annotation when they must start before the
  plugin, see
  [Bootstrapping and System Components](#bootstrapping-and-system-components).

Pod annotations are set by whoever creates the pod. NRI also honors the
annotation in its `<key>/pod` and `<key>/container.<name>` forms, so restrict
every key equal to the toleration key or starting with it followed by `/` to
the namespaces that need it, for example with a ValidatingAdmissionPolicy
(Kubernetes 1.30+):

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: restrict-nri-toleration
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  validations:
    - expression: >-
        !has(object.metadata.annotations) ||
        object.metadata.annotations.all(key,
          key != 'tolerate-missing-nri-plugins.noderesource.dev' &&
          !key.startsWith('tolerate-missing-nri-plugins.noderesource.dev/'))
      message: tolerate-missing-nri-plugins.noderesource.dev is reserved for system namespaces
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: restrict-nri-toleration
spec:
  policyName: restrict-nri-toleration
  validationActions: [Deny]
  matchResources:
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: [kube-system, nri-supply-chain]
```

The plugin exposes `nri_supply_chain_nri_connected` and the monitoring
manifests alert when it is `0` or when the plugin is down, see
[operations.md](operations.md#monitoring-and-alerting). When the NRI connection
is lost, the plugin reconnects instead of exiting.

## Bootstrapping and System Components

On a node that boots or joins the cluster, containers start in this order:

1. Static pods (control plane nodes) and the container runtime.
2. The CNI plugin pods (host network), kube-proxy, and the nri-supply-chain
   DaemonSet pod (host network).
3. Cluster DNS and all other pods, once the pod network is ready.

Keep the plugin independent of anything that starts after it:

- **Host network.** The plugin uses the host network so it can reach registries
  before the CNI plugin is running. On the pod network, the plugin pod cannot
  start before the CNI plugin, so CNI pods are created while the plugin is
  absent (fail open) or, with a required plugin, never (deadlock).
- **Node DNS.** `dnsPolicy: Default` avoids a dependency on cluster DNS.
- **System image excludes.** The shipped default policy excludes
  `registry.k8s.io/**` (kube-proxy, CoreDNS, CSI sidecars) so these
  do not depend on attestations that upstream images usually lack. Add your
  CNI and other node-critical images, and pin them by digest where your
  tooling allows it, for example
  `quay.io/cilium/cilium:v1.18.0@sha256:<digest>`. Excluded images are not
  verified, so keep the list minimal.
- **Toleration annotations.** With a required plugin, annotate static pods and
  every component that must start before the plugin with the toleration
  annotation (see [Failing Closed](#failing-closed)).
- **The plugin's own image.** The plugin pod starts while no plugin instance is
  registered on the node, so its own image is never verified by the plugin.
  Pin it by digest (`image.digest` in the Helm chart) and verify it out of band
  with cosign before rolling it out, see
  [Verifying Releases](../README.md#verifying-releases).

## Sizing

The shipped manifests request `100m` CPU and `128Mi` memory and limit memory to
`512Mi`. They set no CPU limit: CFS throttling delays `CreateContainer`
responses, and a response later than the runtime's NRI request timeout lets
the container start unverified (see [Failing Closed](#failing-closed)).

Memory grows with the number of distinct images on the node (cache pre-warming
runs up to 5 concurrent fetches) and with the attestation size limits
(`max_attestation_size`, 10 MiB per attestation by default, 50 MiB per image).
Raise the limit on nodes with many images or large SBOMs, and watch the
container's memory usage and the `nri_supply_chain_create_container_duration_seconds`
histogram after changes. An OOM-killed plugin is a fail-open window unless the
plugin is required by the runtime.

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
  --output-file attestation-bundle.tar.gz \
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
