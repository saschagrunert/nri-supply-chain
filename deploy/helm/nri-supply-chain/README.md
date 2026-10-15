# nri-supply-chain

Helm deployment for the NRI Supply Chain Plugin. It deploys a hardened DaemonSet
that connects to the host NRI socket and verifies container-image attestations.

## Prerequisites

- Kubernetes 1.26+
- NRI enabled in CRI-O or containerd, with its socket at `/var/run/nri`
- Helm 3 or 4

## Install

The chart installs into the release namespace, or into `namespaceOverride`
when set. Create that namespace with the `privileged` Pod Security level
yourself, as below, or set `namespace.create=true` to let the chart create it
with these labels.

Create a values file containing your policy. The default policy deliberately
contains `myorg` placeholders and is suitable only as a starting point.

```console
kubectl create namespace nri-supply-chain
kubectl label namespace nri-supply-chain pod-security.kubernetes.io/enforce=privileged
helm upgrade --install nri-supply-chain deploy/helm/nri-supply-chain \
  --namespace nri-supply-chain \
  --set image.digest=sha256:<verified digest> \
  --set config.verification=enforce \
  --set-file policies.default\\.json=./default.json
```

Before enabling `enforce` mode, configure the container runtime to require the
plugin and keep `config.admissionTimeout` below the runtime's NRI request
timeout, otherwise containers are created without verification while the
plugin is unavailable or slow. See the repository's
[`docs/deployment.md`](../../../docs/deployment.md#failing-closed).

Render without installing:

```console
helm template nri-supply-chain deploy/helm/nri-supply-chain \
  --namespace nri-supply-chain
```

## Policies and configuration

`policies` is a map of `<namespace>.json` policy files, where the namespace is
a lowercase RFC 1123 label. The values schema rejects other keys. `default.json`
is required for local policy mode. Set `config.policy.source=oci` and
`config.policy.ociRef` for OCI-distributed policies; local policy entries are
then not used by the plugin, and an empty `policies` map mounts an empty
policy directory.

The plugin reloads configuration and policy changes from the mounted ConfigMap
without a restart, so pods are not rolled when they change. Set
`daemonSet.restartOnConfigChange=true` to roll the DaemonSet on every
configuration change instead. `daemonSet.terminationGracePeriodSeconds`
(default `45`, at least `40`) leaves room for the plugin's 30s bound on
in-flight verifications at shutdown.

`config` exposes the common operational settings: timeouts, cache limits,
registry mirrors, Sigstore roots, GUAC, and the policy source.
`config.allowlistDigests` bypasses verification for explicitly trusted digests.
Every other setting goes into `config.extraConfig`, which is inserted into
`config.toml` verbatim. It is rendered before any TOML table the chart
generates, so top-level keys work; place them before any table inside
`extraConfig`. Settings that are only available this way include
`check_timeout`, `audit_log`, and the `[offline]` and `[remediation]` tables:

```yaml
config:
  extraConfig: |
    check_timeout = "10s"
    audit_log = "/var/log/nri-supply-chain/audit.json"

    [remediation]
    mode = "warn"
```

An `audit_log` path must be writable: mount a volume there with
`extraVolumes` and `extraVolumeMounts`, since the root filesystem is
read-only. The chart's remediation alerts only fire with remediation enabled.
For policy and config semantics, see the repository's
[`docs/config.md`](../../../docs/config.md).

Private Sigstore roots and custom registry CAs should be supplied through a
Secret or ConfigMap using `extraVolumes` and `extraVolumeMounts`, then referred
to by their absolute mounted paths in `config.sigstore.roots` or
`config.registries`. Set `config.sigstore.enabled=true` when configuring
custom roots or an explicit `includePublicRoot` value.

## Networking

`daemonSet.hostNetwork` defaults to `true` so the plugin can reach registries
before the CNI plugin runs on the node, and `daemonSet.dnsPolicy` defaults to
`Default` so registry names resolve without cluster DNS. NetworkPolicies do not
apply to host network pods, so the chart only renders its NetworkPolicy when
`daemonSet.hostNetwork=false`. With host networking, the metrics and health
ports listen on every node address; restrict them with host firewall rules,
and pick a `config.metricsAddr` port and a `probes.port` (default `9091`) that
no host service uses (`9090` is also the default of Prometheus and Cockpit).
The probes use the dedicated health port, so a metrics port conflict does not
fail them or restart the pod; a conflict on either port does not affect
admission, and the plugin retries binding it. A conflict on the health port
fails the probes, and the kubelet restarts the pod.

## Monitoring

The chart creates a metrics Service by default.

Set `monitoring.serviceMonitor.enabled=true` when the Prometheus Operator CRD is
installed. The ServiceMonitor sets `honorLabels: true` so the plugin's
`namespace` metric label is kept. Set `monitoring.prometheusRule.enabled=true`
to create the included alerts (12 rules covering plugin availability, NRI
disconnects, verification failures, circuit breaker trips, fetch errors,
interrupted verifications, admission latency, config reloads, cache hit ratio,
degraded containers, remediation errors, and continuous verifier staleness).
Both are opt-in so the chart can install on clusters without those CRDs.
The plugin availability alert matches the scrape job of the chart's
ServiceMonitor. When the plugin is scraped another way, set
`monitoring.prometheusRule.job` to that job; without a ServiceMonitor or a job,
the alert is left out, since it would fire permanently.

`monitoring.prometheusRule.verificationLatencyThresholdSeconds` and
`verificationLatencyFor` are deprecated and ignored. The latency alert now
watches the `CreateContainer` hook through
`admissionLatencyThresholdSeconds` (default `1`) and `admissionLatencyFor`.

Set `monitoring.grafana.enabled=true` to provision a Grafana dashboard via
a ConfigMap with the `grafana_dashboard: "1"` label. This works with the
Grafana sidecar container that watches for labeled ConfigMaps.

The chart derives the container metrics port from `config.metricsAddr` and the
probe port from `probes.port`.
`service.port` controls the port exposed by the Service and may differ from the
application's listening port.

## Security notes

The DaemonSet mounts `/var/run/nri` from the host, read-only: connecting to the
runtime's socket needs no write access, and the plugin cannot replace the
socket. The mount is necessary to enforce runtime verification and should be
treated as privileged node-level access.
The NRI socket is owned by root, so the container runs as UID 0, but it drops
all capabilities, disallows privilege escalation, uses the `RuntimeDefault`
seccomp profile, and has a read-only root filesystem with `emptyDir` volumes
for the Sigstore cache and `/tmp`. The namespace needs the `privileged` Pod
Security level.

The plugin pod carries the `tolerate-missing-nri-plugins.noderesource.dev`
annotation so it can start while the runtime requires the plugin. Pin the image
with `image.digest` and verify it out of band, because the plugin never
verifies its own image.

`podDisruptionBudget` is deprecated and ignored: node drains skip DaemonSet
pods and DaemonSet rollouts do not consult PodDisruptionBudgets. No CPU limit
is set by default, because throttling can delay `CreateContainer` responses
past the runtime's NRI request timeout.

Review policies, registry access, and the runtime's required plugin
configuration before enabling `enforce` mode.
