# nri-supply-chain

Helm deployment for the NRI Supply Chain Plugin. It deploys a hardened DaemonSet
that connects to the host NRI socket and verifies container-image attestations.

## Prerequisites

- Kubernetes 1.26+
- NRI enabled in CRI-O or containerd, with its socket at `/var/run/nri`
- Helm 3

## Install

Create a values file containing your policy. The default policy deliberately
contains `myorg` placeholders and is suitable only as a starting point.

```console
helm upgrade --install nri-supply-chain deploy/helm/nri-supply-chain \
  --namespace nri-supply-chain --create-namespace \
  --set config.verification=enforce \
  --set-file policies.default\\.json=./default.json
```

Render without installing:

```console
helm template nri-supply-chain deploy/helm/nri-supply-chain \
  --namespace nri-supply-chain
```

## Policies and configuration

`policies` is a map of `<namespace>.json` policy files. `default.json` is
required for local policy mode. Set `config.policy.source=oci` and
`config.policy.ociRef` for OCI-distributed policies; local policy entries are
then not used by the plugin.

All standard operational settings are exposed below `config`, including
timeouts, cache limits, registry mirrors, Sigstore roots, and the policy
source. `config.extraConfig` appends TOML verbatim for forward-compatible
fields. `config.allowlistDigests` bypasses verification for explicitly trusted
digests. For policy/config semantics, see the repository's `docs/config.md`.

Private Sigstore roots and custom registry CAs should be supplied through a
Secret or ConfigMap using `extraVolumes` and `extraVolumeMounts`, then referred
to by their absolute mounted paths in `config.sigstore.roots` or
`config.registries`. Set `config.sigstore.enabled=true` when configuring
custom roots or an explicit `includePublicRoot` value.

## Monitoring

The chart creates a metrics Service by default. The network policy permits
metrics scraping only from namespaces selected by the default `monitoring`
label; adjust `networkPolicy.ingress` for your Prometheus topology.

Set `monitoring.serviceMonitor.enabled=true` when the Prometheus Operator CRD
is installed. Set `monitoring.prometheusRule.enabled=true` to create the
included alerts. Both are opt-in so the chart can install on clusters without
those CRDs.

The chart derives the container and probe port from `config.metricsAddr`.
`service.port` controls the port exposed by the Service and may differ from the
application's listening port.

## Security notes

The DaemonSet mounts `/var/run/nri` from the host. This is necessary to enforce
runtime verification and should be treated as privileged node-level access.
The container itself runs non-root, drops all capabilities, and uses a
read-only root filesystem. Review policies, registry access, and network-policy
selectors before enabling `enforce` mode.
