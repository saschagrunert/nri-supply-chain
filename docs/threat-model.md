# Threat Model

This document provides a STRIDE-based threat analysis of the nri-supply-chain
plugin, covering trust boundaries, identified threats, existing mitigations,
and residual risks.

<!-- toc -->

- [System Overview](#system-overview)
- [Trust Boundaries](#trust-boundaries)
- [STRIDE Analysis](#stride-analysis)
  - [TB1: Container Runtime to Plugin (NRI Socket)](#tb1-container-runtime-to-plugin-nri-socket)
  - [TB2: Plugin to OCI Registries](#tb2-plugin-to-oci-registries)
  - [TB3: Plugin to Sigstore Infrastructure](#tb3-plugin-to-sigstore-infrastructure)
  - [TB4: Plugin to Local Filesystem](#tb4-plugin-to-local-filesystem)
  - [TB5: Plugin to Kubernetes API](#tb5-plugin-to-kubernetes-api)
- [Residual Risks](#residual-risks)
- [Out of Scope](#out-of-scope)

<!-- /toc -->

## System Overview

The nri-supply-chain plugin is an NRI (Node Resource Interface) plugin that
intercepts container creation events on CRI-O or containerd. Before a container
is allowed to run, the plugin fetches and verifies supply chain attestations
(SLSA provenance, VEX, VSA, Notation signatures, SBOMs, SCAI) from OCI
registries.
It operates below the Kubernetes API layer, so every container on a node must
pass verification regardless of how it was scheduled.

The plugin runs as a long-lived daemon connected to the container runtime via a
Unix domain socket. It uses Sigstore (Fulcio, Rekor, TUF) for cryptographic
verification, reads per-namespace policies from local files or OCI artifacts,
and caches results to reduce registry load.

## Trust Boundaries

| ID  | Boundary                          | Transport               | Authentication                 |
| --- | --------------------------------- | ----------------------- | ------------------------------ |
| TB1 | Container runtime to plugin       | NRI Unix socket (ttrpc) | Implicit (same-node process)   |
| TB2 | Plugin to OCI registries          | HTTPS                   | Docker/Podman keychain         |
| TB3 | Plugin to Sigstore infrastructure | HTTPS (TUF)             | TUF root of trust              |
| TB4 | Plugin to local filesystem        | Filesystem              | Unix permissions               |
| TB5 | Plugin to Kubernetes API          | NRI annotations         | Runtime-injected, not user-set |

## STRIDE Analysis

### TB1: Container Runtime to Plugin (NRI Socket)

| Category              | Threat                                                                 | Mitigation                                                                                                                                                          |
| --------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Spoofing**          | Rogue process connects to the NRI socket posing as the runtime         | NRI socket uses Unix domain socket with filesystem permissions; only the runtime user can connect                                                                   |
| **Tampering**         | Malicious process modifies NRI messages between runtime and plugin     | ttrpc runs over a local socket; no network intermediary. Requires root or socket owner to intercept                                                                 |
| **Repudiation**       | Runtime does not log which containers were sent to the plugin          | Plugin logs every CreateContainer call with pod, container, image, and outcome (slog.InfoContext in `CreateContainer`)                                              |
| **Info disclosure**   | NRI messages expose image references and annotations to socket readers | Socket permissions restrict access; debug logging (which includes annotations) requires explicit opt-in                                                             |
| **Denial of service** | Flood of CreateContainer calls overwhelms the plugin                   | Verification timeout (`verification_timeout`, max 30m) bounds each call; singleflight (`inflight.DoChan`) deduplicates concurrent verifications for the same digest |
| **Elevation of priv** | Bypassing the plugin by calling the runtime directly                   | NRI hooks are mandatory when enabled in the runtime config; containers cannot be created without passing through registered plugins                                 |

### TB2: Plugin to OCI Registries

| Category              | Threat                                                                                     | Mitigation                                                                                                                                                                                                                               |
| --------------------- | ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Spoofing**          | Attacker serves a rogue registry or performs DNS hijacking                                 | HTTPS with TLS certificate validation (default); `insecure = true` rejected in enforce mode (`config.md`); `ca_cert` for custom CAs                                                                                                      |
| **Tampering**         | Registry returns tampered attestations                                                     | All Sigstore bundles are cryptographically verified against the trusted root; invalid signatures are discarded (cosign size limit check in `internal/attestation/fetcher.go`)                                                            |
| **Tampering**         | Tag-to-digest TOCTOU: registry changes tag between digest resolution and attestation fetch | CRI-O always provides digests in annotations, eliminating the window. See [Residual Risks](#residual-risks) for containerd                                                                                                               |
| **Repudiation**       | Registry denies having served a particular attestation                                     | Rekor transparency log entries provide non-repudiable proof of signing events when `requireTransparencyLog` is enabled                                                                                                                   |
| **Info disclosure**   | Registry learns which images are running on the cluster                                    | Inherent to pull-based verification; cache reduces frequency (`cache_ttl` default 24h)                                                                                                                                                   |
| **Denial of service** | Registry outage blocks container creation                                                  | Circuit breaker (`circuit_breaker_threshold` / `circuit_breaker_cooldown`); `fetch_failure_policy` controls behavior; retry with exponential backoff (`internal/attestation/fetcher.go`); mirror fallback for configured registries      |
| **Denial of service** | Oversized or excessive attestations exhaust plugin memory                                  | Per-attestation size limit (`maxAttestationSize`), aggregate limit (`maxTotalAttestationSize`), max referrers (`maxReferrers`) in `internal/attestation/fetcher.go`; global fetch concurrency semaphore (50) and per-host semaphore (10) |
| **Elevation of priv** | Compromised mirror serves valid attestations for a different image                         | Sigstore bundle verification binds attestations to the image digest; a valid attestation for the wrong digest fails verification                                                                                                         |

### TB3: Plugin to Sigstore Infrastructure

| Category              | Threat                                                               | Mitigation                                                                                                                                               |
| --------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Spoofing**          | Attacker impersonates Fulcio CA or Rekor log                         | TUF root of trust pins Fulcio CA certificates and Rekor public keys; custom deployments use `tuf_root` for independent root keys                         |
| **Tampering**         | Attacker modifies TUF metadata in transit                            | TUF protocol validates metadata signatures against the root of trust; HTTPS transport                                                                    |
| **Repudiation**       | Signing identity disputes having signed an attestation               | Rekor transparency log provides append-only, publicly auditable record of signing events                                                                 |
| **Info disclosure**   | TUF mirror learns plugin refresh patterns                            | Trusted root is cached for 1 hour (`trustedRootCacheTTL` in `internal/attestation/fetcher.go`); stale cache served for up to 24 hours on refresh failure |
| **Denial of service** | TUF mirror or Sigstore services are unavailable                      | Stale trusted root cache (up to 24h) allows continued verification; metric `trusted_root_fallback_total` tracks usage; startup pre-warms the cache       |
| **Elevation of priv** | Compromised OIDC issuer issues certificates for arbitrary identities | `trust.issuers` restricts accepted OIDC providers; `trust.sanPatterns` restricts accepted certificate SANs; enforce mode requires both                   |

### TB4: Plugin to Local Filesystem

| Category              | Threat                                                               | Mitigation                                                                                                                       |
| --------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **Spoofing**          | Attacker replaces policy files with permissive ones                  | Filesystem permissions on `policy_dir`; OCI-based policy distribution (`policy.source = "oci"`) avoids local filesystem entirely |
| **Tampering**         | Attacker modifies config.toml to weaken verification                 | Filesystem permissions; strict TOML parser rejects unknown keys; enforce mode rejects `insecure = true` registries               |
| **Tampering**         | Key file changed between validation and use (TOCTOU)                 | See [Residual Risks](#residual-risks) (TOCTOU comment in `internal/policy/policy_validate.go`)                                   |
| **Repudiation**       | No record of who changed a policy file                               | Outside plugin scope; use filesystem auditing (auditd) or OCI policy source with registry audit logs                             |
| **Info disclosure**   | Key files or config readable by unprivileged users                   | Key files validated via `Lstat` (detects symlinks); `fileutil.ReadLimited` caps reads; standard Unix permissions apply           |
| **Denial of service** | Attacker deletes policy files, causing all containers to be rejected | In enforce mode, missing policies reject containers (fail-closed); in warn mode, missing policies log warnings                   |
| **Elevation of priv** | Attacker with filesystem write access disables verification          | Filesystem access implies node compromise, which is out of scope. Config reload logs all changes                                 |

### TB5: Plugin to Kubernetes API

| Category              | Threat                                                                    | Mitigation                                                                                                                                                                                       |
| --------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Spoofing**          | User injects fake runtime annotations via pod spec to bypass verification | Runtime overwrites user-supplied annotation keys with its own values after processing the CRI request; digests are validated for strict `algorithm:hex` format (`validDigestOrEmpty`)            |
| **Tampering**         | User crafts annotations to make the plugin verify a different image       | Sigstore bundle verification cryptographically binds attestations to the image digest; forged annotations cause signature verification failure                                                   |
| **Repudiation**       | No audit trail of verification decisions per pod                          | Plugin injects `supply-chain.nri/verified`, `supply-chain.nri/mode`, and `supply-chain.nri/checks` annotations on each container; audit logging records decisions with policy hash and node name |
| **Info disclosure**   | Verification annotations leak internal state                              | Annotations contain only pass/fail status and check type; no secrets, keys, or registry credentials are exposed                                                                                  |
| **Denial of service** | Many namespaces create excessive policy lookups                           | Policy files are loaded once at startup and on reload; namespace lookup is a map access. Metrics label cardinality may cause Prometheus memory growth (see `operations.md:239`)                  |
| **Elevation of priv** | User in one namespace influences verification of another namespace        | Policies are per-namespace with no cross-namespace references; namespace is derived from the pod sandbox, not user input                                                                         |

## Residual Risks

These are acknowledged risks that are not fully mitigated by the plugin.

| Risk                                  | Description                                                                                                                                                                                                                                          | Severity | Workaround                                                                                    |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------- |
| Tag-to-digest TOCTOU (containerd)     | When containerd does not provide a digest in annotations, the plugin resolves it via a registry HEAD request. A malicious registry could serve a different digest than the content the runtime pulls. CRI-O is not affected.                         | High     | Pin images by digest (`image@sha256:...`) or use CRI-O                                        |
| Key file TOCTOU                       | The key file could change between `Lstat` validation and the subsequent `loadPublicKeyFromPEM` call (see TOCTOU comment in `internal/policy/policy_validate.go`). An attacker with filesystem write access could swap a key file in the race window. | Low      | Mount key files read-only; use keyless (Fulcio/OIDC) verification instead                     |
| Self-attested VSA in release pipeline | SLSA provenance is generated independently via `slsa-github-generator`, but the VSA is still self-attested: the same workflow that builds the artifact also generates the VSA, creating a circular trust dependency for the verification summary.    | Medium   | Configure `trust.verifiers` to require a separate, independent verifier                       |
| Cache staleness after registry outage | When `fetch_failure_policy` is `allow` or `warn`, failed fetch results are cached for `cache_failure_ttl` (default 5m). Containers admitted during this window bypass registry verification.                                                         | Medium   | Set `fetch_failure_policy = "deny"` in enforce mode (the default); reduce `cache_failure_ttl` |
| Stale trusted root                    | If the TUF mirror is unreachable, the plugin uses a cached trusted root for up to 24 hours. Revoked certificates or keys remain trusted during this window.                                                                                          | Medium   | Monitor `trusted_root_fallback_total` metric; alert on prolonged staleness                    |
| Metrics endpoint exposure             | Changing `metrics_addr` to a non-loopback address exposes image references, namespaces, and verification outcomes, aiding reconnaissance.                                                                                                            | Low      | Keep default loopback binding; use NetworkPolicy when exposing externally                     |

## Out of Scope

The plugin does not protect against:

- **Compromised container runtime.** If CRI-O or containerd is compromised, an
  attacker can bypass NRI hooks entirely. The plugin trusts the runtime to
  faithfully deliver CreateContainer events and annotations.
- **Kernel exploits.** Container escapes via kernel vulnerabilities operate below
  the plugin's enforcement layer.
- **Hardware attacks.** Physical access, side-channel attacks, or compromised
  hardware (TPM, CPU) are outside the software verification model.
- **Image content vulnerabilities.** The plugin verifies attestations about an
  image, not the image content itself. A properly attested image can still
  contain exploitable software. VEX attestations provide vulnerability status
  but depend on the accuracy of the VEX producer.
- **Supply chain attacks upstream of signing.** If a build system is compromised
  before generating attestations, the resulting attestations are valid but
  attest compromised artifacts. SLSA levels and trusted builder lists reduce
  this risk but do not eliminate it.
- **Network-level attacks on the NRI socket.** The Unix domain socket is
  assumed to be protected by filesystem permissions. The plugin does not
  authenticate the runtime process beyond socket access.
- **Denial of service via node resource exhaustion.** An attacker who can
  exhaust node CPU, memory, or disk can prevent the plugin from running. This
  is a node-level concern, not specific to the plugin.
