# Verification

This document describes the verification flow and attestation types supported
by the nri-supply-chain plugin.

<!-- toc -->

- [Verification Flow](#verification-flow)
  - [Continuous Re-verification](#continuous-re-verification)
- [Container Annotations](#container-annotations)
- [Verification Types](#verification-types)
  - [SLSA Provenance](#slsa-provenance)
  - [VEX (Vulnerability Exploitability eXchange)](#vex-vulnerability-exploitability-exchange)
  - [VSA (Verification Summary Attestation)](#vsa-verification-summary-attestation)
  - [Signature Verification](#signature-verification)
  - [Notation (Notary v2)](#notation-notary-v2)
  - [SBOM (Software Bill of Materials)](#sbom-software-bill-of-materials)
  - [SCAI (Supply Chain Attribute Integrity)](#scai-supply-chain-attribute-integrity)
  - [SLSA Source Track](#slsa-source-track)
  - [Build Environment](#build-environment)
  - [Vulnerability Scan](#vulnerability-scan)
  - [Test Result](#test-result)
  - [Release](#release)
  - [Runtime Trace](#runtime-trace)
  - [GUAC (Graph for Understanding Artifact Composition)](#guac-graph-for-understanding-artifact-composition)
  - [OpenSSF Scorecard](#openssf-scorecard)
- [Other Standards](#other-standards)

<!-- /toc -->

## Verification Flow

When a container is created, the plugin performs verification in this order:

1. **Image identification**: Extracts the image reference and digest from
   container annotations. CRI-O annotations are checked first. For the image
   reference, `io.kubernetes.cri-o.ImageName` is preferred; if absent,
   `io.kubernetes.cri-o.Image` is used as a fallback. For the digest,
   `io.kubernetes.cri-o.ImageRepoDigests` is preferred (the first
   comma-separated entry is parsed and the digest extracted from the portion
   after `@`); if absent, `io.kubernetes.cri-o.ImageRef` is used as a
   fallback. When CRI-O provides both a reference and a digest, that pair
   takes precedence. If CRI-O does not provide both, a complete containerd
   pair (`io.kubernetes.cri.image-name` + `io.kubernetes.cri.image-ref`) is
   used. If neither runtime provides a complete pair, available annotations
   from either source are combined. Malformed digests from CRI-O annotations
   are validated and rejected; only well-formed `algorithm:hex` digests are
   accepted. When the containerd image name contains a digest reference
   (e.g. `image@sha256:abc...`), the digest is extracted directly from the
   annotation without a network call. Otherwise, when an image reference is
   present but the digest is missing (common with containerd, which does not
   always provide `io.kubernetes.cri.image-ref`), the plugin resolves the
   digest by performing a `HEAD` request against the registry using the
   configured [`digest_resolve_timeout`](config.md) (NRI plugin) or
   [`fetch_timeout`](config.md) (CLI). If resolution fails, the container
   is handled according to the current verification mode (rejected in
   `enforce`, skipped with a warning in `warn`).

2. **Policy resolution**: Looks up `<namespace>.json` in the
   [policy directory](policy.md). Falls back to `default.json` if no
   namespace-specific policy exists.

3. **Include check**: If the policy has `include` patterns, only images
   matching at least one pattern proceed. Images that do not match any
   include pattern skip verification. When `include` is empty (the
   default), all images are eligible.

4. **Exclusion check**: If the image matches any `exclude` glob pattern in the
   policy, verification is skipped. Exclude takes precedence over include:
   an image matching both is skipped.

5. **Per-image rule resolution**: If the policy has `rules`, the image is
   matched against each rule's `images` patterns in order (first match
   wins). When a rule matches, its non-nil sections (trust, slsa, vex,
   vsa, signatures, notation, sbom, scai, source, buildEnv, vulnScan,
   testResult, release, runtimeTrace, scorecard, cel) override the base policy for that verification.

6. **Cache check**: If a cached result exists for this image digest and is
   within the configured TTL, returns it immediately.

7. **GUAC query** (if enabled): A GUAC query is started in a background
   goroutine before the OCI attestation fetch. The query runs in parallel
   with the fetch and its result is collected after the fetch completes.
   See [config.md](config.md#guac) for configuration.

8. **Attestation fetch**: The attestation source depends on the configured
   `offline.mode` (see [config.md](config.md#offline-bundles)):
   - **disabled** (default): Discovers attestations via the OCI Referrers API.
     Filters for DSSE-enveloped Sigstore bundles, verifies each bundle's
     signature (keyless or key-based), and extracts payloads. Unsigned or
     incorrectly signed bundles are discarded. If the Referrers API returns no
     attestations, the plugin falls back to cosign's tag-based discovery
     scheme, looking for an image tagged `sha256-<digest>.att` in the same
     repository. The same signature verification applies to cosign tag
     attestations.
   - **prefer-bundle**: Reads attestations from the local bundle store first.
     If no attestations are found for the image digest (or the bundle store is
     missing), falls back to the OCI registry path described above.
     Non-recoverable bundle errors (expired bundle with deny policy, signature
     verification failure) are not retried via the registry.
   - **offline**: Reads attestations exclusively from the local bundle store.
     No network calls are made. If the image is not in the bundle, the fetch
     returns an error handled by `fetch_failure_policy`.

9. **VSA-first evaluation**:
   - If a trusted PASSED VSA is found, skip all parallel checks (SLSA, VEX,
     Notation, SBOM, SCAI, Source, BuildEnv, VulnScan, TestResult, Release,
     RuntimeTrace, Scorecard) and
     CEL evaluation entirely.
   - If a trusted FAILED VSA is found, hard reject immediately (no fallback).
   - If no VSA is found, or the VSA is from an untrusted verifier or stale,
     fall through to direct verification.

10. **Parallel verification**: When VSA does not short-circuit, SLSA provenance,
    VEX, Notation signature, SBOM, SCAI, Source Track, Build Environment,
    Vulnerability Scan, Test Result, Release, Runtime Trace, and OpenSSF
    Scorecard checks run concurrently.

11. **CEL policy evaluation**: If the policy defines CEL rules, they are
    evaluated against the combined check results. CEL rules can enforce
    cross-check constraints (e.g., require both SLSA and VEX to pass).

12. **Enforcement**: In `enforce` mode, failed verification rejects the
    container. In `warn` mode, failures are logged but allowed.

13. **Caching**: The result is cached for future lookups.

Latency model:

- With trusted VSA: `max(fetch, GUAC query) + VSA verify`
- Without VSA: `max(fetch, GUAC query) + max(SLSA, VEX, Notation, SBOM, SCAI, Source, BuildEnv, VulnScan, TestResult, Release, RuntimeTrace, Scorecard) + CEL eval`

When GUAC is enabled, its query runs in parallel with the OCI attestation
fetch, so it does not add latency unless the GUAC query is slower than the
fetch. Note that when a trusted VSA short-circuits verification, the GUAC
result is discarded (GUAC data is only used in CEL evaluation, which VSA
bypasses).

### Continuous Re-verification

When [remediation](config.md#remediation) is enabled, the plugin periodically
re-runs the verification flow above for all tracked containers. The
re-verification loop runs in the background at the configured interval. Timer
ticks use cached results when available; feed and manual triggers invalidate
the cache first to fetch fresh attestation data.

If a container's verification result degrades (previously passing checks now
fail), the plugin applies graduated remediation based on the configured mode.
See [config.md](config.md#remediation) for the state machine, triggers, and
throttle behavior.

## Container Annotations

In `warn` and `enforce` modes, the plugin injects annotations on each
container via the NRI `ContainerAdjustment` response. These annotations
provide per-container verification metadata that can be consumed by admission
webhooks, audit pipelines, or `kubectl describe`.

| Annotation                  | Example value        | Description                                                                                                |
| --------------------------- | -------------------- | ---------------------------------------------------------------------------------------------------------- |
| `supply-chain.nri/verified` | `true` or `false`    | Whether all checks passed. In warn mode, reflects the actual outcome even though the container is allowed. |
| `supply-chain.nri/mode`     | `warn` or `enforce`  | The effective verification mode applied to this container.                                                 |
| `supply-chain.nri/checks`   | `slsa:pass,vex:warn` | Comma-separated `type:status` pairs for each check result. Only present when checks were run.              |

In `disabled` mode, no annotations are injected. When a container is skipped
(excluded, not included, or missing annotations), no verification annotations
are added.

## Verification Types

The plugin supports several complementary attestation types that cover different
aspects of the supply chain. The three core types are:

- **SLSA provenance** answers "who built this artifact and how?" by verifying
  build provenance against trusted builders and sources.
- **VEX** answers "is this artifact affected by known vulnerabilities?" by
  evaluating vulnerability exploitability statements.
- **VSA** is a meta-attestation that records the outcome of a prior
  verification performed by a trusted verifier. It is not a replacement for
  the individual checks, but a delegation mechanism: when a trusted VSA with
  result PASSED exists, the plugin skips all parallel checks and CEL evaluation.

### SLSA Provenance

Verifies [SLSA](https://slsa.dev) provenance v1 attestations against trusted
builders and sources. When multiple attestations exist, any single valid one
from a trusted builder is sufficient (any-pass semantics). See
[policy.md](policy.md#slsa-provenance) for the full check list, field
reference, and custom build system configuration.

### VEX (Vulnerability Exploitability eXchange)

Verifies VEX documents in two formats:

- [OpenVEX](https://openvex.dev) v0.2.0
- [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/) (via CycloneDX BOM
  vulnerability entries)

The format is detected automatically from the predicate content. When multiple
VEX documents exist (in either format), the most restrictive result wins: any
`affected`/`exploitable` status causes failure. See
[policy.md](policy.md#vex-vulnerability-exploitability-exchange) for status
handling, product matching, and the field reference.

### VSA (Verification Summary Attestation)

Verifies [SLSA VSA](https://slsa.dev/spec/v1.0/verification_summary) v1
attestations. A VSA records the outcome of a prior verification performed by
a trusted verifier. A trusted PASSED VSA short-circuits all other checks; a
trusted FAILED VSA is a hard reject with no fallback. Untrusted, stale, or
missing VSAs fall through to direct SLSA + VEX verification. See
[policy.md](policy.md#vsa-verification-summary-attestation) for the full
check list and field reference.

### Signature Verification

All attestations must be valid Sigstore bundles. The plugin supports keyless
(Fulcio/OIDC) and key-based (PEM public key) modes. See
[policy.md](policy.md#signature-verification) for configuration details.

### Notation (Notary v2)

Verifies container image signatures using
[Notation](https://notaryproject.dev), the CNCF Notary Project's signing
tool. The plugin validates signatures against configured trust stores and
trust policies, supporting both CA-based and signing-authority trust models.
See [policy.md](policy.md#notation-notary-v2-signature-verification) for
the trust store setup, verification levels, and field reference.

### SBOM (Software Bill of Materials)

Verifies SBOM attestations in [SPDX](https://spdx.dev) JSON and
[CycloneDX](https://cyclonedx.org) JSON formats. SBOMs are discovered via
in-toto predicate type routing (`https://spdx.dev/Document` for SPDX,
`https://cyclonedx.org/bom` for CycloneDX). The plugin extracts package
licenses and PURLs from the SBOM and checks them against configurable deny
and allow lists. When baseline SBOMs are attached to the image via the OCI
Referrers API (artifact type
`application/vnd.nri-supply-chain.sbom-baseline.v1+json`), the plugin
compares the current SBOM against the baseline using PURL as the identity
key and computes a weighted drift score. Policy thresholds on added,
removed, and modified package counts, and overall score can enforce limits
on acceptable drift. See [policy.md](policy.md#sbom-verification) for the
field reference and [policy.md](policy.md#sbomdrift-object) for drift
thresholds.

### SCAI (Supply Chain Attribute Integrity)

Verifies [SCAI](https://github.com/in-toto/attestation/blob/main/spec/predicates/scai.md)
attribute report attestations (predicate type
`https://in-toto.io/attestation/scai/v0.3`). SCAI reports capture
evidence about build attributes, complementing SLSA provenance. The plugin
checks required and forbidden attributes and optionally requires evidence
on each attribute. See [policy.md](policy.md#scai-verification) for the
field reference.

### SLSA Source Track

Verifies [SLSA Source Track v1](https://slsa.dev/spec/draft/source-requirements)
attestations (predicate type `https://slsa.dev/source/v1`). Source attestations
capture the origin repository, branch, and source level of the code used to
build the image. The plugin checks the source against trusted repositories
and enforces minimum source level requirements. See
[policy.md](policy.md#source-track-verification) for the field reference.

### Build Environment

Verifies [build-env v1](https://github.com/in-toto/attestation/tree/main/spec/predicates)
attestations (predicate type `https://in-toto.io/attestation/build-env/v1`).
Build environment attestations describe the properties of the build
environment, such as whether the build was hermetic or reproducible. The
plugin checks required and forbidden properties. See
[policy.md](policy.md#build-environment-verification) for the field reference.

### Vulnerability Scan

Verifies [vulns](https://github.com/in-toto/attestation/blob/main/spec/predicates/vuln.md)
attestations (predicate types `https://in-toto.io/attestation/vulns/v0.1` and
`https://in-toto.io/attestation/vulns/v0.2`).
Vulnerability scan attestations capture automated scanner results. The
plugin enforces CVSS score and severity thresholds with an optional CVE
ignore list. See [policy.md](policy.md#vulnerability-scan-verification) for
the field reference.

### Test Result

Verifies [test-result v0.1](https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md)
attestations (predicate type `https://in-toto.io/attestation/test-result/v0.1`).
Test result attestations capture the outcome of automated test suites. The
plugin verifies the overall result is passing and can enforce that specific
suites are present and passing. See
[policy.md](policy.md#test-result-verification) for the field reference.

### Release

Verifies [release v0.1](https://github.com/in-toto/attestation/blob/main/spec/predicates/release.md)
attestations (predicate type `https://in-toto.io/attestation/release/v0.1`).
Release attestations record the publication of an artifact to a package
repository, capturing the package URL (purl) and optional package identifier.
The plugin checks the purl against trusted registry patterns and can require
a package identifier to be present. When multiple release attestations exist,
any single valid one is sufficient (any-pass semantics). See
[policy.md](policy.md#release-verification) for the field reference.

### Runtime Trace

Verifies [runtime-trace v0.1](https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md)
attestations (predicate type `https://in-toto.io/attestation/runtime-trace/v0.1`).
Runtime trace attestations capture build-time runtime observations from a
monitor, including process activity, network connections, and file accesses.
The plugin checks the monitor type against trusted patterns and validates that
no forbidden file access patterns appear in the trace. When multiple runtime
trace attestations exist, all must pass (all-must-pass semantics) and metadata
is merged across documents. See
[policy.md](policy.md#runtime-trace-verification) for the field reference.

### GUAC (Graph for Understanding Artifact Composition)

[GUAC](https://guac.sh/) is an OpenSSF project that aggregates software supply
chain metadata into a queryable graph. Unlike the other verification types
above, GUAC is not an OCI attestation format. It is a supplemental data source
that the plugin queries in parallel with the OCI attestation fetch.

When enabled via the `[guac]` config section (see [config.md](config.md#guac)),
the plugin queries a GUAC server for three types of information:

- **certify_vuln**: Vulnerability data correlated across the dependency graph,
  split into direct and transitive vulnerabilities. Each entry includes the
  vulnerability ID and the affected package identifier.
- **certify_scorecard**: OpenSSF Scorecard results aggregated by GUAC (uses an
  unscoped filter, returning the first scorecard found).
- **is_dependency**: Transitive dependency enumeration, limited by the
  `max_dependencies` config setting.

GUAC query results are exposed as CEL variables in the `guac.*` namespace (see
[policy.md](policy.md#cel-object) for the variable reference). A GUAC query
failure is handled according to `fallback_policy`: `allow` (skip silently),
`warn` (default, log and continue), or `deny` (fail the check).

GUAC results do not affect the pass/fail outcome of other verification types.
They provide supplemental context that CEL rules can use for policy decisions.

**Why supplemental, not a replacement:** OCI attestations and GUAC serve
different trust models. OCI attestations are cryptographically signed,
tamper-evident, and authoritative for a single image ("this image has SLSA
provenance from builder X"). GUAC is authoritative for cross-artifact
relationships that no single attestation can express ("this image depends on
package Y, which has vulnerability Z"). The two data sources have different
failure modes and update cadences; keeping them separate with independent
fallback policies reflects that. CEL rules combine both perspectives, for
example: `slsa.verified && guac.transitive_vulns.size() == 0`.

### OpenSSF Scorecard

Verifies [OpenSSF Scorecard](https://github.com/ossf/scorecard) JSON v2 results
carried in in-toto attestations with the provisional predicate type
`https://scorecard.dev/result/v0.1`. Scorecard evaluates repository security
practices such as code review, branch protection, dependency pinning, fuzzing,
and maintained status. The plugin can enforce an aggregate minimum and exact
per-check minimum scores, and exposes the repository, Scorecard version,
aggregate score, and check-score map to CEL. When multiple Scorecard results
exist, all must pass. See
[policy.md](policy.md#openssf-scorecard-verification) for the field reference.

## Other Standards

The supply chain ecosystem includes several related formats and frameworks
that the plugin does not currently support:

- **[SARIF](https://sarifweb.azurewebsites.net/)** (Static Analysis Results
  Interchange Format): a standardized format for security scanner results that
  could complement VEX by providing detailed finding data.
