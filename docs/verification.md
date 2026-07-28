# Verification

This document describes the verification flow and attestation types supported
by the nri-supply-chain plugin.

<!-- toc -->

- [Verification Flow](#verification-flow)
- [Verification Types](#verification-types)
  - [SLSA Provenance](#slsa-provenance)
  - [VEX (Vulnerability Exploitability eXchange)](#vex-vulnerability-exploitability-exchange)
  - [VSA (Verification Summary Attestation)](#vsa-verification-summary-attestation)
  - [Signature Verification](#signature-verification)
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
   configured [`fetch_timeout`](config.md). If resolution fails, the container
   is handled according to the current verification mode (rejected in
   `enforce`, skipped with a warning in `warn`).

2. **Policy resolution**: Looks up `<namespace>.json` in the
   [policy directory](policy.md). Falls back to `default.json` if no
   namespace-specific policy exists.

3. **Exclusion check**: If the image matches any `exclude` glob pattern in the
   policy, verification is skipped.

4. **Cache check**: If a cached result exists for this image digest and is
   within the configured TTL, returns it immediately.

5. **Attestation fetch**: Discovers attestations via the OCI Referrers API.
   Filters for DSSE-enveloped Sigstore bundles, verifies each bundle's
   signature (keyless or key-based), and extracts payloads. Unsigned or
   incorrectly signed bundles are discarded. If the Referrers API returns no
   attestations, the plugin falls back to cosign's tag-based discovery
   scheme, looking for an image tagged `sha256-<digest>.att` in the same
   repository. The same signature verification applies to cosign tag
   attestations.

6. **VSA-first evaluation**:
   - If a trusted PASSED VSA is found, skip SLSA and VEX checks entirely.
   - If a trusted FAILED VSA is found, hard reject immediately (no fallback).
   - If no VSA is found, or the VSA is from an untrusted verifier or stale,
     fall through to direct verification.

7. **Parallel SLSA + VEX verification**: When VSA does not short-circuit,
   SLSA provenance and VEX checks run concurrently.

8. **Enforcement**: In `enforce` mode, failed verification rejects the
   container. In `warn` mode, failures are logged but allowed.

9. **Caching**: The result is cached for future lookups.

Latency model:

- With trusted VSA: `fetch + VSA verify`
- Without VSA: `fetch + max(SLSA verify, VEX verify)`

## Verification Types

The plugin supports three complementary attestation types that cover different
aspects of the supply chain:

- **SLSA provenance** answers "who built this artifact and how?" by verifying
  build provenance against trusted builders and sources.
- **VEX** answers "is this artifact affected by known vulnerabilities?" by
  evaluating vulnerability exploitability statements.
- **VSA** is a meta-attestation that records the outcome of a prior SLSA and
  VEX verification performed by a trusted verifier. It is not a replacement for
  SLSA or VEX, but a delegation mechanism: when a trusted VSA with result
  PASSED exists, the plugin skips re-verifying SLSA and VEX individually.

### SLSA Provenance

Verifies [SLSA](https://slsa.dev) provenance v1 attestations against trusted
builders and sources. When multiple attestations exist, any single valid one
from a trusted builder is sufficient (any-pass semantics). See
[policy.md](policy.md#slsa-provenance) for the full check list, field
reference, and custom build system configuration.

### VEX (Vulnerability Exploitability eXchange)

Verifies [OpenVEX](https://openvex.dev) v0.2.0 documents. When multiple VEX
documents exist, the most restrictive result wins: any `affected` status
causes failure. See [policy.md](policy.md#vex-vulnerability-exploitability-exchange)
for status handling, product matching, and the field reference.

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

## Other Standards

The supply chain ecosystem includes several related formats and frameworks
that the plugin does not currently support:

- **[CycloneDX VEX](https://cyclonedx.org/capabilities/vex/)**: an alternative
  VEX format. The plugin currently supports OpenVEX only.
- **[SARIF](https://sarifweb.azurewebsites.net/)** (Static Analysis Results
  Interchange Format): a standardized format for security scanner results that
  could complement VEX by providing detailed finding data.
- **[SCAI](https://github.com/in-toto/attestation/blob/main/spec/predicates/scai.md)**
  (Supply Chain Attribute Integrity): an in-toto predicate type for capturing
  evidence about build attributes, complementing SLSA provenance.
- **[GUAC](https://guac.sh/)** (Graph for Understanding Artifact Composition):
  a framework for aggregating and querying software supply chain metadata. Not
  an attestation format itself, but a potential integration point for policy
  decisions.
