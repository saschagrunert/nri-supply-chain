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

### SLSA Provenance

Verifies [SLSA](https://slsa.dev) provenance v1 attestations.

Checks performed:

- **Subject digest**: The provenance `subject[].digest` must match the image
  digest.
- **Builder trust**: `runDetails.builder.id` must appear in the policy's
  `trust.builders` list.
- **Build type**: If `trust.buildTypes` is configured, the
  `buildDefinition.buildType` must match one of the allowed types.
- **Source repository**: If `trust.sources` is configured, the `source` in
  `externalParameters` must match an allowed glob pattern.
- **Unknown parameters**: If `slsa.rejectUnknownParameters` is enabled,
  unrecognized `externalParameters` fields cause rejection.

See [policy.md](policy.md#slsa-object) for the full field reference.

Note: `trust.builders[].maxLevel` is not checked during provenance
verification because provenance attestations do not declare a build level.
Use `vsa.minimumLevel` to enforce build level requirements.

When multiple provenance attestations exist, verification passes if any single
valid attestation from a trusted builder passes (any-pass semantics).

For custom build systems, configure `knownParameters` to list expected
`externalParameters` keys. See
[policy.md](policy.md#custom-build-systems) for an example.

### VEX (Vulnerability Exploitability eXchange)

Verifies [OpenVEX](https://openvex.dev) v0.2.0 documents.

Status handling:

- `not_affected` or `fixed`: pass
- `affected`: fail
- `under_investigation`: controlled by `underInvestigationPolicy` (default:
  allow)

Product matching operates at the image level using digest comparison and PURL
(`pkg:oci/...`) matching.

VEX statements with empty subjects are rejected when an image digest is
available. This prevents attestations that lack subject binding from bypassing
digest verification.

When multiple VEX documents exist, the most restrictive result wins: any
`affected` status causes failure.

### VSA (Verification Summary Attestation)

Verifies [SLSA VSA](https://slsa.dev/spec/v1.0/verification_summary) v1
attestations. Checks verifier trust, verification result, build level,
resource URI, SLSA version, policy match, and freshness. See
[policy.md](policy.md#vsa-object) for the full field reference.

VSA-first logic:

- Trusted PASSED: short-circuits all other checks.
- Trusted FAILED: hard reject, no fallback allowed.
- Untrusted, stale, or missing: falls through to direct SLSA + VEX
  verification.

### Signature Verification

The plugin supports keyless (Fulcio/OIDC) and key-based (PEM public key)
verification modes, which can be used independently or together. See
[policy.md](policy.md#signature-verification) for configuration details.
