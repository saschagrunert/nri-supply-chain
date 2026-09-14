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
     signature (keyless or key-based), and extracts payloads. The predicate
     type is always read from the signed in-toto statement; unsigned referrer
     annotations are never trusted. Incorrectly signed bundles are discarded,
     and when referrers were found but none of them verified, the fetch fails
     with a verification error (distinct from registry errors). Referrer
     content that is not a valid attestation (for example an image index
     where an attestation manifest is expected, an undecodable layer or a
     broken manifest) counts as a verification failure, not as a registry
     error, so junk pushed to a registry cannot turn a denial into a lenient
     fetch failure. A truncated or corrupt layer or manifest is content, even
     though decoding reports it like a dropped connection; only a response
     body that ends early while it is downloaded is a transport failure.
     Layers that list external URLs (foreign layers) are rejected as invalid
     content before any download, so a pushed manifest cannot make the plugin
     contact arbitrary hosts. A referrer that the registry fails to serve
     (connection errors, timeouts, HTTP 408, 429 and 5xx) fails the whole
     fetch, because evaluating an incomplete attestation set could flip a
     decision. HTTP 401 and 403 for a single referrer after the referrers
     listing succeeded with the same credentials are a per-artifact decision
     of the registry (for example a policy engine blocking a freshly pushed
     artifact) and count as verification failures; a 401 or 403 for the
     listing itself stays a transport failure. A transport failure on any
     referrer (including the fetch deadline) wins over referrers that failed
     verification, because the referrer that could not be fetched might have
     verified; only when every referrer was fetched, none verified and one
     failed verification is the outcome a verification failure (see below). Referrer processing is limited per image to 50
     Sigstore bundles, 10 Notation signatures and 5 baseline SBOMs among the
     distinct referrer manifests, to referrer manifests of at most 4 MiB, to
     the configured attestation size, and to 100 MiB downloaded per fetch
     (referrer manifests and layers, including referrers that turn out to be
     junk). Duplicate referrer manifests and identical bundle blobs are
     counted once. Exceeding any of these limits denies the image as an
     incomplete attestation set instead of silently dropping attestations, since a
     dropped attestation could flip a decision. Referrers with the exact Sigstore bundle artifact type are
     selected before generic (empty or `application/vnd.oci.empty.v1+json`)
     artifact types. Cosign signature bundles (predicate type
     `https://sigstore.dev/cosign/sign/v1`) and unrelated artifact types are
     not attestations and are skipped. If the Referrers API returns no
     attestations, the plugin falls back to cosign's tag-based discovery
     scheme, looking for an image tagged `sha256-<digest>.att` in the same
     repository. Legacy cosign layers (a DSSE envelope with the certificate
     and Rekor bundle in layer annotations) are converted into Sigstore
     bundles and verified the same way; key-signed legacy layers are tried
     against every trusted key. Only a missing `.att` tag (HTTP 404) means "no
     attestations"; registry transport errors fail the fetch and a tag that
     does not hold a readable attestation image is a verification failure.
   - **prefer-bundle**: Reads attestations from the local bundle store first.
     If no attestations are found for the image digest (or the bundle store is
     missing), falls back to the OCI registry path described above.
     Non-recoverable bundle errors (expired bundle with deny policy, signature
     verification failure) are not retried via the registry.
   - **offline**: Reads attestations exclusively from the local bundle store.
     No network calls are made. If the image is not in the bundle, the fetch
     returns an error handled by `fetch_failure_policy`.

   Bundled attestations are always cryptographically re-verified against the
   policy trust configuration, exactly like registry attestations: the stored
   Sigstore bundle signature, the image digest binding, and the signer
   identity. Key-based attestations verify without an embedded trusted root;
   keyless attestations and transparency log checks require the trusted root
   embedded in the bundle and fail closed without it. `bundle create` embeds
   every cached trusted root with the name of its Sigstore root source
   (`public-sigstore` or `sigstore.roots[].name`). The verifying node applies
   the `issuers` it configures for the source with that name, exactly as
   online; issuers recorded in the bundle are informational and never widen
   trust. A root without a matching name (bundles of older releases, or a
   root passed with `--trusted-root`) is only trusted for issuers that every
   configured root allows, and not for certificates at all when no issuer is
   allowed by all of them; it still provides transparency log material for
   key-based attestations. Without a `sigstore.roots` array the embedded
   roots are unscoped, like the single online root, and the plugin logs a
   warning unless `offline.bundle_signature_key` protects the bundle
   manifest. Blob digests and sizes are re-checked on every read; a blob
   that was modified, resized, removed, or replaced by something other than
   a regular file (a directory or FIFO) after import denies the image as an
   incomplete attestation set, while a blob the plugin cannot read for local reasons (for
   example missing permissions) follows `fetch_failure_policy`. The predicate type
   comes from the verified statement rather than the unsigned bundle
   manifest, and bundles created by releases that stored unsigned payloads
   fail verification and must be recreated. Notation signatures are not
   packaged into bundles.

9. **VSA-first evaluation**: a VSA only counts when its attestation was
   signed by a key or keyless identity bound to the verifier it names
   (`trust.verifiers[].keys` or `identities`). The verifier ID is only a claim
   inside the signed payload, so without this binding any trusted signer could
   issue a VSA in the name of a trusted verifier.
   - If a signer-bound, trusted PASSED VSA is found, skip all parallel checks
     (SLSA, VEX, Notation, SBOM, SCAI, Source, BuildEnv, VulnScan, TestResult,
     Release, RuntimeTrace, Scorecard). CEL rules still run; they only see the
     VSA result, so rules that reference other attestation types see them as
     not present.
   - If a signer-bound, trusted FAILED VSA whose resource URI and subject
     match the image is found, hard reject immediately (no fallback).
   - Otherwise (no VSA, or VSAs that are untrusted, unbound, stale,
     unparsable or not bound to the image), `vsa.missingPolicy` applies:
     `deny` rejects the image, `warn` and `allow` fall through to direct
     verification.

10. **Parallel verification**: When VSA does not short-circuit, SLSA provenance,
    VEX, Notation signature, SBOM, SCAI, Source Track, Build Environment,
    Vulnerability Scan, Test Result, Release, Runtime Trace, and OpenSSF
    Scorecard checks run concurrently.

11. **CEL policy evaluation**: If the policy defines CEL rules, they are
    evaluated against the combined check results. CEL rules can enforce
    cross-check constraints (e.g., require both SLSA and VEX to pass).

12. **Enforcement**: In `enforce` mode, failed verification rejects the
    container. In `warn` mode, failures are logged but allowed. The result
    records both decisions: `allowed` (admitted) and `verified` (every check
    passed and verification ran to completion). A result whose attestations
    could not be fetched (a `fetch` check result, for example a registry
    outage, an open circuit breaker or the local concurrency limit) is never
    `verified`, even when `fetch_failure_policy` admits it; it is reported as
    incomplete instead.

13. **Caching**: The result is cached for future lookups, keyed by digest,
    namespace, image reference and matched policy rule. Results computed under
    an older policy or trust material are never reused: a policy change, a
    replaced key or certificate file, or a cache affecting config change
    starts a new cache generation, and in-flight verifications of an older
    generation are not shared with new requests. Circuit breaker open
    results are not cached, and fetch errors are cached for at most the
    circuit breaker cooldown.

The whole admission (digest resolution plus waiting for the result) is
bounded by `admission_timeout`, which must stay below the runtime's NRI
request timeout; see [config.md](config.md#admission-deadline). When the
runtime propagates its own request deadline, the plugin answers ahead of it
by a safety margin of 10% of the remaining time (at least 100ms). When the
admission timeout expires, enforce mode rejects the container while the
verification completes in the background and fills the cache. An admission
that would join a verification of the same image that has already run for
longer than `admission_timeout` does not wait for it: enforce mode rejects the
container immediately and warn mode admits it as incomplete. This keeps a slow
registry from stalling container creation on the whole node, since the runtime
serializes NRI requests; the running verification still fills the cache for
the next attempt.

Digests are taken from the runtime annotations first. When they carry none,
the digest the runtime reports for the container image is used; it can be an
image index or a manifest digest, so the plugin resolves the digest-pinned
reference against the registry to find the platform manifest (falling back to
the reported digest when the registry cannot be reached). Only when the
runtime reports no digest at all is the tag resolved. Cache pre-warming at
startup resolves images the same way, so its cache entries match admission.
If a reload between the admission's include/exclude check and the
verification makes an image require verification, the plugin resolves its
digest and verifies it instead of verifying without a digest.

**Fetch and verification failures.** Registry and network problems follow
`fetch_failure_policy` (see [config.md](config.md#fetch-failures)); only these
transport failures (connection errors, timeouts, HTTP 5xx and 429) count
toward the per-registry circuit breaker. Attestations that were found but did
not verify (for example a bundle signed by an untrusted key, or junk referrer
content) are ignored and treated like absent attestations: the `missingPolicy`
of each check type decides, and the result carries a warning `attestation`
check result describing the ignored attestations. They never follow
`fetch_failure_policy` and never open the circuit breaker, so attaching junk
referrers to an image cannot turn a denial into a lenient fetch failure, a
foreign signature does not deny an otherwise acceptable image, and junk on one
image cannot affect other images from the same registry. An incomplete
attestation set is different: when a referrer count or size limit is exceeded,
or a stored bundle blob fails its integrity check, the image is denied (a
failing `attestation` check result) regardless of `fetch_failure_policy` and
the missing policies, because a dropped attestation could flip the decision.
Trust material that cannot be loaded (a Sigstore trusted root that cannot be
fetched, an unreadable key file) is an availability problem rather than a
verification failure and follows `fetch_failure_policy`. When several trusted roots are configured, this
applies as soon as one root in scope for the attestation could not be loaded,
even if another root loaded and rejected the attestation, because the
unavailable root might have verified it. A trusted root that cannot be
fetched and has no cached or pre-seeded fallback is retried at most every 30
seconds, so verifications in a disconnected environment fail fast instead of
each waiting for the TUF repository. While the breaker is
half-open, only the single probe request decides whether it closes or opens
again; requests admitted before the breaker opened cannot release or decide
the probe.

For images resolved from a manifest list, the index digest is tried first; its
verified attestations are used when it has any, otherwise the platform digest
is fetched as well. A transport failure on either digest makes the
result follow `fetch_failure_policy`, because the full attestation set is
unknown when a registry path was unreachable. When neither digest had a
transport failure, the platform digest decides the outcome: attestations that
failed verification are treated as absent, and when the platform digest has no
attestations, the index digest's verification failures are treated as absent.
An index digest that could not be fetched (transport failure) with an empty
platform makes the result incomplete. Any other index digest error is never
dropped, even when the platform digest has attestations: an incomplete
attestation set (for example junk referrers exceeding the referrer limits)
denies, and a registry error follows `fetch_failure_policy`. A transport
failure on either digest counts toward the circuit breaker.

Latency model:

- With trusted VSA: `max(fetch, GUAC query) + VSA verify`
- Without VSA: `max(fetch, GUAC query) + max(SLSA, VEX, Notation, SBOM, SCAI, Source, BuildEnv, VulnScan, TestResult, Release, RuntimeTrace, Scorecard) + CEL eval`

When GUAC is enabled, its query runs in parallel with the OCI attestation
fetch, so it does not add latency unless the GUAC query is slower than the
fetch. When a trusted VSA short-circuits verification, the GUAC result is kept:
CEL rules evaluated for VSA-accelerated images see the VSA and GUAC results,
while the other attestation types are not present.

### Continuous Re-verification

When [remediation](config.md#remediation) is enabled, the plugin periodically
re-runs the verification flow above for all tracked containers. The
re-verification loop runs in the background at the configured interval. Timer
ticks use cached results when available; feed and manual triggers invalidate
the cache first to fetch fresh attestation data.

A container whose runtime-reported digest was not resolved against the
registry (because the image needed no verification when it started, or the
registry could not be reached) has that digest resolved before it is
re-verified. Until the registry resolves it, the container is not re-verified
and each cycle counts as an incomplete re-verification.

If a container's verification result degrades (previously passing checks now
fail), the plugin applies graduated remediation based on the configured mode.
See [config.md](config.md#remediation) for the state machine, triggers, and
throttle behavior.

## Container Annotations

In `warn` and `enforce` modes, the plugin injects annotations on each
container via the NRI `ContainerAdjustment` response. These annotations
provide per-container verification metadata that can be consumed by admission
webhooks, audit pipelines, or `kubectl describe`.

| Annotation                    | Example value        | Description                                                                                                                                            |
| ----------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `supply-chain.nri/verified`   | `true` or `false`    | Whether all checks passed. In warn mode, reflects the actual outcome even though the container is allowed.                                             |
| `supply-chain.nri/mode`       | `warn` or `enforce`  | The effective verification mode applied to this container.                                                                                             |
| `supply-chain.nri/checks`     | `slsa:pass,vex:warn` | Comma-separated `type:status` pairs for each check result. Only present when checks were run.                                                          |
| `supply-chain.nri/incomplete` | `true`               | Present when verification did not run to completion, for example when the admission timeout expired in warn mode or attestations could not be fetched. |

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
  result PASSED, signed by its verifier, exists, the plugin skips all
  parallel checks (CEL rules still run).

### SLSA Provenance

Verifies [SLSA](https://slsa.dev) provenance v1 attestations against trusted
builders and sources. When a trusted builder lists `keys` or `identities`,
provenance claiming that builder must be signed by one of them, even if another
`trust.builders` entry with the same ID is unbound; builders whose entries are
all unbound accept provenance from any trusted signer (logged once as a
warning). The source repository is read from the layout of the build type
(GitHub Actions workflows, Google Cloud Build `sourceToBuild` or
`configSource`, or a generic `source` parameter) and cross-checked against
`resolvedDependencies`.

When no trusted builders, sources, or build types are configured the check
reports `warn` instead of `pass`. The verdict is unchanged (the image is still
admitted), but the status is visible everywhere a check status is recorded: the
`supply-chain.nri/checks` container annotation shows `slsa:warn`, the audit log
and `verify` output report `warn`, and
`nri_supply_chain_verification_total{type="slsa"}` counts the check with
`result="warn"`. Dashboards or alerts that expect `slsa` to report `pass` need
to account for this, or the policy should configure a trust constraint.

When multiple attestations exist, any single valid one from a trusted builder
is sufficient (any-pass semantics). See
[policy.md](policy.md#slsa-provenance) for the full check list, field
reference, and custom build system configuration.

### VEX (Vulnerability Exploitability eXchange)

Verifies VEX documents in two formats:

- [OpenVEX](https://openvex.dev) v0.2.0
- [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/) (via CycloneDX BOM
  vulnerability entries with an `analysis.state`; entries without one are
  scanner findings gated by `sbom.cvss`)

The format is detected automatically from the predicate content; a predicate
that is neither OpenVEX nor CycloneDX fails the check. Every VEX document must
parse and bind to the image digest: a single document that fails to parse
fails the check. OpenVEX statements from all documents are merged, and for
each vulnerability the most recent statement wins, independent of statement
and document order. Across formats the most
restrictive result wins: any effective `affected`/`exploitable` status causes
failure. Documents that contain no statement about the image report the status
`no_match`, never `not_affected`. See
[policy.md](policy.md#vex-vulnerability-exploitability-exchange) for status
handling, product matching, and the field reference.

### VSA (Verification Summary Attestation)

Verifies [SLSA VSA](https://slsa.dev/spec/v1.0/verification_summary) v1
attestations. A VSA records the outcome of a prior verification performed by
a trusted verifier. The VSA must be bound to the image through a
digest-pinned `resourceUri` and a matching statement subject. A trusted PASSED
VSA short-circuits all other checks; a bound, trusted FAILED VSA is a hard
reject with no fallback. Trusted means the verifier ID is listed in
`trust.verifiers` and the attestation was signed by one of that verifier's
`keys` or `identities`; verifiers without keys or identities never
short-circuit. When no trusted VSA passes, `vsa.missingPolicy` decides
whether the image is denied or falls through to direct verification. See
[policy.md](policy.md#vsa-verification-summary-attestation) for the full
check list and field reference.

### Signature Verification

All attestations must be valid Sigstore bundles. The plugin supports keyless
(Fulcio/OIDC) and key-based (PEM public key) modes. See
[policy.md](policy.md#signature-verification) for configuration details.

The verification path is chosen by the bundle's verification material: bundles
carrying a public key hint are verified against the trusted keys, bundles
carrying a Fulcio certificate against the trusted issuers and SAN patterns.
A policy may configure both keys and issuers; each bundle is accepted when it
verifies on its own path. The identity that signed each attestation (the
trusted key path, or the certificate issuer and SAN) is recorded with the
attestation so that later checks can bind claims such as a VSA verifier ID to
the actual signer.

Key validity windows (`notBefore`/`notAfter` on a trusted verifier) are always
enforced. Keys of trusted builders (`trust.builders[].keys`) are trusted for
signature verification as well, but only for SLSA provenance: an attestation of
any other type (VEX, SBOM, VSA and so on) signed with a key that is listed only
for builders is ignored, so a provenance signing key cannot vouch for other
claims. Verifier keys are trusted for every attestation type. Without
`signatures.requireTransparencyLog`, the bundle's claimed
signing time cannot be trusted, so the window is checked against the current
time: once `notAfter` has passed, every attestation signed with that key is
rejected. With `requireTransparencyLog: true`, key-based bundles must carry a
transparency log entry that verifies against the Sigstore trusted root, and
the window is checked against the log's integrated time, so attestations
logged before `notAfter` remain valid.

The same public key may be configured at several paths, for example during
key rotation or when a verifier and a builder share key material. Each
configured path keeps its own validity window: a signature is attributed only
to the paths whose window contains the verification time, so an unbounded
entry never extends another entry's `notAfter`, and a verifier window never
restricts a builder key that has none. Signer bindings (VSA verifiers, SLSA
builders) match any of the attributed paths. A path listed by both a verifier
and a builder, which can only result from merging an inheriting namespace
policy or an image rule into its base, uses the verifier's window for the
builder as well.

Keyless bundles always have their transparency log entries verified when they
carry any; bundles without log entries must carry a trusted RFC 3161 timestamp
and are rejected when `requireTransparencyLog` is set. When several Sigstore
trusted roots are configured, a certificate is only accepted if it chains to a
root that is allowed to vouch for the certificate's issuer (see
`sigstore.roots[].issuers` in [config.md](config.md#multiple-sigstore-trusted-roots)).
The restriction also applies to a single scoped root with
`include_public_root = false`, and `issuers` set on a root entry without
`tuf_mirror` (the public Sigstore root) restrict the included public root.

### Notation (Notary v2)

Verifies container image signatures using
[Notation](https://notaryproject.dev), the CNCF Notary Project's signing
tool. The plugin validates signatures against configured trust stores and
trust policies, supporting both CA-based and signing-authority trust models.
Validations that notation-go only logs are still inspected: a logged integrity
or authenticity failure (the `audit` verification level) fails the check, the
`skip` level fails the check because nothing was verified, and logged expiry,
revocation, or timestamp failures (the `permissive` level) pass with a warning.
Verifiers are cached per policy and certificate file state, so rotated
certificates are picked up without rebuilding the verifier on every request.
See [policy.md](policy.md#notation-notary-v2-signature-verification) for
the trust store setup, verification levels, and field reference.

### SBOM (Software Bill of Materials)

Verifies SBOM attestations in [SPDX](https://spdx.dev) JSON and
[CycloneDX](https://cyclonedx.org) JSON formats. SBOMs are discovered via
in-toto predicate type routing (`https://spdx.dev/Document` for SPDX,
`https://cyclonedx.org/bom` for CycloneDX). SPDX 2.x, SPDX 3.0, and SPDX
3.0.1 (including licenses expressed through Relationship elements) are
supported. The plugin extracts package licenses (including CycloneDX license
expressions and nested components) and PURLs from the SBOM and checks them
against configurable deny and allow lists. Every SBOM document must parse; a
document that fails to parse fails the check. When baseline SBOMs are attached
to the image via the OCI Referrers API (artifact type
`application/vnd.nri-supply-chain.sbom-baseline.v1+json`, or any Sigstore
bundle referrer), the plugin compares the current SBOM against the baseline.
Baselines must be signed like any other attestation: an in-toto statement with
predicate type `https://nri-supply-chain.dev/baseline-sbom/v1`, the image
digest as subject, and the SBOM document as predicate, for example
`cosign attest --type https://nri-supply-chain.dev/baseline-sbom/v1 --predicate sbom.json`.
Unsigned baseline documents are ignored. The comparison uses PURL as the identity
key and computes a weighted drift score. Policy thresholds on added,
removed, and modified package counts, and overall score can enforce limits
on acceptable drift. When any drift threshold is configured, a missing or
unparsable baseline fails the check. See
[policy.md](policy.md#sbom-verification) for the field reference and
[policy.md](policy.md#sbomdrift-object) for drift thresholds.

### SCAI (Supply Chain Attribute Integrity)

The SCAI, Source Track, Build Environment, Vulnerability Scan, Test Result,
Release, Runtime Trace, and OpenSSF Scorecard checks reject predicates that
are empty, `null`, or missing the fields their specification requires, reject
future timestamps even without `maxAge`, and fail all-must-pass checks when
any document is invalid. See [policy.md](policy.md#predicate-validation).

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
Vulnerability scan attestations capture automated scanner results. Both the
specification layout (`scanner.result[]` with `severity[]{method, score}`, flat
or nested under `vulnerability`) and the legacy `result.vulnerabilities[]`
layout are accepted; a `result` object without a `vulnerabilities` array is
rejected rather than read as a clean scan. The plugin enforces
CVSS score and severity thresholds with an optional CVE ignore list; findings
without a recognizable severity fail closed when a threshold is set. See [policy.md](policy.md#vulnerability-scan-verification) for
the field reference.

### Test Result

Verifies [test-result v0.1](https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md)
attestations (predicate type `https://in-toto.io/attestation/test-result/v0.1`).
Test result attestations capture the outcome of automated test suites. The
plugin verifies the overall result is passing (`WARNED`, passed with warnings,
counts as passing), rejects passing results that report failed tests or suites,
and can enforce that specific suites are present and passing. See
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
neither the name nor the URI of any file access matches a forbidden pattern.
When multiple runtime
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
- **certify_scorecard**: OpenSSF Scorecard results for the source
  repositories GUAC links to the image digest, either directly
  (`IsOccurrence` of a source) or through the packages the image is an
  occurrence of (`IsOccurrence` of a package, then `HasSourceAt`). Scorecards
  of unrelated repositories are never used. Of the scans GUAC stores for a
  repository, the most recent (`timeScanned`) is used; when scans share that
  time, or a scan has no valid time, the lowest score is used. When several
  repositories are linked, the lowest aggregate score is reported; when none
  is linked the
  scorecard is empty (aggregate `0`). When more than 20 repositories or
  packages are linked, so the lowest score cannot be determined, the scorecard
  is reported as truncated (`truncated` true, aggregate `0`, source
  `guac:truncated`). Package sources and scorecards are queried concurrently
  with a bounded number of requests.
- **is_dependency**: Transitive dependency enumeration, limited by the
  `max_dependencies` config setting.

GUAC query results are exposed as CEL variables in the `guac.*` namespace (see
[policy.md](policy.md#cel-object) for the variable reference). Each query
reports its own availability (`guac.vulnerabilities_available`,
`guac.scorecard_available`, `guac.dependencies_available`), and results of
queries that succeeded are kept when another query fails. The data fields of
a query that is not enabled or failed are absent, so CEL rules that read them
fail evaluation (fail closed): the CEL check fails, which denies in enforce
mode and warns in warn mode, and the error names the `*_available` flag to
guard with. A GUAC query failure is handled according to
`fallback_policy`: `allow` (ignore the failure), `warn` (default, log and
continue), or `deny` (fail the check); with `allow` and `warn` the results of
the queries that succeeded are still exposed. `warn` and `allow` still admit
the image when GUAC is down unless a CEL rule reads the missing data, so use
`deny` in enforce mode when GUAC data is required.

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
and maintained status. The plugin binds the scored repository to
`trust.sources` when configured, rejects future dates, can enforce an aggregate
minimum and exact per-check minimum scores, and exposes the repository,
Scorecard version,
aggregate score, and check-score map to CEL. When multiple Scorecard results
exist, all must pass. See
[policy.md](policy.md#openssf-scorecard-verification) for the field reference.

## Other Standards

The supply chain ecosystem includes several related formats and frameworks
that the plugin does not currently support:

- **[SARIF](https://sarifweb.azurewebsites.net/)** (Static Analysis Results
  Interchange Format): a standardized format for security scanner results that
  could complement VEX by providing detailed finding data.
