# Policy Reference

This document covers the policy file format, field reference, and usage
patterns for the nri-supply-chain plugin.

<!-- toc -->

- [Overview](#overview)
- [Writing Your First Policy](#writing-your-first-policy)
  - [Step 1: Allow everything](#step-1-allow-everything)
  - [Step 2: Add trust roots](#step-2-add-trust-roots)
  - [Step 3: Tighten missing attestation behavior](#step-3-tighten-missing-attestation-behavior)
  - [Step 4: Add image excludes](#step-4-add-image-excludes)
- [Field Reference](#field-reference)
  - [<code>trust</code> (object)](#trust-object)
  - [<code>exclude</code> (array of strings)](#exclude-array-of-strings)
  - [<code>provenance</code> (object)](#provenance-object)
  - [<code>vex</code> (object)](#vex-object)
  - [<code>vsa</code> (object)](#vsa-object)
  - [<code>signatures</code> (object)](#signatures-object)
- [Verification Types](#verification-types)
  - [SLSA Provenance](#slsa-provenance)
    - [Custom build systems](#custom-build-systems)
  - [VEX (Vulnerability Exploitability eXchange)](#vex-vulnerability-exploitability-exchange)
  - [VSA (Verification Summary Attestation)](#vsa-verification-summary-attestation)
  - [Signature Verification](#signature-verification)
- [Pattern Matching](#pattern-matching)
  - [<code>exclude</code> and <code>trust.sources</code>](#exclude-and-trustsources)
  - [<code>trust.sanPatterns</code>](#trustsanpatterns)
- [Namespace Overrides](#namespace-overrides)
- [Deployment Patterns](#deployment-patterns)
  - [Gradual rollout](#gradual-rollout)
  - [VSA-accelerated verification](#vsa-accelerated-verification)
  - [Multi-verification mode](#multi-verification-mode)

<!-- /toc -->

## Overview

Policy files are JSON documents stored in the `policy_dir` configured in the
operational config (default: `/etc/nri-supply-chain/policies`). They define
per-namespace trust roots and verification requirements.

- **`default.json`** applies to all namespaces unless overridden.
- **`<namespace>.json`** overrides the default for that namespace. By default,
  this is a full replacement. Set `"inherits": true` to inherit unset fields
  from the default policy (see [Namespace Overrides](#namespace-overrides)).
- Files are parsed with strict mode (`DisallowUnknownFields`). Any
  unrecognized field causes a parse error.
- An empty policy `{}` allows all containers without verification.

## Writing Your First Policy

Start with an empty policy and incrementally add restrictions.

### Step 1: Allow everything

```json
{}
```

This is useful for initial deployment in `warn` mode to observe what the plugin
sees without blocking anything.

### Step 2: Add trust roots

Define which builders and issuers you trust. For GitHub Actions with keyless
(Fulcio) verification:

```json
{
  "trust": {
    "builders": [
      {
        "id": "https://github.com/actions/runner",
        "maxLevel": 3
      }
    ],
    "issuers": ["https://token.actions.githubusercontent.com"],
    "sanPatterns": ["https://github.com/myorg/*"],
    "sources": ["github.com/myorg/*"]
  }
}
```

For key-based verification with a local public key:

```json
{
  "trust": {
    "verifiers": [
      {
        "id": "my-verifier",
        "key": "/etc/nri-supply-chain/keys/cosign.pub"
      }
    ]
  }
}
```

### Step 3: Tighten missing attestation behavior

By default, missing provenance and VEX attestations are allowed. To require
provenance:

```json
{
  "trust": {
    "builders": [
      {
        "id": "https://github.com/actions/runner",
        "maxLevel": 3
      }
    ],
    "issuers": ["https://token.actions.githubusercontent.com"],
    "sanPatterns": ["https://github.com/myorg/*"]
  },
  "provenance": {
    "missingPolicy": "deny"
  },
  "vex": {
    "missingPolicy": "allow"
  }
}
```

### Step 4: Add image excludes

Skip verification for known base images or internal tooling:

```json
{
  "exclude": ["gcr.io/distroless/*", "registry.k8s.io/pause:*"],
  "trust": {
    "builders": [
      {
        "id": "https://github.com/actions/runner",
        "maxLevel": 3
      }
    ],
    "issuers": ["https://token.actions.githubusercontent.com"],
    "sanPatterns": ["https://github.com/myorg/*"]
  },
  "provenance": {
    "missingPolicy": "deny"
  }
}
```

## Field Reference

### `trust` (object)

Trust roots for verification. All sub-fields are optional.

| Field         | Type  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------- | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `builders`    | array | Trusted SLSA provenance builders. Each entry has `id` (URI) and `maxLevel` (0-3). Note: `maxLevel` is only enforced by VSA verification (`vsa.minimumLevel`), not during SLSA provenance checks, because provenance attestations do not declare a build level.                                                                                                                                                                                                                                |
| `verifiers`   | array | Trusted VSA verifiers. Each entry has `id` (URI) and `key` (absolute path to PEM public key). The key is also used for Sigstore bundle signature verification.                                                                                                                                                                                                                                                                                                                                |
| `issuers`     | array | Trusted OIDC issuers for keyless (Fulcio) verification.                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `sanPatterns` | array | Accepted certificate Subject Alternative Names. Supports glob patterns: `*` matches any non-`/` sequence, `**` matches any characters including `/`, `?` matches a single non-`/` character, `[...]` matches a character class. Use `**` for GitHub Actions OIDC SANs that include workflow paths (e.g., `https://github.com/org/repo/**`). Required when `issuers` is set in `enforce` mode. In `warn` mode, omitting this field accepts any SAN from a trusted issuer (with a log warning). |
| `sources`     | array | Allowed source repository glob patterns (Go `path.Match` syntax).                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `buildTypes`  | array | Accepted build type URIs for SLSA provenance.                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### `exclude` (array of strings)

Glob patterns for images that skip verification entirely. Uses Go `path.Match`
semantics where `*` matches any non-`/` sequence.

### `provenance` (object)

SLSA provenance verification settings.

| Field                     | Type   | Default     | Description                                                                                                                                                                                                             |
| ------------------------- | ------ | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `missingPolicy`           | string | `allow`     | Behavior when no provenance is found: `allow`, `warn`, `deny`                                                                                                                                                           |
| `rejectUnknownParameters` | bool   | `false`     | Reject provenance with unrecognized `externalParameters` fields                                                                                                                                                         |
| `knownParameters`         | array  | (see below) | Recognized `externalParameters` keys when `rejectUnknownParameters` is true. Defaults to the GitHub Actions set: `source`, `repository`, `ref`, `workflow`, `buildType`. Set this for non-GitHub Actions build systems. |

### `vex` (object)

OpenVEX verification settings.

| Field                      | Type   | Default | Description                                                        |
| -------------------------- | ------ | ------- | ------------------------------------------------------------------ |
| `missingPolicy`            | string | `allow` | Behavior when no VEX attestation is found: `allow`, `warn`, `deny` |
| `underInvestigationPolicy` | string | `allow` | Behavior for `under_investigation` status: `allow`, `warn`, `deny` |

### `vsa` (object)

Verification Summary Attestation settings.

| Field          | Type   | Default | Description                                                 |
| -------------- | ------ | ------- | ----------------------------------------------------------- |
| `minimumLevel` | int    | `0`     | Minimum SLSA build level required (0-3)                     |
| `maxAge`       | string | (none)  | Maximum age of VSA `timeVerified` (Go duration, e.g. `24h`) |
| `policy`       | string | (none)  | Expected policy URI in the VSA                              |

### `signatures` (object)

Attestation signature verification settings.

| Field                    | Type | Default | Description                                                         |
| ------------------------ | ---- | ------- | ------------------------------------------------------------------- |
| `requireTransparencyLog` | bool | `false` | Require Rekor transparency log inclusion for attestation signatures |

## Verification Types

### SLSA Provenance

Verifies [SLSA](https://slsa.dev) provenance v1 attestations. Checks
performed:

- **Subject digest**: The provenance `subject[].digest` must match the image
  digest.
- **Builder trust**: `runDetails.builder.id` must appear in the policy's
  `trust.builders` list.
- **Build type**: If `trust.buildTypes` is configured, the
  `buildDefinition.buildType` must match one of the allowed types.
- **Source repository**: If `trust.sources` is configured, the `source` in
  `externalParameters` must match an allowed glob pattern.
- **Unknown parameters**: If `provenance.rejectUnknownParameters` is enabled,
  unrecognized `externalParameters` fields cause rejection. The recognized set
  defaults to GitHub Actions parameters (`source`, `repository`, `ref`,
  `workflow`, `buildType`) but can be overridden with `provenance.knownParameters`.

Note: `trust.builders[].maxLevel` is not checked during provenance
verification. SLSA provenance does not declare a build level; levels are a
property of the builder's infrastructure. Use `vsa.minimumLevel` to enforce
build level requirements via VSA verification.

When multiple provenance attestations exist, verification passes if any single
valid attestation from a trusted builder passes (any-pass semantics).

#### Custom build systems

For build systems other than GitHub Actions, configure `knownParameters` to
list the expected `externalParameters` keys:

```json
{
  "trust": {
    "builders": [
      {
        "id": "https://builder.example.com/tekton",
        "maxLevel": 2
      }
    ],
    "buildTypes": ["https://tekton.dev/chains/v2"]
  },
  "provenance": {
    "rejectUnknownParameters": true,
    "knownParameters": ["git-url", "git-commit", "pipeline-name"]
  }
}
```

### VEX (Vulnerability Exploitability eXchange)

Verifies [OpenVEX](https://openvex.dev) v0.2.0 documents.

Status handling:

- `not_affected` or `fixed`: pass
- `affected`: fail
- `under_investigation`: controlled by `underInvestigationPolicy` (default:
  allow)

Product matching operates at the image level using digest comparison and PURL
(`pkg:oci/...`) matching.

When multiple VEX documents exist, the most restrictive result wins: any
`affected` status causes failure regardless of other documents.

### VSA (Verification Summary Attestation)

Verifies [SLSA VSA](https://slsa.dev/spec/v1.0/verification_summary) v1
attestations. Checks performed:

- **Verifier trust**: `verifier.id` must appear in `trust.verifiers`.
- **Verification result**: `PASSED` is required. `FAILED` from a trusted
  verifier is a hard reject that prevents fallback to SLSA/VEX.
- **Build level**: `verifiedLevels` must meet the `vsa.minimumLevel` threshold.
- **Resource URI**: `resourceUri` must match the image reference.
- **SLSA version**: `slsaVersion` must be >= `1.0`.
- **Policy match**: If `vsa.policy` is configured, `policy.uri` must match.
- **Freshness**: `timeVerified` must be within the `vsa.maxAge` window.

VSA-first logic:

- Trusted PASSED: short-circuits all other checks.
- Trusted FAILED: hard reject, no fallback allowed.
- Untrusted, stale, or missing: falls through to direct SLSA + VEX
  verification.

### Signature Verification

The plugin supports two verification modes that can be used independently or
together:

**Keyless (Fulcio)**: Uses OIDC identity. Configure `trust.issuers` with
trusted identity providers. In `enforce` mode, `trust.sanPatterns` is required
to restrict accepted certificate SANs. In `warn` mode, omitting `sanPatterns`
accepts any SAN from a trusted issuer (with a log warning). Requires the
Sigstore public-good instance (Fulcio + Rekor).

**Key-based**: Uses a local PEM public key. Configure `trust.verifiers` with
the verifier ID and key path. Does not require network access to Sigstore
infrastructure.

When `signatures.requireTransparencyLog` is true, attestations must include a
valid Rekor transparency log entry. This is recommended for keyless
verification and optional for key-based.

## Pattern Matching

The plugin uses glob patterns in several contexts, with slightly different
semantics:

### `exclude` and `trust.sources`

These use Go `path.Match` semantics:

- `*` matches any sequence of non-`/` characters
- `?` matches any single non-`/` character
- `[abc]` matches any character in the set
- `**` (globstar) is **not** supported

Patterns are matched against the full image reference as received from the
container runtime, including registry and path components. Patterns must
account for the full registry/namespace/image depth. For example,
`registry.io/org/*` matches `registry.io/org/repo` but not
`registry.io/org/team/repo`. Use multiple patterns for nested paths.

Common mistake: writing `nginx:*` as an exclude pattern will not match
`docker.io/library/nginx:latest` because `*` does not cross `/` boundaries.
Use the full reference `docker.io/library/nginx:*` instead.

### `trust.sanPatterns`

SAN patterns support glob-style wildcards that are converted to regular
expressions for certificate matching:

- `*` matches any sequence of non-`/` characters
- `?` matches any single non-`/` character
- `[...]` character classes are supported (including negation with `[^...]`)
- All other characters are treated as literals

Example: `https://github.com/myorg/*` matches `https://github.com/myorg/repo`
but not `https://github.com/myorg/repo/.github/workflows/build.yaml@refs/heads/main`
(the `*` does not cross `/` boundaries). For GitHub Actions workflow SANs, use
a more specific pattern like
`https://github.com/myorg/repo/.github/workflows/*`.

## Namespace Overrides

A file named `<namespace>.json` in the policy directory overrides
`default.json` for pods in that namespace.

By default, the override is a full replacement. If a namespace policy sets
`"inherits": true`, unset top-level fields (`trust`, `exclude`, `provenance`,
`vex`, `vsa`, `signatures`) are inherited from the default policy. Each
top-level section that is set in the namespace policy replaces the default's
section entirely. The default policy itself cannot set `inherits`.

This is useful for:

- Relaxing verification in development namespaces
- Applying stricter policies to production namespaces
- Using different trust roots per team
- Overriding a single section while inheriting the rest

Example: `default.json` requires provenance, but `dev.json` allows everything:

**`default.json`**:

```json
{
  "trust": {
    "builders": [
      {
        "id": "https://github.com/actions/runner",
        "maxLevel": 3
      }
    ]
  },
  "provenance": {
    "missingPolicy": "deny"
  }
}
```

**`dev.json`** (full replacement for the `dev` namespace, trust roots from
`default.json` do not apply):

```json
{
  "provenance": {
    "missingPolicy": "allow"
  },
  "vex": {
    "missingPolicy": "allow"
  }
}
```

**`staging.json`** (inherits trust roots from default, overrides VEX only):

```json
{
  "inherits": true,
  "vex": {
    "missingPolicy": "warn",
    "underInvestigationPolicy": "allow"
  }
}
```

In this example, `staging.json` inherits `trust`, `exclude`, `provenance`,
`vsa`, and `signatures` from `default.json` but replaces the `vex` section.

## Deployment Patterns

### Gradual rollout

Start with `warn` mode in the operational config and permissive policies to
observe what would be blocked:

```toml
verification = "warn"
fetch_failure_policy = "allow"
```

```json
{
  "provenance": {
    "missingPolicy": "warn"
  },
  "vex": {
    "missingPolicy": "allow"
  }
}
```

Review the logs, then progressively tighten: add trust roots, switch
`missingPolicy` to `deny`, and finally set `verification = "enforce"`.

### VSA-accelerated verification

Use a trusted verifier to pre-verify images. When a valid VSA exists,
verification completes with a single attestation check instead of fetching and
verifying SLSA + VEX individually:

```json
{
  "trust": {
    "builders": [
      {
        "id": "https://github.com/actions/runner",
        "maxLevel": 3
      }
    ],
    "verifiers": [
      {
        "id": "https://verifier.internal/prod",
        "key": "/etc/nri-supply-chain/keys/verifier.pub"
      }
    ]
  },
  "provenance": {
    "missingPolicy": "deny"
  },
  "vsa": {
    "minimumLevel": 2,
    "maxAge": "12h",
    "policy": "https://example.com/strict-policy"
  }
}
```

### Multi-verification mode

Combine key-based and keyless verification for images from different sources.
The plugin tries both modes; either can satisfy the policy:

```json
{
  "trust": {
    "verifiers": [
      {
        "id": "internal-signer",
        "key": "/etc/nri-supply-chain/keys/cosign.pub"
      }
    ],
    "issuers": ["https://token.actions.githubusercontent.com"],
    "sanPatterns": ["https://github.com/myorg/*"],
    "sources": ["github.com/myorg/*"]
  },
  "provenance": {
    "missingPolicy": "deny"
  },
  "signatures": {
    "requireTransparencyLog": false
  }
}
```
