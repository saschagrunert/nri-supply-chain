# Policy Reference

This document covers the policy file format, field reference, and usage
patterns for the nri-supply-chain plugin.

<!-- toc -->

- [Overview](#overview)
- [Writing Your First Policy](#writing-your-first-policy)
  - [Step 1: Allow everything](#step-1-allow-everything)
  - [Step 2: Add trust roots](#step-2-add-trust-roots)
  - [Step 3: Tighten missing attestation behavior](#step-3-tighten-missing-attestation-behavior)
  - [Step 4: Add image includes and excludes](#step-4-add-image-includes-and-excludes)
- [JSON Schema](#json-schema)
- [Field Reference](#field-reference)
  - [<code>mode</code> (string)](#mode-string)
  - [<code>inherits</code> (boolean)](#inherits-boolean)
  - [<code>trust</code> (object)](#trust-object)
  - [<code>include</code> (array of strings)](#include-array-of-strings)
  - [<code>exclude</code> (array of strings)](#exclude-array-of-strings)
  - [<code>slsa</code> (object)](#slsa-object)
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
  - [<code>include</code>, <code>exclude</code>, and <code>trust.sources</code>](#include-exclude-and-trustsources)
  - [<code>trust.sanPatterns</code>](#trustsanpatterns)
- [Namespace Overrides](#namespace-overrides)
- [Deployment Patterns](#deployment-patterns)
  - [Gradual rollout](#gradual-rollout)
  - [VSA-accelerated verification](#vsa-accelerated-verification)
  - [Key rotation](#key-rotation)
  - [Multi-verification mode](#multi-verification-mode)

<!-- /toc -->

## Overview

Policy files are JSON documents stored in the `policy_dir` configured in the
operational config (default: `/etc/nri-supply-chain/policies`). They define
per-namespace trust roots and verification requirements.

- **`default.json`** applies to all namespaces unless overridden. Note that
  `default.json` is the fallback policy, not a namespace-specific policy for
  the Kubernetes `default` namespace. Because the filename is reserved, the
  `default` namespace always uses the fallback policy and cannot have a
  separate override.
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
        "keys": ["/etc/nri-supply-chain/keys/cosign.pub"]
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
  "slsa": {
    "missingPolicy": "deny"
  },
  "vex": {
    "missingPolicy": "allow"
  }
}
```

### Step 4: Add image includes and excludes

Restrict verification to specific images with `include`, and skip known
base images or internal tooling with `exclude`:

```json
{
  "include": ["docker.io/myorg/**"],
  "exclude": ["docker.io/myorg/internal/*"],
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
  "slsa": {
    "missingPolicy": "deny"
  }
}
```

When `include` is set, only images matching at least one pattern are verified.
Images that do not match any `include` pattern are allowed without
verification. When `include` is empty or omitted, all images are eligible
for verification (the default behavior). If both `include` and `exclude`
are configured, `exclude` takes precedence: an image matching both is
skipped.

## JSON Schema

The full JSON Schema for policy files can be printed with:

```console
nri-supply-chain --json-schema policy
```

<details>
<summary>JSON Schema output</summary>

<!-- jsonschema-start -->

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/Policy",
  "$defs": {
    "Policy": {
      "properties": {
        "mode": {
          "type": "string",
          "enum": ["disabled", "warn", "enforce"]
        },
        "inherits": {
          "type": "boolean"
        },
        "trust": {
          "$ref": "#/$defs/TrustPolicy"
        },
        "include": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "exclude": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "slsa": {
          "$ref": "#/$defs/SLSAPolicy"
        },
        "vex": {
          "$ref": "#/$defs/VEXPolicy"
        },
        "vsa": {
          "$ref": "#/$defs/VSAPolicy"
        },
        "signatures": {
          "$ref": "#/$defs/SignaturesPolicy"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "SLSAPolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string"
        },
        "rejectUnknownParameters": {
          "type": "boolean"
        },
        "knownParameters": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "SignaturesPolicy": {
      "properties": {
        "requireTransparencyLog": {
          "type": "boolean"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "TrustPolicy": {
      "properties": {
        "builders": {
          "items": {
            "$ref": "#/$defs/TrustedBuilder"
          },
          "type": "array"
        },
        "verifiers": {
          "items": {
            "$ref": "#/$defs/TrustedVerifier"
          },
          "type": "array"
        },
        "issuers": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "sanPatterns": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "sources": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "buildTypes": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "TrustedBuilder": {
      "properties": {
        "id": {
          "type": "string"
        },
        "maxLevel": {
          "type": "integer"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": ["id", "maxLevel"]
    },
    "TrustedVerifier": {
      "properties": {
        "id": {
          "type": "string"
        },
        "keys": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": ["id"]
    },
    "VEXPolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string"
        },
        "underInvestigationPolicy": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "VSAPolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string"
        },
        "minimumLevel": {
          "type": "integer"
        },
        "maxAge": {
          "type": "string"
        },
        "policy": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object"
    }
  },
  "title": "nri-supply-chain Policy",
  "description": "Defines the trust roots and per-namespace verification settings for nri-supply-chain."
}
```

<!-- jsonschema-end -->

</details>

## Field Reference

### `mode` (string)

Overrides the global `verification` mode for this namespace. Valid values:
`"disabled"`, `"warn"`, `"enforce"`. When empty or omitted, the global mode
from the operational config applies.

The per-namespace mode can only be equal to or stricter than the global mode.
Strictness order: `disabled` < `warn` < `enforce`. For example, global `warn`
with a namespace `enforce` is valid, but global `enforce` with a namespace
`warn` is rejected at startup.

When set on `default.json`, the mode applies to all namespaces that fall
back to the default policy (i.e., namespaces without their own policy file).

This is useful for gradually rolling out enforcement: set the global mode to
`warn` and promote individual namespaces to `enforce` as confidence grows.

### `inherits` (boolean)

When set to `true` on a namespace policy (`<namespace>.json`), unset fields
are inherited from `default.json` instead of using empty defaults. Only valid
on namespace policies; the default policy cannot set `inherits`.

### `trust` (object)

Trust roots for verification. All sub-fields are optional.

| Field         | Type  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------- | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `builders`    | array | Trusted SLSA provenance builders. Each entry has `id` (URI) and `maxLevel` (0-3). Builder IDs must be unique within a policy. Note: `maxLevel` is only enforced by VSA verification (`vsa.minimumLevel`), not during SLSA provenance checks, because provenance attestations do not declare a build level.                                                                                                                                                                                    |
| `verifiers`   | array | Trusted VSA verifiers. Each entry has `id` (URI) and an optional `keys` (array of absolute paths to PEM public keys). Verifier IDs must be unique within a policy. When `keys` is set, the keys are used for Sigstore bundle signature verification. Use `keys` for key rotation so that both old and new keys are accepted simultaneously. When `keys` is empty or omitted, bundles are verified via keyless (Fulcio/OIDC) using `issuers` and `sanPatterns`, which must be configured.      |
| `issuers`     | array | Trusted OIDC issuers for keyless (Fulcio) verification.                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `sanPatterns` | array | Accepted certificate Subject Alternative Names. Supports glob patterns: `*` matches any non-`/` sequence, `**` matches any characters including `/`, `?` matches a single non-`/` character, `[...]` matches a character class. Use `**` for GitHub Actions OIDC SANs that include workflow paths (e.g., `https://github.com/org/repo/**`). Required when `issuers` is set in `enforce` mode. In `warn` mode, omitting this field accepts any SAN from a trusted issuer (with a log warning). |
| `sources`     | array | Allowed source repository glob patterns. Supports the same glob syntax as `sanPatterns`: `*` matches non-`/` characters, `**` matches any characters including `/`.                                                                                                                                                                                                                                                                                                                           |
| `buildTypes`  | array | Accepted build type URIs for SLSA provenance.                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### `include` (array of strings)

Glob patterns for images that require verification. When set, only images
matching at least one pattern are verified; all others are allowed without
verification. When empty or omitted, all images are eligible for verification
(the default). Uses the same glob syntax as `exclude`: `*` matches any
non-`/` sequence, `**` matches any characters including `/`. If both
`include` and `exclude` are set, `exclude` takes precedence.

### `exclude` (array of strings)

Glob patterns for images that skip verification entirely. `*` matches any
non-`/` sequence (single path segment), `**` matches any characters including
`/` (multiple segments). For example, `registry.k8s.io/**` excludes all images
under `registry.k8s.io` regardless of nesting depth.

### `slsa` (object)

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

| Field           | Type   | Default | Description                                                                             |
| --------------- | ------ | ------- | --------------------------------------------------------------------------------------- |
| `missingPolicy` | string | `allow` | Behavior when no VSA attestation is found: `allow`, `warn`, `deny`                      |
| `minimumLevel`  | int    | `0`     | Minimum SLSA build level required (0-3)                                                 |
| `maxAge`        | string | (none)  | Maximum age of VSA `timeVerified` (Go duration, e.g. `24h`). Must be positive when set. |
| `policy`        | string | (none)  | Expected policy URI in the VSA                                                          |

### `signatures` (object)

Attestation signature verification settings. All attestations require a valid
Sigstore bundle signature regardless of these settings. Unsigned attestations
are dropped during the fetch phase. If all bundles fail verification, the
result is governed by `fetch_failure_policy`. If no verified attestation of a
given type remains, the per-type `missingPolicy` applies.

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
- **Unknown parameters**: If `slsa.rejectUnknownParameters` is enabled,
  unrecognized `externalParameters` fields cause rejection. The recognized set
  defaults to GitHub Actions parameters (`source`, `repository`, `ref`,
  `workflow`, `buildType`) but can be overridden with `slsa.knownParameters`.

Note: `trust.builders[].maxLevel` is not checked during provenance
verification. SLSA provenance does not declare a build level; levels are a
property of the builder's infrastructure. Use `vsa.minimumLevel` to enforce
build level requirements via VSA verification.

When multiple provenance attestations exist, verification passes if any single
valid attestation from a trusted builder passes (any-pass semantics).

If all provenance attestations fail to parse or verify (as opposed to being
absent), the check always fails regardless of `missingPolicy`. The
`missingPolicy` setting only controls behavior when no provenance attestation
exists at all.

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
  "slsa": {
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

If all VEX documents fail to parse or verify (as opposed to being absent),
the check always fails regardless of `missingPolicy`. The `missingPolicy`
setting only controls behavior when no VEX attestation exists at all.

### VSA (Verification Summary Attestation)

Verifies [SLSA VSA](https://slsa.dev/spec/v1.0/verification_summary) v1
attestations. A VSA records the outcome of a prior SLSA and VEX verification
performed by a trusted verifier, allowing the plugin to skip those checks when
the VSA is trusted and PASSED. Checks performed:

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
- Untrusted or stale: falls through to direct SLSA + VEX verification.
- Missing: controlled by `vsa.missingPolicy`. When set to `allow` (the
  default) or left empty, falls through to direct SLSA + VEX verification.
  When set to `warn`, allows with a warning. When set to `deny`, rejects
  immediately without fallback.

### Signature Verification

All attestations must be valid [Sigstore](https://sigstore.dev) bundles with a
verified signature. Unsigned or incorrectly signed attestations are dropped
during the fetch phase and never reach SLSA, VEX, or VSA verification. If all
discovered bundles fail signature verification, the fetch is treated as a
failure and handled according to the `fetch_failure_policy` in the
[operational config](config.md). If some bundles verify and others do not, only
the verified ones are used (invalid bundles are logged and discarded).

The plugin supports two verification modes that can be used independently or
together:

**Keyless (Fulcio)**: Uses OIDC identity. Configure `trust.issuers` with
trusted identity providers. In `enforce` mode, `trust.sanPatterns` is required
to restrict accepted certificate SANs. In `warn` mode, omitting `sanPatterns`
accepts any SAN from a trusted issuer (with a log warning). Requires the
Sigstore public-good instance (Fulcio + Rekor).

**Key-based**: Uses local PEM public keys. Configure `trust.verifiers` with
the verifier ID and `keys` paths. Does not require network access to Sigstore
infrastructure.

When `signatures.requireTransparencyLog` is true, attestations must include a
valid Rekor transparency log entry. This is recommended for keyless
verification and optional for key-based.

## Pattern Matching

The plugin uses glob patterns in several contexts, with slightly different
semantics:

### `include`, `exclude`, and `trust.sources`

These fields support glob patterns with the same syntax as `sanPatterns`:

- `*` matches any sequence of non-`/` characters (single path segment)
- `**` matches any characters including `/` (multiple path segments)
- `?` matches any single non-`/` character
- `[abc]` matches any character in the set

Patterns are matched against the full image reference as received from the
container runtime, including registry and path components. For example,
`registry.io/org/*` matches `registry.io/org/repo` but not
`registry.io/org/team/repo`. Use `registry.io/org/**` to match any nesting
depth.

Common mistake: writing `nginx:*` as an exclude pattern will not match
`docker.io/library/nginx:latest` because `*` does not cross `/` boundaries.
Use the full reference `docker.io/library/nginx:*` instead.

### `trust.sanPatterns`

SAN patterns support glob-style wildcards that are converted to regular
expressions for certificate matching:

- `*` matches any sequence of non-`/` characters
- `**` matches any characters including `/`
- `?` matches any single non-`/` character
- `[...]` character classes are supported (including negation with `[^...]`)
- All other characters are treated as literals

Example: `https://github.com/myorg/*` matches `https://github.com/myorg/repo`
but not `https://github.com/myorg/repo/.github/workflows/build.yaml@refs/heads/main`
(the `*` does not cross `/` boundaries). Use `**` for GitHub Actions workflow
SANs that include nested paths, for example
`https://github.com/myorg/repo/**`.

## Namespace Overrides

A file named `<namespace>.json` in the policy directory overrides
`default.json` for pods in that namespace.

By default, the override is a full replacement. If a namespace policy sets
`"inherits": true`, unset top-level fields (`trust`, `include`, `exclude`,
`slsa`, `vex`, `vsa`, `signatures`) are inherited from the default policy. Each
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
  "slsa": {
    "missingPolicy": "deny"
  }
}
```

**`dev.json`** (full replacement for the `dev` namespace, trust roots from
`default.json` do not apply):

```json
{
  "slsa": {
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

In this example, `staging.json` inherits `trust`, `include`, `exclude`,
`slsa`, `vsa`, and `signatures` from `default.json` but replaces the `vex`
section.

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
  "slsa": {
    "missingPolicy": "warn"
  },
  "vex": {
    "missingPolicy": "allow"
  }
}
```

Review the logs, then progressively tighten: add trust roots, switch
`missingPolicy` to `deny`, and finally set `verification = "enforce"`.

You can also promote individual namespaces to `enforce` while the global mode
remains `warn`, using the per-namespace `mode` field:

**`production.json`** (enforce for production while the cluster is still in
warn mode):

```json
{
  "mode": "enforce",
  "slsa": {
    "missingPolicy": "deny"
  }
}
```

**`staging.json`** (inherits defaults, stays in global warn mode):

```json
{
  "inherits": true,
  "slsa": {
    "missingPolicy": "warn"
  }
}
```

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
        "keys": ["/etc/nri-supply-chain/keys/verifier.pub"]
      }
    ]
  },
  "slsa": {
    "missingPolicy": "deny"
  },
  "vsa": {
    "minimumLevel": 2,
    "maxAge": "12h",
    "policy": "https://example.com/strict-policy"
  }
}
```

### Key rotation

During key rotation, configure `keys` to accept both the old and new verifier
keys simultaneously. Attestations signed by either key are accepted:

```json
{
  "trust": {
    "verifiers": [
      {
        "id": "https://verifier.internal/prod",
        "keys": [
          "/etc/nri-supply-chain/keys/verifier-2024.pub",
          "/etc/nri-supply-chain/keys/verifier-2025.pub"
        ]
      }
    ]
  },
  "slsa": {
    "missingPolicy": "deny"
  }
}
```

Once all attestations have been re-signed with the new key, remove the old key
from the `keys` list.

### Multi-verification mode

Combine key-based and keyless verification for images from different sources.
The plugin tries both modes; either can satisfy the policy:

```json
{
  "trust": {
    "verifiers": [
      {
        "id": "internal-signer",
        "keys": ["/etc/nri-supply-chain/keys/cosign.pub"]
      }
    ],
    "issuers": ["https://token.actions.githubusercontent.com"],
    "sanPatterns": ["https://github.com/myorg/*"],
    "sources": ["github.com/myorg/*"]
  },
  "slsa": {
    "missingPolicy": "deny"
  },
  "signatures": {
    "requireTransparencyLog": false
  }
}
```
