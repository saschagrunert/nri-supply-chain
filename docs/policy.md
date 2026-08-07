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
  - [<code>notation</code> (object)](#notation-object)
  - [<code>sbom</code> (object)](#sbom-object)
    - [<code>sbom.license</code> (object)](#sbomlicense-object)
    - [<code>sbom.component</code> (object)](#sbomcomponent-object)
    - [<code>sbom.cvss</code> (object)](#sbomcvss-object)
  - [<code>rules</code> (array of objects)](#rules-array-of-objects)
  - [<code>cel</code> (object)](#cel-object)
- [Verification Types](#verification-types)
  - [SLSA Provenance](#slsa-provenance)
    - [Custom build systems](#custom-build-systems)
  - [VEX (Vulnerability Exploitability eXchange)](#vex-vulnerability-exploitability-exchange)
  - [VSA (Verification Summary Attestation)](#vsa-verification-summary-attestation)
  - [Signature Verification](#signature-verification)
  - [Notation (Notary v2) Signature Verification](#notation-notary-v2-signature-verification)
  - [SBOM Verification](#sbom-verification)
- [Pattern Matching](#pattern-matching)
  - [<code>include</code>, <code>exclude</code>, and <code>trust.sources</code>](#include-exclude-and-trustsources)
  - [<code>trust.sanPatterns</code>](#trustsanpatterns)
- [Namespace Overrides](#namespace-overrides)
- [Deployment Patterns](#deployment-patterns)
  - [Gradual rollout](#gradual-rollout)
  - [Per-image policy rules](#per-image-policy-rules)
  - [VSA-accelerated verification](#vsa-accelerated-verification)
  - [Key rotation](#key-rotation)
  - [Multi-verification mode](#multi-verification-mode)
- [Example Policy Files](#example-policy-files)

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
- As an alternative to local files, policies can be distributed as OCI
  artifacts stored in a container registry. See the
  [Policy Distribution](config.md#policy-distribution) section in the
  configuration reference.

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
nri-supply-chain json-schema policy
```

<details>
<summary>JSON Schema output</summary>

<!-- jsonschema-start -->

```json
{
  "$defs": {
    "CELPolicy": {
      "additionalProperties": false,
      "properties": {
        "rules": {
          "items": {
            "$ref": "#/$defs/CELRule"
          },
          "type": "array"
        }
      },
      "required": ["rules"],
      "type": "object"
    },
    "CELRule": {
      "additionalProperties": false,
      "properties": {
        "match": {
          "type": "string"
        },
        "message": {
          "type": "string"
        },
        "require": {
          "type": "string"
        }
      },
      "required": ["require"],
      "type": "object"
    },
    "ImageRule": {
      "additionalProperties": false,
      "properties": {
        "cel": {
          "$ref": "#/$defs/CELPolicy"
        },
        "images": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "notation": {
          "$ref": "#/$defs/NotationPolicy"
        },
        "sbom": {
          "$ref": "#/$defs/SBOMPolicy"
        },
        "signatures": {
          "$ref": "#/$defs/SignaturesPolicy"
        },
        "slsa": {
          "$ref": "#/$defs/SLSAPolicy"
        },
        "trust": {
          "$ref": "#/$defs/TrustPolicy"
        },
        "vex": {
          "$ref": "#/$defs/VEXPolicy"
        },
        "vsa": {
          "$ref": "#/$defs/VSAPolicy"
        }
      },
      "required": ["images"],
      "type": "object"
    },
    "NotationPolicy": {
      "additionalProperties": false,
      "properties": {
        "missingPolicy": {
          "enum": ["allow", "warn", "deny"],
          "type": "string"
        },
        "trustPolicy": {
          "items": {
            "$ref": "#/$defs/NotationTrustPolicyRule"
          },
          "type": "array"
        },
        "trustStores": {
          "items": {
            "$ref": "#/$defs/NotationTrustStore"
          },
          "type": "array"
        },
        "verificationLevel": {
          "enum": ["strict", "permissive", "audit", "skip"],
          "type": "string"
        }
      },
      "type": "object"
    },
    "NotationTrustPolicyRule": {
      "additionalProperties": false,
      "properties": {
        "name": {
          "type": "string"
        },
        "registryScopes": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "trustStores": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "trustedIdentities": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "required": [
        "name",
        "registryScopes",
        "trustStores",
        "trustedIdentities"
      ],
      "type": "object"
    },
    "NotationTrustStore": {
      "additionalProperties": false,
      "properties": {
        "certificates": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "name": {
          "type": "string"
        },
        "type": {
          "type": "string"
        }
      },
      "required": ["name", "type", "certificates"],
      "type": "object"
    },
    "Policy": {
      "additionalProperties": false,
      "properties": {
        "cel": {
          "$ref": "#/$defs/CELPolicy"
        },
        "exclude": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "include": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "inherits": {
          "type": "boolean"
        },
        "mode": {
          "enum": ["disabled", "warn", "enforce"],
          "type": "string"
        },
        "notation": {
          "$ref": "#/$defs/NotationPolicy"
        },
        "rules": {
          "items": {
            "$ref": "#/$defs/ImageRule"
          },
          "type": "array"
        },
        "sbom": {
          "$ref": "#/$defs/SBOMPolicy"
        },
        "signatures": {
          "$ref": "#/$defs/SignaturesPolicy"
        },
        "slsa": {
          "$ref": "#/$defs/SLSAPolicy"
        },
        "trust": {
          "$ref": "#/$defs/TrustPolicy"
        },
        "vex": {
          "$ref": "#/$defs/VEXPolicy"
        },
        "vsa": {
          "$ref": "#/$defs/VSAPolicy"
        }
      },
      "type": "object"
    },
    "SBOMCVSSPolicy": {
      "additionalProperties": false,
      "properties": {
        "ignoreCVEs": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "maxScore": {
          "type": "number"
        },
        "minSeverity": {
          "type": "string"
        }
      },
      "type": "object"
    },
    "SBOMComponentPolicy": {
      "additionalProperties": false,
      "properties": {
        "allow": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "deny": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "type": "object"
    },
    "SBOMLicensePolicy": {
      "additionalProperties": false,
      "properties": {
        "allow": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "deny": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "type": "object"
    },
    "SBOMPolicy": {
      "additionalProperties": false,
      "properties": {
        "component": {
          "$ref": "#/$defs/SBOMComponentPolicy"
        },
        "cvss": {
          "$ref": "#/$defs/SBOMCVSSPolicy"
        },
        "formats": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "license": {
          "$ref": "#/$defs/SBOMLicensePolicy"
        },
        "missingPolicy": {
          "enum": ["allow", "warn", "deny"],
          "type": "string"
        }
      },
      "type": "object"
    },
    "SLSAPolicy": {
      "additionalProperties": false,
      "properties": {
        "knownParameters": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "maxAge": {
          "type": "string"
        },
        "missingPolicy": {
          "enum": ["allow", "warn", "deny"],
          "type": "string"
        },
        "rejectUnknownParameters": {
          "type": "boolean"
        }
      },
      "type": "object"
    },
    "SignaturesPolicy": {
      "additionalProperties": false,
      "properties": {
        "requireTransparencyLog": {
          "type": "boolean"
        }
      },
      "type": "object"
    },
    "TrustPolicy": {
      "additionalProperties": false,
      "properties": {
        "buildTypes": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "builders": {
          "items": {
            "$ref": "#/$defs/TrustedBuilder"
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
        "verifiers": {
          "items": {
            "$ref": "#/$defs/TrustedVerifier"
          },
          "type": "array"
        }
      },
      "type": "object"
    },
    "TrustedBuilder": {
      "additionalProperties": false,
      "properties": {
        "id": {
          "type": "string"
        },
        "maxLevel": {
          "type": "integer"
        }
      },
      "required": ["id", "maxLevel"],
      "type": "object"
    },
    "TrustedVerifier": {
      "additionalProperties": false,
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
      "required": ["id"],
      "type": "object"
    },
    "VEXPolicy": {
      "additionalProperties": false,
      "properties": {
        "missingPolicy": {
          "enum": ["allow", "warn", "deny"],
          "type": "string"
        },
        "underInvestigationPolicy": {
          "enum": ["allow", "warn", "deny"],
          "type": "string"
        }
      },
      "type": "object"
    },
    "VSAPolicy": {
      "additionalProperties": false,
      "properties": {
        "maxAge": {
          "type": "string"
        },
        "minimumLevel": {
          "type": "integer"
        },
        "missingPolicy": {
          "enum": ["allow", "warn", "deny"],
          "type": "string"
        },
        "policy": {
          "type": "string"
        }
      },
      "type": "object"
    }
  },
  "$ref": "#/$defs/Policy",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "description": "Defines the trust roots and per-namespace verification settings for nri-supply-chain.",
  "title": "nri-supply-chain Policy"
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
| `maxAge`                  | string | (none)      | Maximum age of provenance build timestamp (Go duration, e.g. `720h`). Must be positive when set. Defends against tag rollback attacks by rejecting stale provenance attestations.                                       |

### `vex` (object)

VEX verification settings. Applies to both OpenVEX and CycloneDX VEX formats.

| Field                      | Type   | Default | Description                                                        |
| -------------------------- | ------ | ------- | ------------------------------------------------------------------ |
| `missingPolicy`            | string | `allow` | Behavior when no VEX attestation is found: `allow`, `warn`, `deny` |
| `underInvestigationPolicy` | string | `allow` | Behavior for `under_investigation` status: `allow`, `warn`, `deny` |

> **Production note:** `underInvestigationPolicy` defaults to `allow`, which
> means vulnerabilities still under investigation are silently permitted. For
> production or enforce-mode deployments, set this explicitly to `deny` (block
> the container) or `warn` (allow but log a warning) so that unresolved
> vulnerabilities do not go unnoticed.

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

### `notation` (object)

Notation/Notary v2 signature verification settings. When configured, the plugin
discovers Notation signatures via the OCI Referrers API and verifies them
against the configured trust stores and trust policy.

| Field               | Type   | Default  | Description                                                                                                |
| ------------------- | ------ | -------- | ---------------------------------------------------------------------------------------------------------- |
| `missingPolicy`     | string | `allow`  | Behavior when no Notation signature is found: `allow`, `warn`, `deny`                                      |
| `verificationLevel` | string | `strict` | How strict verification is: `strict`, `permissive`, `audit`, `skip`. `skip` is rejected in `enforce` mode. |
| `trustStores`       | array  | (none)   | Named certificate trust stores for signature verification (see below)                                      |
| `trustPolicy`       | array  | (none)   | Trust policy rules that map registry scopes to trust stores and trusted identities (see below)             |

Each `trustStores` entry:

| Field          | Type   | Required | Description                                                        |
| -------------- | ------ | -------- | ------------------------------------------------------------------ |
| `name`         | string | yes      | Trust store name (referenced by trust policy rules as `type:name`) |
| `type`         | string | yes      | Trust store type: `ca` or `signingAuthority`                       |
| `certificates` | array  | yes      | Absolute paths to PEM-encoded certificate files                    |

Each `trustPolicy` entry:

| Field               | Type   | Required | Description                                                                         |
| ------------------- | ------ | -------- | ----------------------------------------------------------------------------------- |
| `name`              | string | yes      | Human-readable name for this trust policy rule                                      |
| `registryScopes`    | array  | yes      | Registry scope patterns this rule applies to (e.g., `"*"` or `"docker.io/myorg/*"`) |
| `trustStores`       | array  | yes      | Trust store references in `type:name` format (e.g., `"ca:myca"`)                    |
| `trustedIdentities` | array  | yes      | Distinguished name patterns or `"*"` to trust all signers                           |

### `sbom` (object)

SBOM attestation verification settings. When configured, the plugin verifies
SPDX and CycloneDX SBOM attestations attached to container images.

| Field           | Type   | Default | Description                                                            |
| --------------- | ------ | ------- | ---------------------------------------------------------------------- |
| `missingPolicy` | string | `allow` | Behavior when no SBOM attestation is found: `allow`, `warn`, `deny`    |
| `formats`       | array  | (both)  | Accepted SBOM formats: `spdx`, `cyclonedx`. When empty, both accepted. |
| `license`       | object | (none)  | License allow/deny list settings (see below)                           |
| `component`     | object | (none)  | Component allow/deny list settings (see below)                         |
| `cvss`          | object | (none)  | CVSS vulnerability scoring thresholds (CycloneDX only, see below)      |

#### `sbom.license` (object)

| Field   | Type  | Default | Description                                                                     |
| ------- | ----- | ------- | ------------------------------------------------------------------------------- |
| `deny`  | array | (none)  | SPDX license identifiers to deny (case-insensitive match)                       |
| `allow` | array | (none)  | SPDX license identifiers to allow. When non-empty, unlisted licenses are denied |

When both `deny` and `allow` are set, deny takes precedence: a license in both
lists is denied.

#### `sbom.component` (object)

| Field   | Type  | Default | Description                                                                   |
| ------- | ----- | ------- | ----------------------------------------------------------------------------- |
| `deny`  | array | (none)  | PURLs to deny (prefix match, e.g. `pkg:npm/event-stream@3.3.6`)               |
| `allow` | array | (none)  | PURLs to allow (prefix match). When non-empty, unlisted components are denied |

When both `deny` and `allow` are set, deny takes precedence: a component
matching a deny entry is denied even if it also matches an allow entry.

#### `sbom.cvss` (object)

CVSS vulnerability scoring thresholds. Only evaluated for CycloneDX SBOMs
(SPDX does not carry vulnerability data). A vulnerability is flagged if it
exceeds `maxScore` or meets/exceeds `minSeverity` (OR logic). Ignored CVEs
still contribute to aggregate statistics for visibility in CEL rules.

| Field         | Type   | Default | Description                                                                       |
| ------------- | ------ | ------- | --------------------------------------------------------------------------------- |
| `maxScore`    | number | (none)  | Maximum allowed CVSS score (0.0-10.0). Vulnerabilities exceeding this are flagged |
| `minSeverity` | string | (none)  | Minimum severity that triggers a violation: `low`, `medium`, `high`, `critical`   |
| `ignoreCVEs`  | array  | (none)  | CVE IDs to exclude from threshold checks (exact match)                            |

When both `maxScore` and `minSeverity` are set, a vulnerability is flagged if
either condition is met (OR logic, not AND).

### `rules` (array of objects)

Per-image policy overrides. Each rule matches images by glob patterns and
overrides specific verification sections for those images. The first matching
rule wins; images that do not match any rule use the base policy.

Each rule is an object with:

| Field        | Type   | Required | Description                                               |
| ------------ | ------ | -------- | --------------------------------------------------------- |
| `images`     | array  | yes      | Glob patterns to match against image references           |
| `trust`      | object | no       | Override trust roots (same schema as top-level `trust`)   |
| `slsa`       | object | no       | Override SLSA settings (same schema as top-level `slsa`)  |
| `vex`        | object | no       | Override VEX settings (same schema as top-level `vex`)    |
| `vsa`        | object | no       | Override VSA settings (same schema as top-level `vsa`)    |
| `signatures` | object | no       | Override signature settings (same schema as `signatures`) |
| `notation`   | object | no       | Override Notation settings (same schema as `notation`)    |
| `cel`        | object | no       | Override CEL rules (same schema as top-level `cel`)       |
| `sbom`       | object | no       | Override SBOM settings (same schema as `sbom`)            |

Fields not set in a rule are inherited from the base policy. The `images`
patterns use the same glob syntax as `include` and `exclude`.

Rules are evaluated after `include`/`exclude` filtering. An image that is
excluded never reaches rule evaluation.

When a namespace policy sets `"inherits": true`, rules are inherited from the
default policy unless the namespace policy defines its own `rules` array (which
replaces the default rules entirely, same as other top-level sections). Setting
`"rules": []` (an empty array) explicitly clears inherited rules so that the
namespace falls back to its base policy for all images.

Example:

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
    "sanPatterns": ["https://github.com/myorg/**"]
  },
  "slsa": { "missingPolicy": "warn" },
  "rules": [
    {
      "images": ["ghcr.io/myorg/critical-*"],
      "slsa": { "missingPolicy": "deny" },
      "vex": { "missingPolicy": "deny" }
    },
    {
      "images": ["ghcr.io/myorg/internal-*"],
      "slsa": { "missingPolicy": "allow" }
    }
  ]
}
```

In this example, `ghcr.io/myorg/critical-app:latest` requires provenance and
VEX attestations. `ghcr.io/myorg/internal-tool:v1` allows missing provenance.
All other images use the base policy (`warn` on missing provenance).

### `cel` (object)

Custom verification rules using [CEL (Common Expression Language)](https://github.com/google/cel-go).
CEL rules run after all standard checks (SLSA, VEX, VSA) complete and can
reference their results. All rules must pass (all-must-pass semantics).
Expressions are compiled at policy load time, so syntax errors are caught
early. CEL rules are not evaluated when a trusted VSA short-circuits
verification (see [verification.md](verification.md) step 8).

| Field   | Type  | Description                                   |
| ------- | ----- | --------------------------------------------- |
| `rules` | array | CEL rules to evaluate (see rule fields below) |

Each rule is an object with:

| Field     | Type   | Required | Description                                                                                                                           |
| --------- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `match`   | string | no       | CEL expression that determines whether this rule applies. When empty or omitted, the rule always applies. Must evaluate to a boolean. |
| `require` | string | yes      | CEL expression that must evaluate to `true` for the check to pass.                                                                    |
| `message` | string | no       | Human-readable message shown when `require` evaluates to `false`.                                                                     |

**Available variables:**

| Variable                 | Type   | Description                                       |
| ------------------------ | ------ | ------------------------------------------------- |
| `image.ref`              | string | Full image reference                              |
| `image.registry`         | string | Registry host                                     |
| `image.repository`       | string | Repository path                                   |
| `image.digest`           | string | Image digest                                      |
| `image.namespace`        | string | Kubernetes namespace                              |
| `slsa.verified`          | bool   | Whether SLSA check passed                         |
| `slsa.builderID`         | string | Builder ID from SLSA provenance                   |
| `slsa.buildType`         | string | Build type from SLSA provenance                   |
| `slsa.source`            | string | Source URI from SLSA provenance                   |
| `vex.verified`           | bool   | Whether VEX check passed                          |
| `vex.status`             | string | VEX status (e.g. `not_affected`, `affected`)      |
| `vsa.verified`           | bool   | Whether VSA check passed                          |
| `vsa.verifierID`         | string | VSA verifier ID                                   |
| `vsa.result`             | string | VSA verification result (e.g. `PASSED`, `FAILED`) |
| `vsa.level`              | int    | SLSA build level from VSA                         |
| `notation.verified`      | bool   | Whether Notation check passed                     |
| `notation.signerDN`      | string | Signer distinguished name from certificate        |
| `notation.trustPolicy`   | string | Name of the matched trust policy                  |
| `sbom.verified`          | bool   | Whether SBOM check passed                         |
| `sbom.format`            | string | SBOM format (`spdx` or `cyclonedx`)               |
| `sbom.componentCount`    | int    | Number of components in the SBOM                  |
| `sbom.licenseCount`      | int    | Number of licenses in the SBOM                    |
| `sbom.cvssMax`           | float  | Highest CVSS score across all vulnerabilities     |
| `sbom.cvssCriticalCount` | int    | Number of critical-severity vulnerabilities       |
| `sbom.cvssHighCount`     | int    | Number of high-severity vulnerabilities           |
| `sbom.cvssMediumCount`   | int    | Number of medium-severity vulnerabilities         |

Standard string functions are available via `ext.Strings()`: `startsWith`,
`endsWith`, `contains`, `matches`.

**Limits:**

- Maximum expression size: 4096 bytes
- Maximum number of rules: 64
- Runtime cost limit: 100,000 (protects against expensive expressions)

Example:

```json
{
  "cel": {
    "rules": [
      {
        "match": "image.registry == 'ghcr.io'",
        "require": "slsa.verified == true",
        "message": "GHCR images must have SLSA provenance"
      },
      {
        "require": "!(image.namespace == 'production') || (slsa.verified == true && vex.verified == true)",
        "message": "Production images require both SLSA and VEX verification"
      }
    ]
  }
}
```

The `cel` section can be set at the top level, in per-image `rules`, and in
namespace overrides. When `"inherits": true` is set, the CEL section is
inherited from the default policy unless the namespace policy defines its own.

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
- **Timestamp sanity**: Regardless of `slsa.maxAge`, provenance build timestamps
  (`startedOn` for v1, `buildStartedOn` for v0.2) are checked for basic sanity.
  Future timestamps beyond a 60-second clock skew tolerance are rejected, as are
  timestamps more than 200 years old (which indicate crafted or corrupt data).
- **Freshness**: If `slsa.maxAge` is configured, the build timestamp must be
  present and within the configured maximum age. This defends against tag
  rollback attacks by rejecting stale provenance attestations. When `slsa.maxAge`
  is not configured, a missing timestamp is allowed.

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

Verifies VEX documents in two formats:

- [OpenVEX](https://openvex.dev) v0.2.0
- [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/) (via CycloneDX BOM
  vulnerability entries with `analysis.state`)

The format is detected automatically from the predicate content. The same
policy settings apply to both formats.

**OpenVEX status handling:**

- `not_affected` or `fixed`: pass
- `affected`: fail
- `under_investigation`: controlled by `underInvestigationPolicy` (default:
  allow)

**CycloneDX VEX status handling** (mapped from `analysis.state`):

- `not_affected`, `false_positive`, `resolved`, `resolved_with_pedigree`: pass
- `exploitable`: fail
- `in_triage`: controlled by `underInvestigationPolicy` (default: allow)
- Missing or empty `analysis`: skipped (no VEX assertion)

CycloneDX BOMs without a `vulnerabilities` section are treated as pure SBOMs
with no VEX data (pass, not an error).

Product matching operates at the image level using digest comparison and PURL
(`pkg:oci/...`) matching. For CycloneDX, vulnerability `affects[].ref` entries
are resolved to components via BOM-ref, then matched by component hash or PURL.

When multiple VEX documents exist (in either format), the most restrictive
result wins: any `affected`/`exploitable` status causes failure regardless of
other documents.

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
verification and optional for key-based. In enforce mode, the plugin logs a
warning when key-only verification is used without transparency log
requirements, because a compromised signing key cannot be time-bounded or
revoked without log entries.

### Notation (Notary v2) Signature Verification

Verifies [Notation](https://notaryproject.dev) (Notary v2) signatures
discovered via the OCI Referrers API. This provides an alternative to Sigstore
bundle signatures for image trust verification.

Notation signatures are discovered by querying the OCI registry's Referrers API
for manifests with media type `application/vnd.cncf.notary.signature`. These
signatures are verified against the trust stores and trust policy configured in
the `notation` section.

Verification flow:

1. **Signature discovery**: Notation signatures are discovered alongside
   Sigstore attestations during the fetch phase.
2. **Trust policy matching**: The image reference is matched against the
   `registryScopes` in the trust policy rules to find the applicable rule.
3. **Certificate verification**: Signatures are verified against the
   certificates in the referenced trust stores.
4. **Identity verification**: The signer identity is checked against the
   `trustedIdentities` in the matching trust policy rule.

When multiple Notation signatures exist, verification passes if any single
signature is valid (any-pass semantics).

Notation verification runs in parallel with SLSA and VEX checks. The results
are combined: all configured checks must pass for the overall result to pass.

Example configuration:

```json
{
  "notation": {
    "missingPolicy": "deny",
    "verificationLevel": "strict",
    "trustStores": [
      {
        "name": "acme-ca",
        "type": "ca",
        "certificates": ["/etc/notation/certs/acme-ca.pem"]
      }
    ],
    "trustPolicy": [
      {
        "name": "default",
        "registryScopes": ["*"],
        "trustStores": ["ca:acme-ca"],
        "trustedIdentities": ["*"]
      }
    ]
  }
}
```

### SBOM Verification

Verifies SBOM (Software Bill of Materials) attestations in
[SPDX](https://spdx.dev) JSON and [CycloneDX](https://cyclonedx.org) JSON
formats. SBOM attestations are discovered via the same in-toto predicate
routing used for other attestation types, using predicate URIs
`https://spdx.dev/Document` (SPDX) and `https://cyclonedx.org/bom`
(CycloneDX).

Checks performed:

- **Format filtering**: When `sbom.formats` is configured, only the listed
  formats are accepted. Unrecognized formats cause a verification error.
- **License deny list**: Each package/component license is checked against
  `sbom.license.deny` using case-insensitive SPDX identifier matching.
  Any match causes failure.
- **License allow list**: When `sbom.license.allow` is set and non-empty,
  any license not in the allow list causes failure.
- **Component deny list**: Each package/component PURL is checked against
  `sbom.component.deny` using prefix matching. Any match causes failure.
- **Component allow list**: When `sbom.component.allow` is set and non-empty,
  any component not matching an allow entry causes failure.
- **Deny over allow**: If a license or component appears in both the deny and
  allow lists, it is denied. Deny always takes precedence.
- **CVSS thresholds** (CycloneDX only): When `sbom.cvss` is configured,
  vulnerabilities in CycloneDX BOMs are checked against score and severity
  thresholds. A vulnerability is flagged if its highest rating score exceeds
  `maxScore` or its highest severity meets or exceeds `minSeverity` (OR logic).
  CVEs listed in `ignoreCVEs` are excluded from threshold checks but still
  contribute to aggregate statistics (cvssMax, cvssCriticalCount, cvssHighCount,
  cvssMediumCount) exposed as CEL variables. SPDX documents do not carry
  vulnerability data, so CVSS checks are silently skipped for SPDX.

When multiple SBOM attestations exist, any denied license or component in any
document causes failure. CVSS metadata from passing attestations is accumulated
and available in CEL rules.

If all SBOM documents fail to parse (as opposed to being absent), the check
always fails regardless of `missingPolicy`. The `missingPolicy` setting only
controls behavior when no SBOM attestation exists at all.

Example configuration:

```json
{
  "sbom": {
    "missingPolicy": "deny",
    "formats": ["spdx", "cyclonedx"],
    "license": {
      "deny": ["AGPL-3.0-only", "GPL-3.0-only"],
      "allow": ["MIT", "Apache-2.0"]
    },
    "component": {
      "deny": ["pkg:npm/event-stream@3.3.6"],
      "allow": ["pkg:npm/trusted"]
    },
    "cvss": {
      "maxScore": 7.0,
      "minSeverity": "critical",
      "ignoreCVEs": ["CVE-2024-0001"]
    }
  }
}
```

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
`slsa`, `vex`, `vsa`, `signatures`, `notation`, `sbom`, `cel`, `rules`) are inherited from the default
policy. Each top-level section that is set in the namespace policy replaces
the default's section entirely. The default policy itself cannot set `inherits`.

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

In this example, `staging.json` inherits all remaining sections (`trust`,
`include`, `exclude`, `slsa`, `vsa`, `signatures`, `notation`, `sbom`, `cel`,
`rules`) from `default.json` but replaces the `vex` section.

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

### Per-image policy rules

Apply different verification strictness to different images within the same
namespace. This avoids the need for separate namespace policies when images
share a namespace but have different risk profiles:

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
    "sanPatterns": ["https://github.com/myorg/**"]
  },
  "slsa": { "missingPolicy": "warn" },
  "vex": { "missingPolicy": "allow" },
  "rules": [
    {
      "images": ["ghcr.io/myorg/payment-*", "ghcr.io/myorg/auth-*"],
      "slsa": { "missingPolicy": "deny" },
      "vex": { "missingPolicy": "deny" }
    },
    {
      "images": ["ghcr.io/myorg/debug-*"],
      "slsa": { "missingPolicy": "allow" }
    }
  ]
}
```

Payment and auth services require full attestation coverage. Debug tools allow
missing provenance. Everything else gets the base policy (warn on missing
provenance, allow missing VEX).

Rules use first-match-wins semantics, so place more specific patterns before
broader ones.

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

## Example Policy Files

Ready-to-use policy files are available in
[`deploy/examples/policies/`](../deploy/examples/policies/), including:

- `keybased.json`: Key-based verification with PEM public keys
- `cel-rules.json`: CEL policy expressions for custom verification logic
- `sbom-deny-list.json`: SBOM component deny-list for license or package control
- `vex-strict.json`: Strict VEX verification requiring all images to have VEX attestations
- `vsa-accelerated.json`: VSA-first verification that short-circuits direct checks
- `gradual-rollout.json`: Gradual rollout from warn to enforce mode
