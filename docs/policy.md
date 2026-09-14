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
  - [<code>version</code> (integer)](#version-integer)
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
    - [<code>sbom.drift</code> (object)](#sbomdrift-object)
  - [<code>scai</code> (object)](#scai-object)
  - [<code>source</code> (object)](#source-object)
  - [<code>buildEnv</code> (object)](#buildenv-object)
  - [<code>vulnScan</code> (object)](#vulnscan-object)
  - [<code>testResult</code> (object)](#testresult-object)
  - [<code>release</code> (object)](#release-object)
  - [<code>runtimeTrace</code> (object)](#runtimetrace-object)
  - [<code>scorecard</code> (object)](#scorecard-object)
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
  - [Predicate Validation](#predicate-validation)
  - [SCAI Verification](#scai-verification)
  - [Source Track Verification](#source-track-verification)
  - [Build Environment Verification](#build-environment-verification)
  - [Vulnerability Scan Verification](#vulnerability-scan-verification)
  - [Test Result Verification](#test-result-verification)
  - [Release Verification](#release-verification)
  - [Runtime Trace Verification](#runtime-trace-verification)
  - [OpenSSF Scorecard Verification](#openssf-scorecard-verification)
- [Pattern Matching](#pattern-matching)
  - [<code>include</code>, <code>exclude</code>, and <code>trust.sources</code>](#include-exclude-and-trustsources)
  - [<code>trust.sanPatterns</code>](#trustsanpatterns)
- [Namespace Overrides](#namespace-overrides)
- [Deployment Patterns](#deployment-patterns)
  - [Gradual rollout](#gradual-rollout)
  - [Per-image policy rules](#per-image-policy-rules)
  - [VSA-accelerated verification](#vsa-accelerated-verification)
  - [Key rotation](#key-rotation)
    - [Time-bounded key rotation](#time-bounded-key-rotation)
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
    "sanPatterns": ["https://github.com/myorg/**"],
    "sources": ["https://github.com/myorg/*"]
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
    "sanPatterns": ["https://github.com/myorg/**"]
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
    "sanPatterns": ["https://github.com/myorg/**"]
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
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/Policy",
  "$defs": {
    "BuildEnvPolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string",
          "enum": ["allow", "warn", "deny"]
        },
        "requiredProperties": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "forbiddenProperties": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "CELPolicy": {
      "properties": {
        "rules": {
          "items": {
            "$ref": "#/$defs/CELRule"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": ["rules"]
    },
    "CELRule": {
      "properties": {
        "match": {
          "type": "string"
        },
        "require": {
          "type": "string"
        },
        "message": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": ["require"]
    },
    "ImageRule": {
      "properties": {
        "trust": {
          "$ref": "#/$defs/TrustPolicy"
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
        },
        "notation": {
          "$ref": "#/$defs/NotationPolicy"
        },
        "cel": {
          "$ref": "#/$defs/CELPolicy"
        },
        "sbom": {
          "$ref": "#/$defs/SBOMPolicy"
        },
        "scai": {
          "$ref": "#/$defs/SCAIPolicy"
        },
        "source": {
          "$ref": "#/$defs/SourcePolicy"
        },
        "buildEnv": {
          "$ref": "#/$defs/BuildEnvPolicy"
        },
        "vulnScan": {
          "$ref": "#/$defs/VulnScanPolicy"
        },
        "testResult": {
          "$ref": "#/$defs/TestResultPolicy"
        },
        "release": {
          "$ref": "#/$defs/ReleasePolicy"
        },
        "runtimeTrace": {
          "$ref": "#/$defs/RuntimeTracePolicy"
        },
        "scorecard": {
          "$ref": "#/$defs/ScorecardPolicy"
        },
        "images": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": ["images"]
    },
    "NotationPolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string",
          "enum": ["allow", "warn", "deny"]
        },
        "trustStores": {
          "items": {
            "$ref": "#/$defs/NotationTrustStore"
          },
          "type": "array"
        },
        "trustPolicy": {
          "items": {
            "$ref": "#/$defs/NotationTrustPolicyRule"
          },
          "type": "array"
        },
        "verificationLevel": {
          "type": "string",
          "enum": ["strict", "permissive", "audit", "skip"]
        },
        "revocationMode": {
          "type": "string",
          "enum": ["strict", "soft", "skip"]
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "NotationTrustPolicyRule": {
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
      "additionalProperties": false,
      "type": "object",
      "required": ["name", "registryScopes", "trustStores", "trustedIdentities"]
    },
    "NotationTrustStore": {
      "properties": {
        "name": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "certificates": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": ["name", "type", "certificates"]
    },
    "Policy": {
      "properties": {
        "trust": {
          "$ref": "#/$defs/TrustPolicy"
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
        },
        "notation": {
          "$ref": "#/$defs/NotationPolicy"
        },
        "cel": {
          "$ref": "#/$defs/CELPolicy"
        },
        "sbom": {
          "$ref": "#/$defs/SBOMPolicy"
        },
        "scai": {
          "$ref": "#/$defs/SCAIPolicy"
        },
        "source": {
          "$ref": "#/$defs/SourcePolicy"
        },
        "buildEnv": {
          "$ref": "#/$defs/BuildEnvPolicy"
        },
        "vulnScan": {
          "$ref": "#/$defs/VulnScanPolicy"
        },
        "testResult": {
          "$ref": "#/$defs/TestResultPolicy"
        },
        "release": {
          "$ref": "#/$defs/ReleasePolicy"
        },
        "runtimeTrace": {
          "$ref": "#/$defs/RuntimeTracePolicy"
        },
        "scorecard": {
          "$ref": "#/$defs/ScorecardPolicy"
        },
        "version": {
          "type": "integer"
        },
        "mode": {
          "type": "string",
          "enum": ["disabled", "warn", "enforce"]
        },
        "inherits": {
          "type": "boolean"
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
        "rules": {
          "items": {
            "$ref": "#/$defs/ImageRule"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "ReleasePolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string",
          "enum": ["allow", "warn", "deny"]
        },
        "trustedRegistries": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "requirePackageId": {
          "type": "boolean"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "RuntimeTracePolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string",
          "enum": ["allow", "warn", "deny"]
        },
        "trustedMonitors": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "forbiddenFilePatterns": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "maxAge": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "SBOMCVSSPolicy": {
      "properties": {
        "maxScore": {
          "type": "number"
        },
        "minSeverity": {
          "type": "string"
        },
        "ignoreCVEs": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "SBOMComponentPolicy": {
      "properties": {
        "deny": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "allow": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "SBOMDriftPolicy": {
      "properties": {
        "maxAdded": {
          "type": "integer"
        },
        "maxRemoved": {
          "type": "integer"
        },
        "maxModified": {
          "type": "integer"
        },
        "maxScore": {
          "type": "number"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "SBOMLicensePolicy": {
      "properties": {
        "deny": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "allow": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "SBOMPolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string",
          "enum": ["allow", "warn", "deny"]
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
        "component": {
          "$ref": "#/$defs/SBOMComponentPolicy"
        },
        "cvss": {
          "$ref": "#/$defs/SBOMCVSSPolicy"
        },
        "drift": {
          "$ref": "#/$defs/SBOMDriftPolicy"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "SCAIPolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string",
          "enum": ["allow", "warn", "deny"]
        },
        "requiredAttributes": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "forbiddenAttributes": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "requireEvidence": {
          "type": "boolean"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "SLSAPolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string",
          "enum": ["allow", "warn", "deny"]
        },
        "rejectUnknownParameters": {
          "type": "boolean"
        },
        "knownParameters": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "maxAge": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "ScorecardPolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string",
          "enum": ["allow", "warn", "deny"]
        },
        "minScore": {
          "type": "number"
        },
        "checks": {
          "additionalProperties": {
            "type": "integer"
          },
          "type": "object"
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
    "SourcePolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string",
          "enum": ["allow", "warn", "deny"]
        },
        "minimumLevel": {
          "type": "integer"
        },
        "maxAge": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "TestResultPolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string",
          "enum": ["allow", "warn", "deny"]
        },
        "requiredSuites": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "maxAge": {
          "type": "string"
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
        },
        "keys": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "identities": {
          "items": {
            "$ref": "#/$defs/TrustedIdentity"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": ["id", "maxLevel"]
    },
    "TrustedIdentity": {
      "properties": {
        "issuer": {
          "type": "string"
        },
        "sanPattern": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": ["issuer", "sanPattern"]
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
        },
        "notBefore": {
          "type": "string",
          "format": "date-time"
        },
        "notAfter": {
          "type": "string",
          "format": "date-time"
        },
        "identities": {
          "items": {
            "$ref": "#/$defs/TrustedIdentity"
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
          "type": "string",
          "enum": ["allow", "warn", "deny"]
        },
        "underInvestigationPolicy": {
          "type": "string",
          "enum": ["allow", "warn", "deny"]
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "VSAPolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string",
          "enum": ["allow", "warn", "deny"]
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
    },
    "VulnScanPolicy": {
      "properties": {
        "missingPolicy": {
          "type": "string",
          "enum": ["allow", "warn", "deny"]
        },
        "maxScore": {
          "type": "number"
        },
        "minSeverity": {
          "type": "string"
        },
        "ignoreCVEs": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "maxAge": {
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

### `version` (integer)

Policy schema version. Currently `1`. Omitting defaults to `0`, which is
treated as version 1. The plugin rejects policies with a version newer than
it supports.

### `mode` (string)

Overrides the global `verification` mode for this namespace. Valid values:
`"disabled"`, `"warn"`, `"enforce"`. When omitted on `default.json`, the global
mode from the operational config applies. When omitted on a namespace policy,
the mode of `default.json` applies (see below), falling back to the global mode
when `default.json` does not set one.

The per-namespace mode can only be equal to or stricter than the global mode.
Strictness order: `disabled` < `warn` < `enforce`. For example, global `warn`
with a namespace `enforce` is valid, but global `enforce` with a namespace
`warn` is rejected at startup.

When set on `default.json`, the mode applies to all namespaces that fall
back to the default policy (i.e., namespaces without their own policy file).
Namespace policies that do not set `mode` also use the mode of `default.json`,
whether or not they set `inherits`, so moving a mode into `default.json` never
weakens other namespaces. Set `mode` explicitly on a namespace policy to use a
different (still at least as strict as global) mode.

When the global `verification` mode is `disabled`, policies are not evaluated
and every container is admitted, even when a policy sets `mode` to `warn` or
`enforce`. The global `disabled` mode acts as an emergency kill switch, so the
plugin only logs a warning for such policies and still starts or reloads. The
`validate` subcommand reports the same condition as an error, so CI catches the
mismatch before rollout.

This is useful for gradually rolling out enforcement: set the global mode to
`warn` and promote individual namespaces to `enforce` as confidence grows.

### `inherits` (boolean)

When set to `true` on a namespace policy (`<namespace>.json`), unset fields
are inherited from `default.json` instead of using empty defaults. Sections
are merged field by field (see [Namespace Overrides](#namespace-overrides)).
Only valid on namespace policies; the default policy cannot set `inherits`.

### `trust` (object)

Trust roots for verification. All sub-fields are optional.

| Field         | Type  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `builders`    | array | Trusted SLSA provenance builders. Each entry has `id` (URI) and `maxLevel` (0-3), plus optional `keys` (absolute paths to PEM public keys) and `identities` (keyless signing identities, see below) that bind the builder to its signer. Builder IDs must be unique within a policy. A bound builder is only accepted from provenance signed by one of its keys or identities; an unbound builder is accepted from any trusted signer (a warning is logged). Note: `maxLevel` is only enforced by VSA verification (`vsa.minimumLevel`), not during SLSA provenance checks, because provenance attestations do not declare a build level.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `verifiers`   | array | Trusted VSA verifiers. Each entry has `id` (URI), an optional `keys` (array of absolute paths to PEM public keys), and optional `identities` (keyless signing identities, see below). Verifier IDs must be unique within a policy. A VSA claiming a verifier `id` is only trusted when it was signed by one of that verifier's `keys` or `identities`; a verifier with neither never short-circuits verification. When `keys` is set, the keys are used for Sigstore bundle signature verification. Use `keys` for key rotation so that both old and new keys are accepted simultaneously. Optional `notBefore` and `notAfter` (RFC 3339 timestamps) bound the validity window for key-based verification: without `signatures.requireTransparencyLog` the window is checked against the current time (every signature of the key is rejected once `notAfter` passed), with it against the transparency log integrated time. When `keys` is empty or omitted, bundles are verified via keyless (Fulcio/OIDC) using `issuers` and `sanPatterns`, which must be configured in the effective policy (after inheritance from `default.json` and after merging each image rule). Verifier keys are unique, but builders may share a key. |
| `issuers`     | array | Trusted OIDC issuers for keyless (Fulcio) verification.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `sanPatterns` | array | Accepted certificate Subject Alternative Names. Supports glob patterns: `*` matches any non-`/` sequence, `**` matches any characters including `/`, `?` matches a single non-`/` character, `[...]` matches a character class. Use `**` for GitHub Actions OIDC SANs that include workflow paths (e.g., `https://github.com/org/repo/**`). Required when `issuers` is set in `enforce` mode. In `warn` mode, omitting this field accepts any SAN from a trusted issuer (with a log warning).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `sources`     | array | Allowed source repository glob patterns for SLSA provenance, Source Track, and Scorecard attestations (e.g., `https://github.com/myorg/*`). A pattern is matched against the source repository without a `git+` prefix or ref; a ref-pinned pattern such as `git+https://github.com/myorg/repo@refs/tags/*` must also match the ref (see [SLSA Provenance](#slsa-provenance)). Supports the same glob syntax as `sanPatterns`: `*` matches non-`/` characters, `**` matches any characters including `/`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `buildTypes`  | array | Accepted build type URIs for SLSA provenance.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

Each `identities` entry of a builder or verifier:

| Field        | Type   | Required | Description                                                                                                                                            |
| ------------ | ------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `issuer`     | string | yes      | OIDC issuer recorded in the signing certificate (exact match). It should also be listed in `trust.issuers`, otherwise the certificate is not accepted. |
| `sanPattern` | string | yes      | Glob pattern for the certificate Subject Alternative Name (same syntax as `sanPatterns`).                                                              |

Binding matters because `trust.issuers` and `sanPatterns` (and all verifier
keys) form a single trust set for every attestation type. Builder keys are only
trusted for SLSA provenance, so a provenance signing key cannot sign other
attestation types. A verifier key may not be listed by another verifier or by
a builder, while several builders may share a key. Without a binding,
any trusted signer, for example any workflow of the organization that matches
`sanPatterns`, could sign a VSA naming the trusted verifier and skip all other
checks. Bind each verifier to the workflow or key that actually issues its
VSAs:

```json
{
  "trust": {
    "issuers": ["https://token.actions.githubusercontent.com"],
    "sanPatterns": ["https://github.com/myorg/**"],
    "verifiers": [
      {
        "id": "https://github.com/myorg/verifier/.github/workflows/verify.yml",
        "identities": [
          {
            "issuer": "https://token.actions.githubusercontent.com",
            "sanPattern": "https://github.com/myorg/verifier/.github/workflows/verify.yml@refs/heads/main"
          }
        ]
      }
    ]
  }
}
```

### `include` (array of strings)

Glob patterns for images that require verification. When set, only images
matching at least one pattern are verified; all others are allowed without
verification. When empty or omitted, all images are eligible for verification
(the default). Uses the same glob syntax as `exclude`: `*` matches any
non-`/` sequence, `**` matches any characters including `/`. If both
`include` and `exclude` are set, `exclude` takes precedence. Because images
that match no pattern skip verification, matching is broad (see
[Pattern Matching](#pattern-matching)) and a warning is logged when `include`
is used in `enforce` mode.

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

| Field               | Type   | Default                                   | Description                                                                                                                                                                                                                                                                                                 |
| ------------------- | ------ | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `missingPolicy`     | string | `allow`                                   | Behavior when no Notation signature is found: `allow`, `warn`, `deny`                                                                                                                                                                                                                                       |
| `verificationLevel` | string | `strict`                                  | How strict verification is: `strict`, `permissive`, `audit`, `skip`. `skip` and `audit` are rejected in `enforce` mode (`audit` only logs authenticity failures). `permissive` logs a warning in `enforce` mode because it does not enforce expiry and revocation.                                          |
| `revocationMode`    | string | (none, inherits from `verificationLevel`) | Certificate revocation checking: `strict` (enforce OCSP/CRL), `soft` (log failures), `skip` (explicitly disable revocation checking). When omitted, no override is set and the base verification level controls revocation behavior. Cannot be set when `verificationLevel` is `skip`. Recommended: `soft`. |
| `trustStores`       | array  | (none)                                    | Named certificate trust stores for signature verification (see below)                                                                                                                                                                                                                                       |
| `trustPolicy`       | array  | (none)                                    | Trust policy rules that map registry scopes to trust stores and trusted identities (see below)                                                                                                                                                                                                              |

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
| `drift`         | object | (none)  | SBOM drift detection thresholds for baseline comparison (see below)    |

#### `sbom.license` (object)

| Field   | Type  | Default | Description                                                                     |
| ------- | ----- | ------- | ------------------------------------------------------------------------------- |
| `deny`  | array | (none)  | SPDX license identifiers to deny (case-insensitive match)                       |
| `allow` | array | (none)  | SPDX license identifiers to allow. When non-empty, unlisted licenses are denied |

When both `deny` and `allow` are set, deny takes precedence: a license in both
lists is denied.

License values that are SPDX expressions (SPDX `licenseConcluded` and
`licenseDeclared`, CycloneDX `license.id` and `expression`, SPDX 3 license
expressions) are split into identifiers before matching. Parentheses and any
Unicode whitespace are token boundaries (`MIT AND(GPL-3.0-only)`),
`AND`/`OR`/`WITH` are matched case-insensitively, and exception identifiers
after `WITH` (identifiers containing `exception`, ending in `-note`, or
starting with `AdditionRef-`) are skipped. Any other identifier after `WITH`
is checked like a license. Every identifier of an expression is checked, so
`MIT OR GPL-3.0-only` is denied by a `GPL-3.0-only` deny entry and requires
both identifiers in an allow list. Identifiers are compared
case-insensitively, zero-width characters (such as U+200B or a byte order
mark) are ignored or act as separators, and the deprecated (`GPL-2.0`),
`-only`, `+`, and `-or-later` forms are normalized. A deny entry covers every
form of its license version, so `GPL-2.0-only`, `GPL-2.0`, and
`GPL-2.0-or-later` each deny `GPL-2.0+` and `GPL-2.0-only`. An allow entry
only covers its own scope: `GPL-2.0-only` (or `GPL-2.0`) allows `GPL-2.0` and
`GPL-2.0-only`, while `GPL-2.0+` and `GPL-2.0-only+` require
`GPL-2.0-or-later`. CycloneDX
free-text `license.name` values are matched verbatim, and the licenses of the
BOM subject (`metadata.component`) are checked too. SPDX 3 expanded licensing
elements are resolved: `WithAdditionOperator` yields its subject license and
`OrLaterOperator` yields its subject license with a `+` suffix. License
references that cannot be resolved count as an unknown license, which fails
any allow list.

#### `sbom.component` (object)

| Field   | Type  | Default | Description                                                                   |
| ------- | ----- | ------- | ----------------------------------------------------------------------------- |
| `deny`  | array | (none)  | PURLs to deny (prefix match, e.g. `pkg:npm/event-stream@3.3.6`)               |
| `allow` | array | (none)  | PURLs to allow (prefix match). When non-empty, unlisted components are denied |

When both `deny` and `allow` are set, deny takes precedence: a component
matching a deny entry is denied even if it also matches an allow entry.

When `allow` is set, package components without a PURL fail the check because
they cannot be matched against the allow list. Components that are not packages
are exempt: CycloneDX components of type `operating-system`, `file`, `data`,
`device`, `firmware`, `platform`, or `cryptographic-asset`; SPDX packages the
document describes (the image itself) or whose primary purpose is
`OPERATING-SYSTEM`, `FILE`, `CONTAINER`, `SOURCE`, `ARCHIVE`, `DEVICE`, or
`FIRMWARE`. Application components without a PURL that describe a lock or
manifest file rather than a versioned package are exempt as well: CycloneDX
components of type `application` without a version or classified by Trivy as
`lang-pkgs` (property `aquasecurity:trivy:Class`), and SPDX packages with the
primary purpose `APPLICATION` and no version. Nested CycloneDX components are
checked like top-level ones. The number of non-exempt components without a
PURL is exposed in the check metadata as `componentsWithoutPURL`. A CycloneDX
BOM without components (for example for scratch or static images) is an SBOM
only when it names its subject in `metadata.component`. A CycloneDX document
with neither components nor `metadata.component`, such as a VEX-only document,
is not treated as an SBOM: it is ignored by the SBOM check, and when no other
SBOM attestation exists `missingPolicy` applies. With several SBOM documents,
the metadata aggregates across them: `componentCount` and
`componentsWithoutPURL` are summed, `licenseCount` counts the distinct
licenses, and `format` lists every format (for example `cyclonedx,spdx`).

#### `sbom.cvss` (object)

CVSS vulnerability scoring thresholds. Only evaluated for CycloneDX SBOMs
(SPDX does not carry vulnerability data). A vulnerability is flagged if it
exceeds `maxScore` or meets/exceeds `minSeverity` (OR logic). Ignored CVEs
still contribute to aggregate statistics for visibility in CEL rules.

CycloneDX documents without components and without `metadata.component`
(vulnerability disclosure reports or VEX documents) are not SBOMs, but their
unresolved rated vulnerabilities (analysis state `exploitable`, `in_triage`,
or none) are still evaluated against these thresholds, so moving findings into
a separate document cannot hide them. Such a document fails the SBOM check
when a finding exceeds the thresholds; otherwise it only contributes to the
`cvss*` statistics and does not count as an SBOM for `missingPolicy`,
`componentCount`, or `format`.

| Field         | Type   | Default | Description                                                                       |
| ------------- | ------ | ------- | --------------------------------------------------------------------------------- |
| `maxScore`    | number | (none)  | Maximum allowed CVSS score (0.0-10.0). Vulnerabilities exceeding this are flagged |
| `minSeverity` | string | (none)  | Minimum severity that triggers a violation: `low`, `medium`, `high`, `critical`   |
| `ignoreCVEs`  | array  | (none)  | CVE IDs to exclude from threshold checks (exact match)                            |

When both `maxScore` and `minSeverity` are set, a vulnerability is flagged if
either condition is met (OR logic, not AND).

#### `sbom.drift` (object)

SBOM drift detection compares an image's current SBOM against a known-good
baseline SBOM stored as an OCI artifact (artifact type
`application/vnd.nri-supply-chain.sbom-baseline.v1+json`). Drift detection
flags unexpected package additions, removals, version changes, checksum
mismatches, and license changes that signature verification alone cannot catch.
Packages are matched by PURL; packages without a PURL are ignored.

| Field         | Type   | Default | Description                                                                                  |
| ------------- | ------ | ------- | -------------------------------------------------------------------------------------------- |
| `maxAdded`    | int    | (none)  | Maximum number of added packages allowed before failing                                      |
| `maxRemoved`  | int    | (none)  | Maximum number of removed packages allowed before failing                                    |
| `maxModified` | int    | (none)  | Maximum number of modified packages allowed before failing                                   |
| `maxScore`    | number | (none)  | Maximum drift score allowed. Computed as `(added*3 + modified*2 + removed) / baseline_count` |

When any threshold is set, a baseline is mandatory: the check fails when no
baseline SBOM referrer is found or when any baseline SBOM cannot be parsed.
Without thresholds, drift is computed for information only (exposed in
metadata and CEL) and missing or unparsable baselines are skipped. All
thresholds must be non-negative.

### `scai` (object)

SCAI (Supply Chain Attribute Integrity) attribute report verification settings.
When configured, the plugin verifies
[SCAI](https://github.com/in-toto/attestation/blob/main/spec/predicates/scai.md)
attribute report attestations attached to container images.

| Field                 | Type   | Default | Description                                                           |
| --------------------- | ------ | ------- | --------------------------------------------------------------------- |
| `missingPolicy`       | string | `allow` | Behavior when no SCAI attestation is found: `allow`, `warn`, `deny`   |
| `requiredAttributes`  | array  | (none)  | Attribute names that must be present in the report (case-insensitive) |
| `forbiddenAttributes` | array  | (none)  | Attribute names that must not appear in the report (case-insensitive) |
| `requireEvidence`     | bool   | `false` | Require that every attribute includes non-empty evidence              |

### `source` (object)

SLSA Source Track verification settings. When configured, the plugin verifies
[SLSA Source Track v1](https://slsa.dev/spec/draft/source-requirements)
attestations (predicate type `https://slsa.dev/source/v1`) attached to
container images.

| Field           | Type   | Default | Description                                                               |
| --------------- | ------ | ------- | ------------------------------------------------------------------------- |
| `missingPolicy` | string | `allow` | Behavior when no source attestation is found: `allow`, `warn`, `deny`     |
| `minimumLevel`  | int    | 0       | Minimum SLSA source level required (0-3)                                  |
| `maxAge`        | string | (none)  | Maximum age of the attestation (e.g. `24h`, `168h`); older ones are stale |

The source verification checks that the source repository listed in the
attestation matches one of the trusted `trust.sources` glob patterns configured
in the policy.

### `buildEnv` (object)

Build environment attestation verification settings. When configured, the
plugin verifies
[build-env v1](https://github.com/in-toto/attestation/tree/main/spec/predicates)
attestations (predicate type `https://in-toto.io/attestation/build-env/v1`)
attached to container images.

| Field                 | Type   | Default | Description                                                               |
| --------------------- | ------ | ------- | ------------------------------------------------------------------------- |
| `missingPolicy`       | string | `allow` | Behavior when no build env attestation is found: `allow`, `warn`, `deny`  |
| `requiredProperties`  | array  | (none)  | Property names that must be present in the environment (case-insensitive) |
| `forbiddenProperties` | array  | (none)  | Property names that must not appear in the environment (case-insensitive) |

The `requiredProperties` and `forbiddenProperties` lists must not overlap; the
policy is rejected at load time if they do.

### `vulnScan` (object)

Vulnerability scan attestation verification settings. When configured, the
plugin verifies
[vulns](https://github.com/in-toto/attestation/blob/main/spec/predicates/vuln.md)
attestations (predicate types `https://in-toto.io/attestation/vulns/v0.1` and
`https://in-toto.io/attestation/vulns/v0.2`)
attached to container images.

| Field           | Type   | Default | Description                                                                         |
| --------------- | ------ | ------- | ----------------------------------------------------------------------------------- |
| `missingPolicy` | string | `allow` | Behavior when no vuln scan attestation is found: `allow`, `warn`, `deny`            |
| `maxScore`      | float  | (none)  | Maximum allowed CVSS score (0.0-10.0); any vulnerability above this threshold fails |
| `minSeverity`   | string | (none)  | Minimum severity that triggers a violation: `low`, `medium`, `high`, `critical`     |
| `ignoreCVEs`    | array  | (none)  | CVE IDs to exclude from threshold checks (exact match)                              |
| `maxAge`        | string | (none)  | Maximum age of the scan (e.g. `24h`, `168h`); older scans are considered stale      |

When both `maxScore` and `minSeverity` are set, a vulnerability is flagged if
either condition is met (OR logic).

### `testResult` (object)

Test result attestation verification settings. When configured, the plugin
verifies
[test-result v0.1](https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md)
attestations (predicate type `https://in-toto.io/attestation/test-result/v0.1`)
attached to container images.

| Field            | Type   | Default | Description                                                                  |
| ---------------- | ------ | ------- | ---------------------------------------------------------------------------- |
| `missingPolicy`  | string | `allow` | Behavior when no test result attestation is found: `allow`, `warn`, `deny`   |
| `requiredSuites` | array  | (none)  | Test suite names that must be present and passing                            |
| `maxAge`         | string | (none)  | Maximum age of the test result (e.g. `24h`, `168h`); older results are stale |

The overall test result must be `pass` or `passed` (case-insensitive). If any
required suite is missing or has a non-passing result, verification fails.

### `release` (object)

Release attestation verification settings. When configured, the plugin verifies
[release v0.1](https://github.com/in-toto/attestation/blob/main/spec/predicates/release.md)
attestations (predicate type `https://in-toto.io/attestation/release/v0.1`)
attached to container images.

| Field               | Type    | Default | Description                                                             |
| ------------------- | ------- | ------- | ----------------------------------------------------------------------- |
| `missingPolicy`     | string  | `allow` | Behavior when no release attestation is found: `allow`, `warn`, `deny`  |
| `trustedRegistries` | array   | (none)  | Glob patterns for trusted package registries (matched against the purl) |
| `requirePackageId`  | boolean | `false` | Require a non-empty `packageId` in the release attestation              |

When multiple release attestations exist, any single valid one is sufficient
(any-pass semantics).

### `runtimeTrace` (object)

Runtime trace attestation verification settings. When configured, the plugin
verifies
[runtime-trace v0.1](https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md)
attestations (predicate type `https://in-toto.io/attestation/runtime-trace/v0.1`)
attached to container images.

| Field                   | Type   | Default | Description                                                                      |
| ----------------------- | ------ | ------- | -------------------------------------------------------------------------------- |
| `missingPolicy`         | string | `allow` | Behavior when no runtime trace attestation is found: `allow`, `warn`, `deny`     |
| `trustedMonitors`       | array  | (none)  | Glob patterns for trusted monitor types (e.g. `falco`, `tetragon*`)              |
| `forbiddenFilePatterns` | array  | (none)  | Glob patterns for file accesses that must not appear (e.g. `/etc/shadow`)        |
| `maxAge`                | string | (none)  | Maximum age of the trace (e.g. `24h`, `168h`); older traces are considered stale |

### `scorecard` (object)

OpenSSF Scorecard result verification settings. The plugin verifies Scorecard
JSON v2 results carried in in-toto attestations with the provisional predicate
type `https://scorecard.dev/result/v0.1`.

| Field           | Type   | Default | Description                                                                    |
| --------------- | ------ | ------- | ------------------------------------------------------------------------------ |
| `missingPolicy` | string | `allow` | Behavior when no Scorecard attestation is found: `allow`, `warn`, or `deny`    |
| `minScore`      | float  | (none)  | Minimum aggregate Scorecard score (0.0-10.0)                                   |
| `checks`        | object | (none)  | Map of exact Scorecard check names to minimum integer scores (0-10), inclusive |

An upstream Scorecard check score of `-1` means inconclusive. It remains
available to CEL, but fails any configured per-check minimum. Every check named
in `checks` must be present in the attestation.

### `rules` (array of objects)

Per-image policy overrides. Each rule matches images by glob patterns and
overrides specific verification sections for those images. The first matching
rule wins; images that do not match any rule use the base policy.

Each rule is an object with:

| Field          | Type   | Required | Description                                                     |
| -------------- | ------ | -------- | --------------------------------------------------------------- |
| `images`       | array  | yes      | Glob patterns to match against image references                 |
| `trust`        | object | no       | Override trust roots (same schema as top-level `trust`)         |
| `slsa`         | object | no       | Override SLSA settings (same schema as top-level `slsa`)        |
| `vex`          | object | no       | Override VEX settings (same schema as top-level `vex`)          |
| `vsa`          | object | no       | Override VSA settings (same schema as top-level `vsa`)          |
| `signatures`   | object | no       | Override signature settings (same schema as `signatures`)       |
| `notation`     | object | no       | Override Notation settings (same schema as `notation`)          |
| `cel`          | object | no       | Override CEL rules (same schema as top-level `cel`)             |
| `sbom`         | object | no       | Override SBOM settings (same schema as `sbom`)                  |
| `scai`         | object | no       | Override SCAI settings (same schema as `scai`)                  |
| `source`       | object | no       | Override source settings (same schema as `source`)              |
| `buildEnv`     | object | no       | Override build env settings (same schema as `buildEnv`)         |
| `vulnScan`     | object | no       | Override vuln scan settings (same schema as `vulnScan`)         |
| `testResult`   | object | no       | Override test result settings (same schema as `testResult`)     |
| `release`      | object | no       | Override release settings (same schema as `release`)            |
| `runtimeTrace` | object | no       | Override runtime trace settings (same schema as `runtimeTrace`) |
| `scorecard`    | object | no       | Override Scorecard settings (same schema as `scorecard`)        |

Fields not set in a rule are inherited from the base policy. Sections are
merged field by field with the same semantics as
[namespace overrides](#namespace-overrides), so a rule that only sets
`slsa.maxAge` keeps the base `slsa.missingPolicy`. The `cel` section is
replaced as a whole: `"cel": {"rules": []}` removes the base CEL rules for the
matching images. The `images` patterns use the same glob syntax as `include`
and `exclude`; like `exclude`, they only match the reference as reported by
the runtime and its normalized fully qualified forms.

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
CEL rules run after all standard checks complete and can
reference their results. All rules must pass (all-must-pass semantics).
Expressions are compiled at policy load time, so syntax errors, type errors,
and unknown fields (for example a misspelled field like `image.registryx`) are caught
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

**Missing attestations:** every attestation variable (all variables except
`image` and `guac`) provides `present` and `verified`. When no attestation of
the type was found, `present` and `verified` are both `false`, even if the
type's `missingPolicy` allowed the image, and no data fields are provided.
Reading a data field of a missing attestation (for example
`vulnscan.criticalCount == 0`) is an evaluation error, which fails the CEL
check instead of seeing a clean default. Guard such expressions with
`present`, for example `!vulnscan.present || vulnscan.criticalCount == 0`, or
require the attestation with `vulnscan.present == true`.

**Available variables:**

| Variable                       | Type   | Description                                       |
| ------------------------------ | ------ | ------------------------------------------------- |
| `image.ref`                    | string | Full image reference                              |
| `image.registry`               | string | Registry host                                     |
| `image.repository`             | string | Repository path                                   |
| `image.digest`                 | string | Image digest                                      |
| `image.namespace`              | string | Kubernetes namespace                              |
| `<type>.present`               | bool   | Whether an attestation of the type was found      |
| `slsa.verified`                | bool   | Whether SLSA check passed                         |
| `slsa.builderID`               | string | Builder ID from SLSA provenance                   |
| `slsa.buildType`               | string | Build type from SLSA provenance                   |
| `slsa.source`                  | string | Source URI from SLSA provenance                   |
| `slsa.sourceRef`               | string | Source git ref or commit SHA                      |
| `slsa.sourceDigest`            | string | Source commit digest (`algorithm:value`)          |
| `slsa.trustConfigured`         | bool   | Whether builders, sources, or build types are set |
| `vex.verified`                 | bool   | Whether VEX check passed                          |
| `vex.status`                   | string | Status: `affected`, `not_affected`, `no_match`    |
| `vsa.verified`                 | bool   | Whether VSA check passed                          |
| `vsa.verifierID`               | string | VSA verifier ID                                   |
| `vsa.result`                   | string | VSA verification result (e.g. `PASSED`, `FAILED`) |
| `vsa.level`                    | int    | SLSA build level from VSA                         |
| `notation.verified`            | bool   | Whether Notation check passed                     |
| `notation.signerDN`            | string | Signer distinguished name from certificate        |
| `notation.trustPolicy`         | string | Name of the matched trust policy                  |
| `sbom.verified`                | bool   | Whether SBOM check passed                         |
| `sbom.format`                  | string | SBOM formats, comma separated (`cyclonedx,spdx`)  |
| `sbom.componentCount`          | int    | Number of components in the SBOM                  |
| `sbom.licenseCount`            | int    | Number of licenses in the SBOM                    |
| `sbom.cvssMax`                 | float  | Highest CVSS score across all vulnerabilities     |
| `sbom.cvssCriticalCount`       | int    | Number of critical-severity vulnerabilities       |
| `sbom.cvssHighCount`           | int    | Number of high-severity vulnerabilities           |
| `sbom.cvssMediumCount`         | int    | Number of medium-severity vulnerabilities         |
| `sbom.drift.detected`          | bool   | Whether any drift was detected                    |
| `sbom.drift.addedCount`        | int    | Number of packages added vs baseline              |
| `sbom.drift.removedCount`      | int    | Number of packages removed vs baseline            |
| `sbom.drift.modifiedCount`     | int    | Number of packages modified vs baseline           |
| `sbom.drift.addedPackages`     | list   | PURLs of added packages                           |
| `sbom.drift.score`             | float  | Weighted drift score                              |
| `scai.verified`                | bool   | Whether SCAI verification passed                  |
| `scai.attributes`              | string | Comma-separated attribute names                   |
| `scai.attributeCount`          | int    | Number of attributes                              |
| `scai.hasEvidence`             | bool   | Whether all attributes have evidence              |
| `source.verified`              | bool   | Whether source verification passed                |
| `source.source`                | string | Source repository URI                             |
| `source.branch`                | string | Source branch                                     |
| `source.level`                 | int    | SLSA source level                                 |
| `buildenv.verified`            | bool   | Whether build environment verification passed     |
| `buildenv.properties`          | string | Comma-separated property names                    |
| `buildenv.propertyCount`       | int    | Number of environment properties                  |
| `buildenv.propertyValues`      | map    | Property name-value pairs (`map[string]string`)   |
| `buildenv.conflicts`           | list   | Properties dropped because attestations disagree  |
| `vulnscan.verified`            | bool   | Whether vulnerability scan verification passed    |
| `vulnscan.scanner`             | string | Scanner URI                                       |
| `vulnscan.vulnCount`           | int    | Number of vulnerabilities found                   |
| `vulnscan.maxScore`            | float  | Highest CVSS score across all vulnerabilities     |
| `vulnscan.maxSeverity`         | string | Highest severity across all vulnerabilities       |
| `vulnscan.criticalCount`       | int    | Number of critical-severity vulnerabilities       |
| `vulnscan.highCount`           | int    | Number of high-severity vulnerabilities           |
| `vulnscan.unknownCount`        | int    | Number of vulnerabilities with unknown severity   |
| `testresult.verified`          | bool   | Whether test result verification passed           |
| `testresult.result`            | string | Overall test result (e.g. `pass`, `fail`)         |
| `testresult.suiteCount`        | int    | Number of test suites                             |
| `testresult.suites`            | string | Comma-separated suite names                       |
| `testresult.passed`            | int    | Total passed tests across all suites              |
| `testresult.failed`            | int    | Total failed tests across all suites              |
| `release.verified`             | bool   | Whether release verification passed               |
| `release.purl`                 | string | Package URL from the release attestation          |
| `release.packageId`            | string | Package identifier from the release attestation   |
| `runtimetrace.verified`        | bool   | Whether runtime trace verification passed         |
| `runtimetrace.monitorType`     | string | Monitor type (e.g. `falco`, `tetragon`)           |
| `runtimetrace.processCount`    | int    | Number of process log entries                     |
| `runtimetrace.networkCount`    | int    | Number of network log entries                     |
| `runtimetrace.fileAccessCount` | int    | Number of file access entries                     |
| `runtimetrace.fileNames`       | string | Comma-separated file names from file accesses     |
| `guac.available`               | bool   | Whether all enabled GUAC queries succeeded        |
| `guac.vulnerabilities`         | list   | Direct vulnerabilities (id, package)              |
| `guac.transitive_vulns`        | list   | Transitive vulnerabilities (same fields)          |
| `guac.scorecard.aggregate`     | float  | OpenSSF Scorecard aggregate score                 |
| `guac.scorecard.checks`        | map    | Individual Scorecard check scores                 |
| `guac.scorecard.source`        | string | Source repository from the Scorecard              |
| `guac.scorecard.truncated`     | bool   | Too many linked repositories to determine a score |
| `guac.dependencies`            | list   | Transitive dependency PURLs (truncated by max)    |
| `guac.dependency_count`        | int    | Total transitive dependencies (before truncation) |
| `scorecard.verified`           | bool   | Whether OpenSSF Scorecard verification passed     |
| `scorecard.repo`               | string | Repository analyzed by Scorecard                  |
| `scorecard.version`            | string | OpenSSF Scorecard version                         |
| `scorecard.score`              | float  | Aggregate Scorecard score                         |
| `scorecard.checks`             | map    | Check-name to integer-score map                   |

`vex.status` can also be `under_investigation`; see
[VEX](#vex-vulnerability-exploitability-exchange) for the meaning of
`no_match`.

GUAC data is fail-closed. The booleans `guac.vulnerabilities_available`,
`guac.scorecard_available`, and `guac.dependencies_available` report whether
the corresponding query was enabled and succeeded. When a query did not
succeed (or GUAC is not configured), its data fields are absent:
`guac.vulnerabilities`, `guac.transitive_vulns`, `guac.scorecard`,
`guac.dependencies`, and `guac.dependency_count` are not set, so any rule that
reads them fails evaluation, which fails the CEL check (a denial in enforce
mode, a warning in warn mode). The error names the availability flag to guard
with. This covers both positive rules (`guac.vulnerabilities.size() == 0`) and
negative rules (`!guac.vulnerabilities.exists(v, v.id == "CVE-2024-1234")`).
Use the `*_available` flags or `has(guac.vulnerabilities)` to write rules that
tolerate missing data explicitly. `guac.scorecard` only reflects repositories
GUAC links to the image digest. When more repositories or packages are linked
than can be queried, `guac.scorecard.truncated` is `true`, the aggregate is
`0`, and `guac.scorecard.source` is `guac:truncated`, so a rule such as
`guac.scorecard.source == "" || guac.scorecard.aggregate >= 7.0` does not
mistake a truncated result for an image without a linked repository.

The CEL built-in string functions `startsWith`, `endsWith`, `contains`, and
`matches` are available, as well as the `ext.Strings()` extension library
(for example `lowerAscii`, `split`, `replace`, and `trim`).

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
inherited from the default policy unless the namespace policy defines its own,
which replaces it as a whole.

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
- **Source repository**: If `trust.sources` is configured, the source repository
  must match an allowed glob pattern. The source is read from the layout of the
  build type:
  - `https://actions.github.io/buildtypes/workflow/v1` and
    `https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1`:
    `externalParameters.workflow.repository` and `workflow.ref`.
  - `https://slsa-framework.github.io/gcb-buildtypes/triggered-build/v1`:
    `externalParameters.sourceToBuild.repository` and `sourceToBuild.ref` when
    `sourceToBuild` names a repository, otherwise
    `externalParameters.configSource.repository` and `configSource.ref` (the
    specification omits `sourceToBuild`, or keeps only its `dir`, when the
    built source is the configuration source). When `sourceToBuild` and
    `configSource` name different repositories, both must match a trusted
    source pattern, because the build configuration controls the build steps.
  - Other build types, or when the layout above is absent: a top-level
    `externalParameters.source` (a URI string, or an object with `uri` and
    `digest`), then the layouts above.

  Git URIs such as `git+https://github.com/org/repo@refs/heads/main` are
  normalized to the repository `https://github.com/org/repo` and the ref
  `refs/heads/main`. An explicit `ref` parameter (for example `workflow.ref`)
  takes precedence over a ref embedded in the repository URI. A pattern
  without `@` is matched against the normalized repository only, so ref text
  can never satisfy a repository wildcard. A ref-pinned pattern such as
  `git+https://github.com/org/repo@refs/tags/*` (the `git+` prefix is
  optional) is split into its repository and ref parts, which must match the
  normalized repository and the resolved ref; a source without a ref does not
  match it. The source ref and digest are also exposed to CEL as
  `slsa.sourceRef` and `slsa.sourceDigest`.

- **Resolved dependencies**: Every `buildDefinition.resolvedDependencies` entry
  that refers to the source repository must carry a digest. When both sides name
  a ref, the refs must match: fully qualified refs must be identical
  (`refs/tags/v1` does not match `refs/heads/v1`), while a short name matches a
  branch or tag of that name. When the source ref is a commit SHA, the ref
  comparison is skipped and the SHA must instead match the dependency's commit
  digest of the same length: a 40 hex character SHA is compared with a
  `gitCommit` or `sha1` digest, a 64 hex character SHA with a `gitCommit` or
  `sha256` digest. A dependency without a digest of that length is not
  compared. A source digest must likewise match a dependency digest of the same
  algorithm. For Cloud Build, a dependency of the `configSource` repository may
  match either the built source or the configuration source, so both can use
  the same repository at different refs. The digest is exposed as
  `sourceDigest` metadata.
- **Unknown parameters**: If `slsa.rejectUnknownParameters` is enabled,
  unrecognized `externalParameters` fields cause rejection. The recognized set
  defaults to GitHub Actions parameters (`source`, `repository`, `ref`,
  `workflow`, `buildType`) but can be overridden with `slsa.knownParameters`.
- **Timestamp sanity**: Regardless of `slsa.maxAge`, provenance build timestamps
  (`startedOn` for v1, `buildStartedOn` for v0.2) are checked for basic sanity.
  Future timestamps beyond a 60-second clock skew tolerance are rejected, as are
  timestamps more than 200 years old (which indicate crafted or corrupt data).
  A zero timestamp (`0001-01-01T00:00:00Z`, as written for an unset Go
  `time.Time`) is treated as absent.
- **Freshness**: If `slsa.maxAge` is configured, the build timestamp must be
  present and within the configured maximum age. This defends against tag
  rollback attacks by rejecting stale provenance attestations. When `slsa.maxAge`
  is not configured, a missing timestamp is allowed.

Note: `trust.builders[].maxLevel` is not checked during provenance
verification. SLSA provenance does not declare a build level; levels are a
property of the builder's infrastructure. Use `vsa.minimumLevel` to enforce
build level requirements via VSA verification.

When none of `trust.builders`, `trust.sources`, or `trust.buildTypes` is
configured, any provenance with a matching subject passes the builder and source
checks. The check then reports `warn` instead of `pass` (for example
`slsa:warn` in the container annotation) and sets the `trustConfigured`
metadata to `false`, so an unconstrained provenance check stays visible.

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

The format is detected automatically from the predicate content: OpenVEX by
`@context` or `statements`, CycloneDX by `bomFormat`. A JSON `null` or empty
object predicate is an empty document. Any other content is rejected as an
invalid VEX document. The same policy settings apply to both formats.

**OpenVEX status handling:**

- `not_affected` or `fixed`: pass
- `affected`: fail
- `under_investigation`: controlled by `underInvestigationPolicy` (default:
  allow)
- Any other status (including differently cased values such as `Affected`):
  treated as affected

**OpenVEX statement precedence:** statements from all OpenVEX documents for
the image are grouped by vulnerability name, product scope (the image, or the
matched packages including their versions), and subcomponent scope. The
result does not depend on the order of statements or documents. Among
statements of the same match strength (see below) the most recent statement
wins, using the statement `last_updated` or `timestamp` and falling back to
the document `last_updated` or `timestamp`. A later `fixed` statement
therefore overrides an earlier `affected` statement. When timestamps are
equal, the most restrictive status wins.

**CycloneDX VEX status handling** (mapped from `analysis.state`):

- `not_affected`, `false_positive`, `resolved`, `resolved_with_pedigree`: pass
- `exploitable`: fail
- `in_triage`: controlled by `underInvestigationPolicy` (default: allow)
- Unknown `analysis.state`: treated as affected
- Missing or empty `analysis.state`: not a VEX statement and ignored by the
  VEX check. Such findings (for example scanner output in an SBOM) are gated
  by [`sbom.cvss`](#sbomcvss-object) instead

**Product matching:** an identifier refers to the image when it is the image
digest (also percent-encoded, as in `sha256%3A...`), an image reference with
that digest, or an OCI or docker PURL whose version is the image digest. When
the image was resolved from a manifest list, both the index digest and the
platform manifest digest identify the image. Qualifiers such as
`repository_url`, `tag`, or `arch` do not prevent a digest match, and
`repository_url` may include the image name (`docker.io/library/nginx`, as
the PURL specification requires), omit it, or name only the registry. An OCI
or docker PURL without a digest matches by name: its name, namespace (for
example `library` in `pkg:docker/library/nginx`), `repository_url`, and tag
(a tag version or `tag` qualifier, compared when the image reference names a
tag) must all agree with the image, so `pkg:docker/bitnami/nginx@1.25` does
not match `docker.io/library/nginx:1.27`. Statements that can only raise
severity (`affected`, `under_investigation`, or an unknown status) are matched
leniently: an OCI or docker PURL with the image name applies even when its
namespace, tag, or `repository_url` differ (for example after a retag or a
mirror), as long as it does not carry a different digest. A lenient match is
ignored for a vulnerability that a strictly matching statement covers, and a
lenient match naming another tag is ignored whenever any statement in the
documents matches the image strictly: such documents distinguish the image
from its other versions, so in a multi-version document `affected` for
`?tag=v0` does not apply to `:v1`. Package PURLs listed in a statement whose
lenient match is ignored still apply as package products. `not_affected` and
`fixed` statements require the strict match. OpenVEX product `hashes` are
compared by algorithm (`sha-256` equals `sha256`) and hex value. Because the
document is bound to the image digest, an OpenVEX product that is a package
PURL (for example `pkg:npm/lodash@4.17.20`, as emitted by scanners) applies to
the image as one of its components; statements about different packages, or
different versions of a package, are resolved independently. A versionless
package PURL forms its own scope, so it can raise severity for the package but
never resolve a statement about a specific version. Package-level `fixed` or
`not_affected` statements do not count as statements about the image: when
only such statements exist, the status stays `no_match`.

**Match strength:** a statement that identifies the image only by name, or
applies through a package PURL, can raise the severity of a statement bound to
the image digest but never lower it. It is considered when it is not older
than the most recent digest-bound statement. A newer name-only `not_affected`
therefore does not override a digest-bound `affected`, a newer name-only
`affected` raises a digest-bound `not_affected`, and a newer digest-bound
`not_affected` overrides an older name-only `affected`. A statement without any
timestamp (neither on the statement nor on the document) ties with every other
statement, so its status wins when it is more restrictive.

For CycloneDX, the BOM is bound to the image digest through the in-toto
subject, so it describes the image. A vulnerability applies to the image when
an `affects[].ref` resolves (via BOM-ref, including `metadata.component` and
nested components) to a component of the BOM, is a BOM-Link (`urn:cdx:`), is a
package PURL, or identifies the image. This covers scanner output such as
Trivy, where vulnerabilities reference package components. Vulnerabilities
that are not resolved (`exploitable`, `in_triage`, or an unknown state) are
matched leniently: references that carry a different image digest
(another digest, a PURL with another digest, or a container component with
another hash) or an image PURL with a different image name are ignored, so
unknown BOM-refs (for example from a separate SBOM), CPEs, retagged image
PURLs, and the BOM subject (`metadata.component`, whatever its name) still
apply, while a finding for another image of a multi-image document does not.
Resolved vulnerabilities must identify the image or one of its components. A
vulnerability without `affects` applies to the image.

**Reported status:** the check metadata `status` (and the CEL variable
`vex.status`) is `affected`, `under_investigation`, `not_affected`, or
`no_match`. `no_match` means the VEX documents are valid but contain no
statement about the image (for example an empty document, or a CycloneDX SBOM
without vulnerabilities). It passes, but it is never reported as
`not_affected`. Use a CEL rule such as `vex.status != "no_match"` to require an
explicit statement. The metadata `matchedStatements` counts the statements
that apply to the image.

When multiple VEX documents exist (in either format), the most restrictive
result wins: any effective `affected`/`exploitable` status causes failure
regardless of other documents.

Every VEX document must parse and bind to the image digest. If any VEX
document fails to parse or verify (as opposed to being absent), the check
fails regardless of `missingPolicy` and of the other documents. The
`missingPolicy` setting only controls behavior when no VEX attestation exists
at all.

### VSA (Verification Summary Attestation)

Verifies [SLSA VSA](https://slsa.dev/spec/v1.0/verification_summary) v1
attestations. A VSA records the outcome of a prior SLSA and VEX verification
performed by a trusted verifier, allowing the plugin to skip those checks when
the VSA is trusted and PASSED. Checks performed:

- **Verifier trust**: `verifier.id` must appear in `trust.verifiers`, and the
  VSA must be signed by one of that verifier's `keys` or `identities`.
- **Verification result**: `PASSED` is required. `FAILED` from a trusted
  verifier is a hard reject that prevents fallback to SLSA/VEX.
- **Build level**: `verifiedLevels` must meet the `vsa.minimumLevel` threshold.
- **Resource URI**: `resourceUri` must be digest-pinned and name the same
  repository and digest as the image. References are normalized before
  comparison: every Docker Hub alias (`docker.io`, `index.docker.io`,
  `registry-1.docker.io`, `registry.hub.docker.com`) is equal, and official
  images may omit `library/`, so `docker.io/library/nginx@sha256:...` and
  `registry-1.docker.io/nginx@sha256:...` are equal.
- **Subject**: A statement `subject[].digest` must match the image digest.
- **SLSA version**: `slsaVersion` must be >= `1.0`.
- **Policy match**: If `vsa.policy` is configured, `policy.uri` must match.
- **Freshness**: `timeVerified` (RFC 3339, lowercase `t` and `z` accepted) must
  be within the `vsa.maxAge` window.

VSA-first logic:

- Trusted PASSED: short-circuits all other checks. CEL rules still run, but
  they only see the VSA result; rules that reference other attestation types
  see them as not present (`present == false`).
- Trusted FAILED: hard reject, no fallback allowed. A FAILED result is only
  honored after the resource URI and subject are bound to the image, and only
  when the VSA was signed by its verifier, so a FAILED VSA for a different
  image or from another signer cannot deny this one.
- No trusted PASSED VSA (missing, untrusted, signed by a signer not bound to
  the verifier, unbound to the image, stale, or unparsable): controlled by
  `vsa.missingPolicy`. When set to `allow` (the default) or left empty, falls
  through to direct verification. When set to `warn`, falls through with a
  warning. When set to `deny`, rejects immediately without fallback.

### Signature Verification

All attestations must be valid [Sigstore](https://sigstore.dev) bundles with a
verified signature. Unsigned or incorrectly signed attestations are dropped
during the fetch phase and never reach SLSA, VEX, or VSA verification. If all
discovered bundles fail signature verification, the image fails
verification: it is rejected in enforce mode regardless of
`fetch_failure_policy`, which only covers registry and network errors (see
[config.md](config.md#fetch-failures)). If some bundles verify and others do
not, only the verified ones are used (invalid bundles are logged and
discarded).

The plugin supports two verification modes that can be used independently or
together:

**Keyless (Fulcio)**: Uses OIDC identity. Configure `trust.issuers` with
trusted identity providers. In `enforce` mode, `trust.sanPatterns` is required
to restrict accepted certificate SANs. In `warn` mode, omitting `sanPatterns`
accepts any SAN from a trusted issuer (with a log warning). Requires the
Sigstore public-good instance (Fulcio + Rekor).

**Key-based**: Uses local PEM public keys. Configure `trust.verifiers` with
the verifier ID and `keys` paths. Optional `notBefore`/`notAfter` fields
restrict the validity window for the verifier's keys. Without a transparency
log the window is checked against the current time, since the signing time
claimed by the bundle cannot be trusted. Does not require network access to
Sigstore infrastructure.

When `signatures.requireTransparencyLog` is true, attestations must include a
valid Rekor transparency log entry. This is recommended for keyless
verification and optional for key-based. Operators can configure `notBefore`
and `notAfter` on key-based verifiers to bound key validity, but transparency
log entries provide cryptographic proof of signing time. In enforce mode, the
plugin logs a warning when key-only verification is used without transparency
log requirements.

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

Certificate revocation checking is controlled by `revocationMode`. Setting it
to `soft` is recommended for most deployments: revocation failures are logged
but do not block the workload, which avoids outages caused by unreachable
OCSP/CRL endpoints. Use `strict` only when your infrastructure guarantees
reliable access to revocation services.

Notation verification runs in parallel with SLSA and VEX checks. The results
are combined: all configured checks must pass for the overall result to pass.

Example configuration:

```json
{
  "notation": {
    "missingPolicy": "deny",
    "verificationLevel": "strict",
    "revocationMode": "soft",
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

- **Drift detection**: When a baseline SBOM is attached as an OCI referrer
  (artifact type `application/vnd.nri-supply-chain.sbom-baseline.v1+json`),
  the current SBOM is compared against it using PURL as the package identity
  key. Added, removed, and modified packages are counted and a weighted drift
  score is computed. When `sbom.drift` thresholds are configured, exceeding
  any threshold causes failure. Drift results are always exposed as CEL
  variables (`sbom.drift.*`) regardless of whether thresholds are set. With
  thresholds configured, a missing or unparsable baseline fails the check;
  without thresholds, drift detection is skipped when no usable baseline is
  found.

Supported documents: SPDX 2.x JSON, SPDX 3.0 and 3.0.1 JSON-LD (package types
`software_Package` and `software_SoftwarePackage`, versions from
`software_packageVersion`, PURLs from `software_packageUrl` or external
identifiers, and licenses from `hasConcludedLicense`/`hasDeclaredLicense`
Relationship elements), and CycloneDX JSON (including nested components and
license expressions). Each SBOM payload is decoded once.

When multiple SBOM attestations exist, every document must parse and pass: any
denied license or component in any document causes failure, and so does any
document that fails to parse. CVSS metadata from passing attestations is
accumulated and available in CEL rules.

The `purls` list in the check metadata (used to match vulnerability feeds
against running containers) has qualifiers and subpaths removed, is
deduplicated, and is capped at 10000 entries. When the cap is hit, the list
ends with the marker `pkg:generic/nri-supply-chain/purls-truncated`, and feed
matching treats the image as affected by every feed entry.

If any SBOM document fails to parse (as opposed to being absent), the check
fails regardless of `missingPolicy`. The `missingPolicy` setting only controls
behavior when no SBOM attestation exists at all.

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
    },
    "drift": {
      "maxAdded": 5,
      "maxRemoved": 3,
      "maxModified": 10,
      "maxScore": 2.0
    }
  }
}
```

### Predicate Validation

The SCAI, Source Track, Build Environment, Vulnerability Scan, Test Result,
Release, Runtime Trace, and OpenSSF Scorecard checks share the following
behavior:

- **Required fields**: A predicate that is empty, `null`, not a JSON object, or
  missing the fields its specification requires is invalid, even when the
  corresponding policy section is not configured. The required fields are
  listed in each section below.
- **Timestamps**: A timestamp more than 60 seconds in the future, or more than
  200 years in the past, fails the check whether or not `maxAge` is configured.
  When `maxAge` is configured, the timestamp must also be present and within the
  maximum age. A zero timestamp (`0001-01-01T00:00:00Z`) is treated as absent.
- **Multiple documents**: For checks where all attestations must pass, a
  document that cannot be parsed or validated fails the check even when other
  documents pass. For any-pass checks, invalid documents are reported only when
  no document passes. Documents that contradict each other (for example the
  same build environment property with different values) also fail the check.

### SCAI Verification

Verifies [SCAI](https://github.com/in-toto/attestation/blob/main/spec/predicates/scai.md)
(Supply Chain Attribute Integrity) attribute report attestations (predicate type
`https://in-toto.io/attestation/scai/v0.3`). SCAI reports capture structured
evidence about build attributes, complementing SLSA provenance with
fine-grained property assertions.

Checks performed:

- **Subject digest**: The in-toto `subject[].digest` must match the image digest.
- **Required fields**: `attributes` must contain at least one entry, and every
  entry must have a non-empty `attribute`.
- **Required attributes**: If `scai.requiredAttributes` is configured, every
  listed attribute name must be present in the report (case-insensitive match).
- **Forbidden attributes**: If `scai.forbiddenAttributes` is configured, none
  of the listed attribute names may appear in the report (case-insensitive
  match).
- **Evidence requirement**: If `scai.requireEvidence` is true, every attribute
  in the report must include non-empty evidence (`null`, `{}`, and absent
  evidence all count as missing).

When multiple SCAI attestations exist, any policy violation in any document
causes failure. Metadata from passing attestations is merged: attribute counts
are summed, attribute name lists are concatenated (deduplicated), and the
`hasEvidence` flag uses AND logic (all attestations must have evidence for the merged
result to be true).

If any SCAI document fails to parse or validate (as opposed to being absent),
the check fails regardless of `missingPolicy`. The `missingPolicy` setting only
controls behavior when no SCAI attestation exists at all.

Example configuration:

```json
{
  "scai": {
    "missingPolicy": "warn",
    "requiredAttributes": ["PASSED_CODE_REVIEW", "PASSED_TESTS"],
    "forbiddenAttributes": ["KNOWN_VULNERABLE"],
    "requireEvidence": true
  }
}
```

### Source Track Verification

Verifies [SLSA Source Track v1](https://slsa.dev/spec/draft/source-requirements)
attestations (predicate type `https://slsa.dev/source/v1`). Source attestations
capture the origin repository, branch, and source level of the code used to
build the image.

Checks performed:

- **Subject digest**: The in-toto `subject[].digest` must match the image digest.
- **Required fields**: The first `sourceLocations` entry must have a non-empty
  `uri`.
- **Trusted source**: The source repository in the attestation must match one of
  the `trust.sources` glob patterns. Patterns are interpreted as for SLSA
  provenance: the `git+` prefix is optional, a ref embedded in the source URI
  is not part of the repository, and a ref-pinned pattern is matched against
  `branch` (or the embedded ref when `branch` is empty). A short branch name
  such as `main` also matches `refs/heads/main`.
- **Minimum level**: If `source.minimumLevel` is configured, the source level in
  the attestation must meet or exceed it.
- **Freshness**: `sourceMetadata.verifiedOn` is checked as described in
  [Predicate Validation](#predicate-validation) using `source.maxAge`.

When multiple source attestations exist, any single valid attestation that
passes all checks is sufficient. Metadata from the first passing attestation is
used for CEL evaluation.

Example configuration:

```json
{
  "trust": {
    "sources": ["https://github.com/myorg/**"]
  },
  "source": {
    "missingPolicy": "warn",
    "minimumLevel": 2,
    "maxAge": "168h"
  }
}
```

### Build Environment Verification

Verifies [build-env v1](https://github.com/in-toto/attestation/tree/main/spec/predicates)
attestations (predicate type `https://in-toto.io/attestation/build-env/v1`).
Build environment attestations describe the properties and configuration of the
environment in which an artifact was built.

Checks performed:

- **Subject digest**: The in-toto `subject[].digest` must match the image digest.
- **Required fields**: `environment` must contain at least one property, and
  every property must have a non-empty `name`.
- **Unambiguous values**: A property name (compared case-insensitively) that
  appears more than once with different values makes the document invalid.
  When the same property has different values in two attestations (for
  example a build ID after a re-attestation), the check still passes, but the
  property is dropped from `buildenv.propertyValues` and listed in
  `buildenv.conflicts`. A CEL rule reading a dropped property
  fails closed, while rules on unambiguous properties keep working.
- **Required properties**: If `buildEnv.requiredProperties` is configured, every
  listed property name must be present in the environment (case-insensitive match).
- **Forbidden properties**: If `buildEnv.forbiddenProperties` is configured, none
  of the listed property names may appear in the environment (case-insensitive
  match).

The `buildEnv` section only constrains property names; property values are not
checked. To require specific values, use a CEL rule on
`buildenv.propertyValues`, for example
`buildenv.propertyValues['HERMETIC'] == 'true'`.

When multiple build environment attestations exist, any policy violation or
invalid document causes failure. Required and forbidden properties are checked
in every attestation. Metadata from passing attestations is merged: property
counts are summed, property name lists are concatenated (deduplicated), and
property values are combined, dropping properties whose values differ (see
`buildenv.conflicts`).

Example configuration:

```json
{
  "buildEnv": {
    "missingPolicy": "warn",
    "requiredProperties": ["HERMETIC", "REPRODUCIBLE"],
    "forbiddenProperties": ["ALLOW_NETWORK"]
  }
}
```

### Vulnerability Scan Verification

Verifies [vulns](https://github.com/in-toto/attestation/blob/main/spec/predicates/vuln.md)
attestations (predicate types `https://in-toto.io/attestation/vulns/v0.1` and
`https://in-toto.io/attestation/vulns/v0.2`).
Vulnerability scan attestations capture the results of automated vulnerability
scanning of container images.

Two predicate layouts are accepted:

- **Specification layout**: `scanner.uri`, `scanner.version`, `scanner.db`,
  and `scanner.result[]`, where each result has an `id` and a `severity` list of
  `{method, score}` entries, with `metadata.scanStartedOn` and
  `metadata.scanFinishedOn`. The nested form from the specification's field
  table, `scanner.result[].vulnerability.{id, severity}`, is accepted as well,
  and `severity` may be a single `{method, score}` object.
- **Legacy layout**: `scanner.uri` with `result.vulnerabilities[]`, where each
  vulnerability has an `id`, a textual `severity`, and a numeric `score`, with
  `metadata.scannedOn`. When `result` is present, `result.vulnerabilities` must
  be an array, so a report in another format (for example a raw scanner report
  under `result`) is rejected instead of being read as a clean scan.

The severity of each vulnerability is derived from all of its entries, keeping
the most severe: numeric scores (strings or numbers) are read as CVSS base
scores and mapped to qualitative ratings (low 0.1 to 3.9, medium 4.0 to 6.9,
high 7.0 to 8.9, critical 9.0 to 10.0), and textual scores are read as
severities (`moderate` counts as medium, `important` as high, `negligible` as
low). EPSS entries and values that are neither, such as CVSS vectors, are
ignored.

Checks performed:

- **Subject digest**: The in-toto `subject[].digest` must match the image digest.
- **Required fields**: `scanner.uri` and either `scanner.result` or `result`
  must be present, and every vulnerability must have an `id`.
- **CVSS threshold**: If `vulnScan.maxScore` is configured, no vulnerability may
  have a CVSS score exceeding the threshold (after filtering `ignoreCVEs`). A
  vulnerability without a numeric score is compared using the lowest score of
  its severity.
- **Severity threshold**: If `vulnScan.minSeverity` is configured, no
  vulnerability may have a severity at or above the threshold (after filtering
  `ignoreCVEs`).
- **Unknown severity**: When `maxScore` or `minSeverity` is configured, a
  vulnerability whose severity cannot be determined fails the check. Add its ID
  to `ignoreCVEs` to accept it explicitly.
- **Freshness**: `scanFinishedOn` (or `scannedOn`, then `scanStartedOn`) is
  checked as described in [Predicate Validation](#predicate-validation) using
  `vulnScan.maxAge`. Zero timestamps are skipped in favor of the next one.

The `maxSeverity` metadata ranks an unknown severity above `none`, so a finding
that could not be classified is never hidden behind a clean result, and
`unknownCount` counts such findings.

When both `maxScore` and `minSeverity` are set, a vulnerability is flagged if
either condition is met (OR logic). When multiple scan attestations exist, any
policy violation or invalid document causes failure.

Example configuration:

```json
{
  "vulnScan": {
    "missingPolicy": "deny",
    "maxScore": 7.0,
    "minSeverity": "critical",
    "ignoreCVEs": ["CVE-2024-0001"],
    "maxAge": "24h"
  }
}
```

### Test Result Verification

Verifies [test-result v0.1](https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md)
attestations (predicate type `https://in-toto.io/attestation/test-result/v0.1`).
Test result attestations capture the outcome of automated test suites run
against an artifact.

Checks performed:

- **Subject digest**: The in-toto `subject[].digest` must match the image digest.
- **Required fields**: `result` must be present.
- **Overall result**: The top-level `result` must be `pass`, `passed`, `warn`,
  or `warned` (case-insensitive). The specification defines `WARNED` as a run
  that passed with warnings; the number of `warnedTests` is exposed as the
  `warned` metadata.
- **Consistency**: A passing `result` fails when `failedTests` is non-empty or
  when any entry in `suites` has a failing result (`fail`, `failed`, `error`) or
  a non-zero `failed` count.
- **Required suites**: If `testResult.requiredSuites` is configured, every
  listed name must be a suite with a passing result or appear in `passedTests`
  or `warnedTests`.
- **Freshness**: `metadata.finishedOn` is checked as described in
  [Predicate Validation](#predicate-validation) using `testResult.maxAge`.

Both the specification fields (`result`, `configuration`, `passedTests`,
`warnedTests`, `failedTests`) and the suite-based fields (`suites`,
`metadata.finishedOn`) are understood.

When multiple test result attestations exist, any policy violation in any
document causes failure. Metadata from passing attestations is merged: suite
counts, pass/fail totals, and suite name lists are aggregated.

Example configuration:

```json
{
  "testResult": {
    "missingPolicy": "deny",
    "requiredSuites": ["unit", "integration", "e2e"],
    "maxAge": "168h"
  }
}
```

### Release Verification

Verifies [release v0.1](https://github.com/in-toto/attestation/blob/main/spec/predicates/release.md)
attestations (predicate type `https://in-toto.io/attestation/release/v0.1`).
Release attestations record the publication of an artifact to a package
repository, capturing the package URL (purl) and optional package identifier.

Checks performed:

- **Subject digest**: The in-toto `subject[].digest` must match the image digest.
- **Required fields**: `purl` must be non-empty.
- **Trusted registries**: If `release.trustedRegistries` is configured, the
  `purl` field must match at least one glob pattern.
- **Package ID**: If `release.requirePackageId` is `true`, the `packageId`
  field must be non-empty.

When multiple release attestations exist, any single valid one is sufficient
(any-pass semantics). Metadata from the first passing attestation is used.

Example configuration:

```json
{
  "release": {
    "missingPolicy": "deny",
    "trustedRegistries": ["pkg:oci/ghcr.io/*", "pkg:npm/@myorg/*"],
    "requirePackageId": true
  }
}
```

### Runtime Trace Verification

Verifies [runtime-trace v0.1](https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md)
attestations (predicate type `https://in-toto.io/attestation/runtime-trace/v0.1`).
Runtime trace attestations capture build-time runtime observations from a
monitor, including process activity, network connections, and file accesses.

Checks performed:

- **Subject digest**: The in-toto `subject[].digest` must match the image digest.
- **Required fields**: `monitor.type` must be non-empty and `monitorLog` must be
  present.
- **Trusted monitors**: If `runtimeTrace.trustedMonitors` is configured, the
  `monitor.type` field must match at least one glob pattern.
- **Forbidden files**: If `runtimeTrace.forbiddenFilePatterns` is configured,
  none of the `name`, `uri`, or `downloadLocation` of any file access entry may
  match a forbidden pattern. File URLs (`file:///path`, `file://localhost/path`,
  `file:/path`, in any scheme case) are also matched as their percent-decoded
  path, and paths are additionally matched after cleaning (`//`, `.`, and `..`
  segments), so alternative encodings cannot evade a pattern.
- **Freshness**: `metadata.buildFinishedOn` is checked as described in
  [Predicate Validation](#predicate-validation) using `runtimeTrace.maxAge`.

When multiple runtime trace attestations exist, all must pass (all-must-pass
semantics). Metadata from passing attestations is merged: process, network, and
file access counts are summed, and monitor types and file names are
deduplicated.

Example configuration:

```json
{
  "runtimeTrace": {
    "missingPolicy": "deny",
    "trustedMonitors": ["falco", "tetragon*"],
    "forbiddenFilePatterns": ["/etc/shadow", "/root/.ssh/**"],
    "maxAge": "24h"
  }
}
```

### OpenSSF Scorecard Verification

Verifies [OpenSSF Scorecard](https://github.com/ossf/scorecard) JSON v2 results
attached to container images as in-toto attestations. Until the upstream
Software Verification Results predicate is finalized, the plugin recognizes
the provisional predicate type `https://scorecard.dev/result/v0.1`.

Checks performed:

- **Subject digest**: The in-toto `subject[].digest` must match the image digest.
- **Result structure**: The repository, Scorecard version, aggregate score, and
  at least one named check must be present. Scores must be in Scorecard's
  `-1` (inconclusive) to `10` range.
- **Trusted repository**: If `trust.sources` is configured, `repo.name` must
  match one of the patterns. Scorecard reports names without a scheme
  (`github.com/org/repo`), so the name is also matched with an `https://`
  prefix. Patterns are interpreted as for SLSA provenance: the `git+` prefix
  is optional, and a ref-pinned pattern such as
  `git+https://github.com/org/repo@<ref>` is matched against `repo.commit`,
  because Scorecard results carry no ref. A result without `repo.commit`
  never matches a ref-pinned pattern.
- **Aggregate score**: If `scorecard.minScore` is configured, the aggregate
  score must be greater than or equal to it.
- **Per-check scores**: Every entry in `scorecard.checks` must exist in the
  result and meet or exceed its configured minimum.
- **Date**: When present, `date` must be an RFC 3339 timestamp or a
  `YYYY-MM-DD` date that is not in the future. A `YYYY-MM-DD` date is the
  scanner's local date, which can be a day ahead of UTC, so date-only values get
  a 24 hour tolerance. The `scorecard` section has no `maxAge`, so result age is
  not limited.

When multiple Scorecard attestations exist, all must pass. CEL metadata is
merged conservatively: the lowest aggregate and per-check score is retained,
while repository and version values are deduplicated.

Example configuration:

```json
{
  "scorecard": {
    "missingPolicy": "deny",
    "minScore": 7.0,
    "checks": {
      "Code-Review": 8,
      "Branch-Protection": 9
    }
  },
  "cel": {
    "rules": [
      {
        "require": "scorecard.verified && scorecard.checks['Fuzzing'] >= 5",
        "message": "Scorecard fuzzing score is too low"
      }
    ]
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

- `[!abc]` and `[^abc]` match any character not in the set, except `/`

`include` and `exclude` patterns are matched against the full image reference as
received from the container runtime, including registry and path components. For
example, `registry.io/org/*` matches `registry.io/org/repo` but not
`registry.io/org/team/repo`. Use `registry.io/org/**` to match any nesting
depth. `trust.sources` patterns are matched against source repositories instead
(see [`trust`](#trust-object)).

References are also matched in normalized form, with every Docker Hub alias
(`index.docker.io`, `registry-1.docker.io`, `registry.hub.docker.com`) spelled
as `docker.io` and official images under `library/` (for example
`registry-1.docker.io/nginx:1.27` matches `docker.io/library/nginx:*`; VEX
identifiers use the same normalization). How far normalization applies depends
on the list:

- `include` matches broadly, because an image that matches no include pattern
  skips verification. Short names are normalized (`nginx:1.27` matches
  `docker.io/library/nginx:*`), the bare repository is a match target, and a
  pattern with a tag part also covers digest-pinned references of the same
  repository (`ghcr.io/org/app:*` matches `ghcr.io/org/app@sha256:...`).
- `exclude` always relaxes verification and a rule can relax it, so `exclude`
  and rule `images` match conservatively: only the reported reference and, for
  references that
  already name a registry, its normalized `repository:tag` and
  `repository@digest` forms. A reference that carries a digest is only matched
  by its digest, because the runtime runs the digest and ignores the tag: the
  reported reference is matched without its tag, so neither
  `ghcr.io/org/app:v1` nor a tag wildcard such as `ghcr.io/org/app:v1*`
  matches `ghcr.io/org/app:v1.0@sha256:...`, while `ghcr.io/org/app@sha256:*`
  and `ghcr.io/org/**` do. Short names are not normalized, because the runtime
  may resolve them against other registries.

Rules are evaluated in order and can tighten verification as well as relax
it. A rule or exclude pattern scoped to a tag (`ghcr.io/org/app:prod-*`) never
matches a digest-pinned reference, since the pod author controls the tag and
the runtime ignores it. Such a reference falls through to later rules or the
base policy, so a tag-scoped rule cannot be relied on to tighten
verification: scope tightening rules by repository, covering both spellings
(`ghcr.io/org/app:*` and `ghcr.io/org/app@*`), or with `ghcr.io/org/**`, and
put them before broader relaxing rules. The plugin logs a warning for rule
`images` patterns scoped to a tag. A tag-scoped `exclude` fails safe
(digest-pinned references are verified) and is only logged at info level.

Common mistake: writing `nginx:*` as an exclude pattern will not match
`docker.io/library/nginx:latest` because `*` does not cross `/` boundaries.
Use the full reference `docker.io/library/nginx:*` instead.

### `trust.sanPatterns`

SAN patterns support glob-style wildcards that are converted to regular
expressions for certificate matching:

- `*` matches any sequence of non-`/` characters
- `**` matches any characters including `/`
- `?` matches any single non-`/` character
- `[...]` character classes are supported (including negation with `[^...]`
  or `[!...]`; negated classes never match `/`). Earlier releases matched
  `[!...]` literally, so policy loading logs a warning for patterns that use
  it; escape the bracket (`\[!`) to match a literal `[!`.
- All other characters are treated as literals

Example: `https://github.com/myorg/*` matches `https://github.com/myorg/repo`
but not `https://github.com/myorg/repo/.github/workflows/build.yaml@refs/heads/main`
(the `*` does not cross `/` boundaries). Use `**` for GitHub Actions workflow
SANs that include nested paths, for example
`https://github.com/myorg/repo/**`.

## Namespace Overrides

A file named `<namespace>.json` in the policy directory overrides
`default.json` for pods in that namespace. The file name must be
`default.json` or a lowercase Kubernetes namespace name (RFC 1123 label)
followed by `.json`; other names such as `Prod.json` fail the policy load
instead of silently never applying. Hidden files (names starting with `.`,
such as `.json`, editor backups, or `.#default.json` lock files) are skipped
with a warning. Symlinked policy files are
followed when they resolve inside the policy directory, as with Kubernetes
ConfigMap volumes. Any invalid or unreadable policy file fails the whole load,
and a reload that would replace loaded policies with an empty set is refused,
so a namespace never silently falls back to `default.json`.

By default, the override is a full replacement (except for `mode`, see
[`mode`](#mode-string)). If a namespace policy sets `"inherits": true`, unset
top-level fields (`trust`, `include`, `exclude`, `slsa`, `vex`, `vsa`,
`signatures`, `notation`, `sbom`, `scai`, `source`, `buildEnv`, `vulnScan`,
`testResult`, `release`, `runtimeTrace`, `scorecard`, `cel`, `rules`) are
inherited from the default policy. The default policy itself cannot set
`inherits`.

Sections set in both policies are merged field by field:

- A field that appears in the namespace policy replaces the default's value,
  including explicit `false`, `0`, and `""` values.
- Fields omitted from the namespace policy (or set to `null`) keep the
  default's value. For example, overriding only `slsa.maxAge` keeps the
  default `slsa.missingPolicy: "deny"`.
- Lists (for example `trust.builders` or `sbom.license.deny`) and maps replace
  the default's value as a whole.
- `include`, `exclude`, `rules`, and the `cel` section replace the default's
  value as a whole.
- Field names must use the documented spelling. JSON field matching is
  otherwise case-insensitive, so a policy spelling a field differently (for
  example `MissingPolicy`) is rejected instead of being silently ignored by the
  merge.

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
`include`, `exclude`, `slsa`, `vsa`, `signatures`, `notation`, `sbom`, `scai`,
`source`, `buildEnv`, `vulnScan`, `testResult`, `release`, `runtimeTrace`,
`scorecard`, `cel`, `rules`) from `default.json` and sets the two `vex` fields
on top of the default's `vex` section.

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

Use a trusted verifier to pre-verify images. When a valid VSA signed by the
verifier's key or identity exists, verification completes with a single
attestation check instead of fetching and verifying SLSA + VEX individually:

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

#### Time-bounded key rotation

Use `notBefore` and `notAfter` to restrict each key's validity window. Because
time bounds apply per-verifier (not per-key), use separate verifier entries
(with distinct IDs) when keys need different validity windows:

```json
{
  "trust": {
    "verifiers": [
      {
        "id": "https://verifier.internal/prod-2024",
        "keys": ["/etc/nri-supply-chain/keys/verifier-2024.pub"],
        "notBefore": "2024-01-01T00:00:00Z",
        "notAfter": "2025-01-01T00:00:00Z"
      },
      {
        "id": "https://verifier.internal/prod-2025",
        "keys": ["/etc/nri-supply-chain/keys/verifier-2025.pub"],
        "notBefore": "2024-12-01T00:00:00Z"
      }
    ]
  },
  "slsa": {
    "missingPolicy": "deny"
  }
}
```

The overlap between `notAfter` on the old entry and `notBefore` on the new
entry allows a smooth transition. Without `signatures.requireTransparencyLog`
the window is checked against the current time: once the old entry's
`notAfter` has passed, every attestation signed with the old key is rejected,
so re-sign attestations with the new key before that time. With
`requireTransparencyLog: true`, the window is checked against the transparency
log integrated time, and attestations logged before `notAfter` stay valid.
Replacing a key file in place and reloading the configuration invalidates
cached verification results.

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
    "sanPatterns": ["https://github.com/myorg/**"],
    "sources": ["https://github.com/myorg/*"]
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
[`deploy/examples/policies/`](../deploy/examples/policies/):

- [`default.json`](../deploy/examples/policies/default.json): Minimal default policy with trusted builders and keyless verification
- [`keyless.json`](../deploy/examples/policies/keyless.json): Keyless (Fulcio/OIDC) verification with GitHub Actions
- [`keybased.json`](../deploy/examples/policies/keybased.json): Key-based verification with PEM public keys
- [`key-rotation.json`](../deploy/examples/policies/key-rotation.json): Dual-key setup for rolling key rotation
- [`github-attestations.json`](../deploy/examples/policies/github-attestations.json): GitHub Actions `attest-build-provenance` with GitHub OIDC issuer
- [`custom-build-system.json`](../deploy/examples/policies/custom-build-system.json): Custom build system (Tekton) with explicit known parameters
- [`production.json`](../deploy/examples/policies/production.json): Strict production policy with provenance freshness and VSA requirements
- [`gradual-rollout.json`](../deploy/examples/policies/gradual-rollout.json): Gradual rollout from warn to enforce mode
- [`namespace-override.json`](../deploy/examples/policies/namespace-override.json): Namespace override with `inherits: true`
- [`vex-strict.json`](../deploy/examples/policies/vex-strict.json): Strict VEX verification requiring all images to have VEX attestations
- [`vsa-accelerated.json`](../deploy/examples/policies/vsa-accelerated.json): VSA-first verification that short-circuits direct checks
- [`sbom-deny-list.json`](../deploy/examples/policies/sbom-deny-list.json): SBOM component and license deny-list
- [`sbom-drift.json`](../deploy/examples/policies/sbom-drift.json): SBOM drift detection with baseline comparison thresholds
- [`cel-rules.json`](../deploy/examples/policies/cel-rules.json): CEL policy expressions for custom verification logic
- [`notation.json`](../deploy/examples/policies/notation.json): Notation (Notary v2) signature verification with CA trust store
- [`scai.json`](../deploy/examples/policies/scai.json): SCAI attribute report verification with required and forbidden attributes
- [`source-track.json`](../deploy/examples/policies/source-track.json): SLSA Source Track verification with trusted sources and minimum level
- [`build-env.json`](../deploy/examples/policies/build-env.json): Build environment verification with required and forbidden properties
- [`vuln-scan.json`](../deploy/examples/policies/vuln-scan.json): Vulnerability scan verification with CVSS thresholds and CVE ignore list
- [`test-result.json`](../deploy/examples/policies/test-result.json): Test result verification with required test suites
- [`release.json`](../deploy/examples/policies/release.json): Release attestation verification with trusted registries and required package IDs
- [`runtime-trace.json`](../deploy/examples/policies/runtime-trace.json): Runtime trace verification with trusted monitors and forbidden file patterns
