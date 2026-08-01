#!/usr/bin/env bats

load helpers

@test "enforce mode with valid policy file succeeds" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "trust": {
        "builders": [{"id": "https://github.com/actions/runner", "maxLevel": 3}]
    },
    "slsa": {"missingPolicy": "deny"}
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "policy with all verification types configured" {
	mkdir -p "$TEST_DIR/policies" "$TEST_DIR/keys"
	touch "$TEST_DIR/keys/v.pub"
	cat >"$TEST_DIR/policies/production.json" <<EOF
{
    "trust": {
        "builders": [{"id": "https://github.com/actions/runner", "maxLevel": 3}],
        "verifiers": [{"id": "https://example.com/verifier", "keys": ["$TEST_DIR/keys/v.pub"]}],
        "sources": ["github.com/myorg/*"],
        "buildTypes": ["https://actions.github.io/buildtypes/workflow/v1"]
    },
    "slsa": {
        "missingPolicy": "deny",
        "rejectUnknownParameters": true
    },
    "vex": {
        "missingPolicy": "allow",
        "underInvestigationPolicy": "allow"
    },
    "vsa": {
        "minimumLevel": 2,
        "maxAge": "24h",
        "policy": "https://example.com/policy"
    },
    "signatures": {
        "requireTransparencyLog": true
    },
    "sbom": {
        "missingPolicy": "allow",
        "formats": ["spdx", "cyclonedx"]
    },
    "exclude": ["test-*", "dev-*"]
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "multiple namespace policies coexist" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{"slsa": {"missingPolicy": "allow"}}
EOF
	cat >"$TEST_DIR/policies/production.json" <<EOF
{
    "trust": {
        "builders": [{"id": "https://github.com/actions/runner", "maxLevel": 3}]
    },
    "slsa": {"missingPolicy": "deny"}
}
EOF
	cat >"$TEST_DIR/policies/staging.json" <<EOF
{"slsa": {"missingPolicy": "warn"}}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "policy with exclude patterns" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "exclude": ["kube-system", "istio-*", "test-*"],
    "slsa": {"missingPolicy": "deny"}
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "policy with VEX policies" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "vex": {
        "missingPolicy": "allow",
        "underInvestigationPolicy": "deny"
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "invalid policy JSON rejected" {
	mkdir -p "$TEST_DIR/policies"
	echo "not valid json" >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
}

@test "policy with unknown JSON fields rejected" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "unknownField": "value",
    "slsa": {"missingPolicy": "allow"}
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
}

@test "policy with trusted issuers for keyless verification" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "trust": {
        "issuers": ["https://accounts.google.com", "https://token.actions.githubusercontent.com"],
        "sanPatterns": ["*@example.com"],
        "builders": [{"id": "https://github.com/actions/runner", "maxLevel": 3}]
    },
    "signatures": {
        "requireTransparencyLog": true
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "enforce mode rejects issuers without SANPatterns" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "trust": {
        "issuers": ["https://accounts.google.com"]
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"sanPatterns is required"* ]]
}

@test "warn mode allows issuers without SANPatterns" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "trust": {
        "issuers": ["https://accounts.google.com"]
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "warn"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "policy with builder missing ID rejected" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "trust": {
        "builders": [{"id": "", "maxLevel": 3}]
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"builder id is required"* ]]
}

@test "policy with builder maxLevel out of range rejected" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "trust": {
        "builders": [{"id": "https://example.com/builder", "maxLevel": 5}]
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"maxLevel"* ]]
}

@test "policy with keyless verifier without issuers rejected" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "trust": {
        "verifiers": [{"id": "https://example.com/v"}]
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"keyless verifier requires trust.issuers"* ]]
}

@test "policy with relative verifier key path rejected" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "trust": {
        "verifiers": [{"id": "https://example.com/v", "keys": ["relative/path.pub"]}]
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"absolute path"* ]]
}

@test "policy with invalid VSA minimum level rejected" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "vsa": {
        "minimumLevel": 5
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"minimum level"* ]]
}

@test "policy with trailing JSON content rejected" {
	mkdir -p "$TEST_DIR/policies"
	printf '{"slsa": {"missingPolicy": "allow"}} {"extra": true}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"trailing"* ]]
}

@test "keyless policy with issuers and SAN patterns accepted by validate" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "trust": {
        "issuers": [
            "https://accounts.google.com",
            "https://token.actions.githubusercontent.com"
        ],
        "sanPatterns": ["*@example.com", "ci-bot@build.internal"]
    },
    "signatures": {
        "requireTransparencyLog": true
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "keyless policy in warn mode accepted without SAN patterns" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "trust": {
        "issuers": ["https://accounts.google.com"]
    },
    "signatures": {
        "requireTransparencyLog": false
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "warn"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "policy with valid CEL rules passes validation" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "cel": {
        "rules": [
            {
                "match": "image.registry == 'ghcr.io'",
                "require": "slsa.verified == true",
                "message": "GHCR images must have SLSA provenance"
            }
        ]
    },
    "slsa": {"missingPolicy": "allow"}
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "policy with invalid CEL syntax rejected" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "cel": {
        "rules": [
            {
                "require": "image.registry ===== 'invalid'",
                "message": "this expression has bad syntax"
            }
        ]
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"CEL"* ]]
}

@test "policy with VSA configuration" {
	mkdir -p "$TEST_DIR/policies" "$TEST_DIR/keys"
	touch "$TEST_DIR/keys/v.pub"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "trust": {
        "verifiers": [{"id": "https://example.com/v", "keys": ["$TEST_DIR/keys/v.pub"]}]
    },
    "vsa": {
        "minimumLevel": 3,
        "maxAge": "48h",
        "policy": "https://example.com/strict-policy"
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "policy with SBOM configuration" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "sbom": {
        "missingPolicy": "deny",
        "formats": ["spdx", "cyclonedx"],
        "license": {"deny": ["AGPL-3.0", "GPL-3.0"]},
        "component": {"deny": ["pkg:npm/event-stream@3.3.6"]}
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "policy with invalid SBOM format rejected" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "sbom": {
        "formats": ["invalid"]
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"invalid sbom format"* ]]
}

@test "policy with invalid SBOM component PURL rejected" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/policies/default.json" <<EOF
{
    "sbom": {
        "component": {"deny": ["not-a-purl"]}
    }
}
EOF
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"valid PURL"* ]]
}
