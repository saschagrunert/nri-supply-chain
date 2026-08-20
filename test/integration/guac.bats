#!/usr/bin/env bats

load helpers

@test "guac: valid endpoint accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac.internal:8080"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "guac: https endpoint accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "https://guac.internal:8443"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "guac: invalid endpoint rejected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "not-a-url"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"endpoint"* ]]
}

@test "guac: empty endpoint means disabled, passes validation" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = ""
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "guac: no guac section passes validation" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "guac: timeout zero rejected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
timeout = "0s"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"timeout"* ]]
}

@test "guac: timeout exceeding max rejected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
timeout = "60s"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"timeout"* ]]
}

@test "guac: custom timeout accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
timeout = "10s"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "guac: fallback_policy allow accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
fallback_policy = "allow"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "guac: fallback_policy deny accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
fallback_policy = "deny"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "guac: fallback_policy warn accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
fallback_policy = "warn"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "guac: invalid fallback_policy rejected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
fallback_policy = "invalid"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"fallback_policy"* ]]
}

@test "guac: valid check names accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
checks = ["certify_vuln", "certify_scorecard", "is_dependency"]
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "guac: single check accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
checks = ["certify_vuln"]
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "guac: unknown check name rejected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
checks = ["certify_vuln", "bogus_check"]
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"bogus_check"* ]]
}

@test "guac: empty checks rejected when endpoint is set" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
checks = []
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"checks"* ]]
}

@test "guac: max_dependencies in valid range accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
max_dependencies = 10
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "guac: max_dependencies zero rejected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
max_dependencies = 0
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"max_dependencies"* ]]
}

@test "guac: max_dependencies exceeding max rejected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
max_dependencies = 25
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"max_dependencies"* ]]
}

@test "guac: relative auth_token_path rejected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
auth_token_path = "relative/token"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"auth_token_path"* ]]
}

@test "guac: absolute auth_token_path accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
auth_token_path = "/var/run/secrets/guac/token"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "guac: relative ca_cert rejected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
ca_cert = "relative/ca.pem"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"ca_cert"* ]]
}

@test "guac: absolute ca_cert accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "http://guac:8080"
ca_cert = "/etc/pki/guac/ca.pem"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "guac: multiple validation errors collected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[guac]
endpoint = "not-a-url"
timeout = "0s"
checks = ["bogus"]
max_dependencies = 0
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"endpoint"* ]]
	[[ "$output" == *"timeout"* ]]
	[[ "$output" == *"bogus"* ]]
	[[ "$output" == *"max_dependencies"* ]]
}

@test "guac: ca_cert nonexistent file rejected at runtime" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "warn"
policy_dir = "$TEST_DIR/policies"

[guac]
endpoint = "http://guac:8080"
ca_cert = "/nonexistent/ca.pem"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"ca_cert"* ]]
}
