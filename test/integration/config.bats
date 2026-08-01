#!/usr/bin/env bats

load helpers

@test "missing config file fails" {
	run_binary --config /nonexistent/config.toml validate
	[[ "$status" -ne 0 ]]
}

@test "invalid config file fails" {
	echo "invalid = [" >"$TEST_DIR/bad.toml"
	run_binary --config "$TEST_DIR/bad.toml" validate
	[[ "$status" -ne 0 ]]
}

@test "valid config file succeeds validation" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
policy_dir = "/etc/nri-supply-chain/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "invalid verification mode rejected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "invalid"
policy_dir = "/tmp"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
}

@test "warn mode with missing policy dir fails at runtime" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "warn"
fetch_timeout = "10s"
policy_dir = "/nonexistent/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
}

@test "warn mode with valid policy dir succeeds" {
	mkdir -p "$TEST_DIR/policies"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "warn"
fetch_timeout = "10s"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "OCI source with valid oci_ref and custom poll_interval passes" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[policy]
source = "oci"
oci_ref = "ghcr.io/myorg/policies:v1"
poll_interval = "10m"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "OCI source with missing oci_ref fails" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[policy]
source = "oci"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"oci_ref"* ]]
}

@test "OCI source with poll_interval below minimum fails" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[policy]
source = "oci"
oci_ref = "ghcr.io/myorg/policies:v1"
poll_interval = "10s"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"30s"* ]]
}

@test "unknown policy source fails" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"

[policy]
source = "ftp"
oci_ref = "ghcr.io/myorg/policies:v1"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"source"* ]]
}
