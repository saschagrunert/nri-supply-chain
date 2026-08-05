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

@test "valid max_attestation_size and cache_max_entries accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
max_attestation_size = 5242880
cache_max_entries = 500
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "max_attestation_size at minimum boundary accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
max_attestation_size = 1048576
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "max_attestation_size at maximum boundary accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
max_attestation_size = 104857600
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "max_attestation_size below minimum rejected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
max_attestation_size = 1000
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"max_attestation_size"* ]]
}

@test "max_attestation_size above maximum rejected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
max_attestation_size = 209715200
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"max_attestation_size"* ]]
}

@test "cache_max_entries at minimum boundary accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
cache_max_entries = 100
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "cache_max_entries at maximum boundary accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
cache_max_entries = 1000000
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}

@test "cache_max_entries below minimum rejected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
cache_max_entries = 50
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"cache_max_entries"* ]]
}

@test "cache_max_entries above maximum rejected" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
cache_max_entries = 2000000
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"cache_max_entries"* ]]
}

@test "both limits invalid collects multiple errors" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
max_attestation_size = 500
cache_max_entries = 10
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"max_attestation_size"* ]]
	[[ "$output" == *"cache_max_entries"* ]]
}

@test "default limits pass validation without explicit values" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
EOF
	run_binary --config "$TEST_DIR/config.toml" validate
	[[ "$status" -eq 0 ]]
}
