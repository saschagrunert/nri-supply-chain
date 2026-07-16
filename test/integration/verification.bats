#!/usr/bin/env bats

load helpers

@test "enforce mode with missing policy dir fails" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "/nonexistent/policy/dir"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
}

@test "enforce mode with empty policy dir and version flag succeeds" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" --version
	[[ "$status" -eq 0 ]]
	[[ "$output" == *"nri-supply-chain v"* ]]
}

@test "disabled mode ignores policy dir" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
policy_dir = "/nonexistent"
EOF
	run_binary --config "$TEST_DIR/config.toml" --version
	[[ "$status" -eq 0 ]]
}

@test "warn mode with valid policy dir and version flag succeeds" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "warn"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" --version
	[[ "$status" -eq 0 ]]
}

@test "fetch timeout must be positive" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
fetch_timeout = "0s"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
}

@test "invalid fetch failure policy rejected" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
fetch_failure_policy = "invalid"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
}

@test "fetch failure policy allow accepted" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
fetch_failure_policy = "allow"
EOF
	run_binary --config "$TEST_DIR/config.toml" --version
	[[ "$status" -eq 0 ]]
}

@test "fetch failure policy deny accepted" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
fetch_failure_policy = "deny"
EOF
	run_binary --config "$TEST_DIR/config.toml" --version
	[[ "$status" -eq 0 ]]
}

@test "invalid verification mode rejected" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "invalid"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"invalid"* ]]
}

@test "negative cache_ttl rejected" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
cache_ttl = "-1s"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
}

@test "relative policy_dir rejected in enforce mode" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "relative/path"
EOF
	run_binary --config "$TEST_DIR/config.toml"
	[[ "$status" -ne 0 ]]
}

@test "cache_ttl zero accepted (caching disabled)" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
cache_ttl = "0s"
EOF
	run_binary --config "$TEST_DIR/config.toml" --version
	[[ "$status" -eq 0 ]]
}

@test "custom fetch timeout accepted" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
fetch_timeout = "60s"
EOF
	run_binary --config "$TEST_DIR/config.toml" --version
	[[ "$status" -eq 0 ]]
}

@test "custom metrics address accepted" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "warn"
policy_dir = "$TEST_DIR/policies"
metrics_addr = ":9091"
EOF
	run_binary --config "$TEST_DIR/config.toml" --version
	[[ "$status" -eq 0 ]]
}

@test "debug log level accepted" {
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
policy_dir = "/tmp"
EOF
	run_binary --config "$TEST_DIR/config.toml" --log-level debug --version
	[[ "$status" -eq 0 ]]
}
