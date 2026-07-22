#!/usr/bin/env bats

load helpers

@test "verify-image with invalid image reference fails" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" --verify-image ":::invalid"
	[[ "$status" -ne 0 ]]
}

@test "verify-image uses default config when no config flag" {
	run_binary --verify-image "localhost:1/nonexistent:latest"
	[[ "$status" -eq 0 ]]
	[[ "$output" == *"verification disabled"* ]]
}

@test "verify-image with unreachable registry fails" {
	mkdir -p "$TEST_DIR/policies"
	echo '{}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "warn"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" --verify-image "localhost:1/nonexistent:latest"
	[[ "$status" -ne 0 ]]
}

@test "verify-namespace flag is accepted" {
	run_binary --verify-image "localhost:1/nonexistent:latest" --verify-namespace "kube-system"
	[[ "$status" -eq 0 ]]
	[[ "$output" == *"verification disabled"* ]]
}
