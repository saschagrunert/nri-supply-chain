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

@test "verify-image without config fails" {
	run_binary --verify-image "localhost:1/nonexistent:latest"
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"verification to be enabled"* ]]
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

@test "verify-namespace flag without config fails" {
	run_binary --verify-image "localhost:1/nonexistent:latest" --verify-namespace "kube-system"
	[[ "$status" -ne 0 ]]
	[[ "$output" == *"verification to be enabled"* ]]
}
