#!/usr/bin/env bats

load helpers

@test "missing config file fails" {
    run_binary --config /nonexistent/config.toml
    [[ "$status" -ne 0 ]]
}

@test "invalid config file fails" {
    echo "invalid = [" >"$TEST_DIR/bad.toml"
    run_binary --config "$TEST_DIR/bad.toml"
    [[ "$status" -ne 0 ]]
}

@test "version flag with config file prints version and exits" {
    cat >"$TEST_DIR/config.toml" <<EOF
verification = "disabled"
policy_dir = "/etc/nri-supply-chain/policies"
EOF
    run_binary --config "$TEST_DIR/config.toml" --version
    [[ "$status" -eq 0 ]]
    [[ "$output" == *"nri-supply-chain v"* ]]
}

@test "invalid verification mode rejected" {
    cat >"$TEST_DIR/config.toml" <<EOF
verification = "invalid"
policy_dir = "/tmp"
EOF
    run_binary --config "$TEST_DIR/config.toml"
    [[ "$status" -ne 0 ]]
}

@test "warn mode with missing policy dir fails at runtime" {
    cat >"$TEST_DIR/config.toml" <<EOF
verification = "warn"
fetch_timeout = "10s"
policy_dir = "/nonexistent/policies"
EOF
    run_binary --config "$TEST_DIR/config.toml"
    [[ "$status" -ne 0 ]]
}

@test "warn mode with valid policy dir and version flag succeeds" {
    mkdir -p "$TEST_DIR/policies"
    cat >"$TEST_DIR/config.toml" <<EOF
verification = "warn"
fetch_timeout = "10s"
policy_dir = "$TEST_DIR/policies"
EOF
    run_binary --config "$TEST_DIR/config.toml" --version
    [[ "$status" -eq 0 ]]
}
