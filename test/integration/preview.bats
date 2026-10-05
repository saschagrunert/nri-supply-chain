#!/usr/bin/env bats

load helpers

bats_require_minimum_version 1.5.0

write_warn_config() {
	mkdir -p "$TEST_DIR/policies"
	echo '{"slsa": {"missingPolicy": "warn"}}' >"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "warn"
policy_dir = "$TEST_DIR/policies"
fetch_timeout = "5s"
EOF
}

@test "preview without images fails" {
	write_warn_config
	run_binary --config "$TEST_DIR/config.toml" preview
	[[ "$status" -eq 2 ]]
	[[ "$output" == *"No images specified"* ]]
}

@test "preview rejects the quiet output format" {
	write_warn_config
	run_binary --config "$TEST_DIR/config.toml" preview -o quiet "localhost:1/app:latest"
	[[ "$status" -eq 2 ]]
	[[ "$output" == *"valid options are: table, json"* ]]
	[[ "$output" != *"Preview Summary"* ]]
}

@test "verify still accepts the quiet output format" {
	write_warn_config
	run_binary --config "$TEST_DIR/config.toml" verify -o quiet "localhost:1/app:latest"
	[[ "$status" -eq 2 ]]
	[[ "$output" != *"valid options are"* ]]
}

@test "preview with unreachable registry exits with an error and reports it" {
	write_warn_config
	run --separate-stderr "$BINARY" --config "$TEST_DIR/config.toml" \
		preview -o json "localhost:1/app:latest"
	[[ "$status" -eq 2 ]]
	[[ "$output" == *'"total": 1'* ]]
	[[ "$output" == *'"errors": 1'* ]]
}

@test "preview --images-file reads images, skipping comments and duplicates" {
	write_warn_config
	cat >"$TEST_DIR/images.txt" <<EOF
# images to preview
localhost:1/app:latest

localhost:1/app:latest
localhost:1/other:latest
EOF
	run --separate-stderr "$BINARY" --config "$TEST_DIR/config.toml" \
		preview -o json --images-file "$TEST_DIR/images.txt" "localhost:1/third:latest"
	[[ "$status" -eq 2 ]]
	[[ "$output" == *'"total": 3'* ]]
	[[ "$output" == *'"image": "localhost:1/third:latest"'* ]]
	[[ "$output" == *'"image": "localhost:1/other:latest"'* ]]
}

@test "preview --images-file with a missing file fails" {
	write_warn_config
	run_binary --config "$TEST_DIR/config.toml" \
		preview --images-file "$TEST_DIR/missing.txt"
	[[ "$status" -eq 2 ]]
	[[ "$output" == *"opening images file"* ]]
}

@test "preview --compare-policy prints a diff" {
	write_warn_config
	mkdir -p "$TEST_DIR/proposed"
	echo '{"slsa": {"missingPolicy": "deny"}}' >"$TEST_DIR/proposed/default.json"
	run --separate-stderr "$BINARY" --config "$TEST_DIR/config.toml" \
		preview -o json --compare-policy "$TEST_DIR/proposed" "localhost:1/app:latest"
	[[ "$status" -eq 2 ]]
	[[ "$output" == *'"current"'* ]]
	[[ "$output" == *'"proposed"'* ]]
	[[ "$output" == *'"unchanged": 1'* ]]
}

@test "preview --compare-policy rejects the quiet output format" {
	write_warn_config
	run_binary --config "$TEST_DIR/config.toml" \
		preview -o quiet --compare-policy "$TEST_DIR/policies" "localhost:1/app:latest"
	[[ "$status" -eq 2 ]]
	[[ "$output" == *"valid options are: table, json"* ]]
}

@test "verify --preview-policy uses the preview policy with an OCI policy source" {
	echo '{"slsa": {"missingPolicy": "warn"}}' >"$TEST_DIR/preview.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "warn"
fetch_timeout = "5s"

[policy]
source = "oci"
oci_ref = "localhost:1/policies:v1"
EOF
	run_binary --config "$TEST_DIR/config.toml" \
		verify --preview-policy "$TEST_DIR/preview.json" "localhost:1/app:latest"
	[[ "$status" -eq 2 ]]
	[[ "$output" == *"Using the local preview policies instead of the configured OCI policies"* ]]
	# The configured OCI policies must not be fetched.
	[[ "$output" != *"OCI policy fetch failed"* ]]
}
