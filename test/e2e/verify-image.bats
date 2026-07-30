#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	start_registry
	generate_signing_key
	configure_insecure_registry

	VERIFY_IMAGE=$(push_test_image "verify-cli:v1")
	VERIFY_DIGEST=$(get_image_digest "$VERIFY_IMAGE")
	export VERIFY_IMAGE VERIFY_DIGEST

	local pred_dir="${BATS_FILE_TMPDIR}/predicates"
	mkdir -p "$pred_dir"

	write_slsa_predicate "${pred_dir}/verify-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$VERIFY_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/verify-slsa.json"

	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "builders": [{"id": "https://test-builder.example.com", "maxLevel": 3}],
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"

	write_plugin_config "enforce"
}

teardown_file() {
	stop_registry
	unconfigure_insecure_registry
}

setup() {
	true
}

teardown() {
	true
}

@test "verify with attested image shows verification passed" {
	local ref="${VERIFY_IMAGE}@${VERIFY_DIGEST}"
	run timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		verify "$ref" \
		--output json
	echo "# verify output: $output" >&2
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q '"allowed": true'
}

@test "verify with unsigned image shows verification failed" {
	local unsigned_image
	unsigned_image=$(push_test_image "verify-unsigned:v1")
	local unsigned_digest
	unsigned_digest=$(get_image_digest "$unsigned_image")
	local ref="${unsigned_image}@${unsigned_digest}"

	run timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		verify "$ref" \
		--output json
	echo "# verify output: $output" >&2
	[[ "$status" -ne 0 ]]
	echo "$output" | grep -q '"allowed": false'
}

@test "verify outputs valid JSON" {
	local ref="${VERIFY_IMAGE}@${VERIFY_DIGEST}"
	local json_out
	json_out=$(timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		verify "$ref" \
		--output json 2>/dev/null)
	echo "$json_out" | python3 -c "import sys, json; json.load(sys.stdin)"
}

@test "verify includes image and digest in output" {
	local ref="${VERIFY_IMAGE}@${VERIFY_DIGEST}"
	run timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		verify "$ref" \
		--output json
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q "\"digest\":"
	echo "$output" | grep -q "\"image\":"
}

@test "verify default table output shows ALLOWED" {
	local ref="${VERIFY_IMAGE}@${VERIFY_DIGEST}"
	run timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		verify "$ref"
	echo "# verify output: $output" >&2
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q "ALLOWED"
	echo "$output" | grep -q "Image:"
}

@test "verify multiple images via positional args" {
	local ref="${VERIFY_IMAGE}@${VERIFY_DIGEST}"
	local json_out
	json_out=$(timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		verify "$ref" "$ref" \
		--output json 2>/dev/null)
	echo "# verify output: $json_out" >&2
	echo "$json_out" | python3 -c "
import sys, json
data = json.load(sys.stdin)
assert isinstance(data, list), 'expected array'
assert len(data) == 2, f'expected 2 results, got {len(data)}'
assert all(r['allowed'] for r in data), 'expected all allowed'
"
}

@test "verify with disabled verification fails" {
	local ref="${VERIFY_IMAGE}@${VERIFY_DIGEST}"
	local disabled_config="${BATS_FILE_TMPDIR}/disabled-config.toml"
	cat >"$disabled_config" <<-EOF
		verification = "disabled"
		policy_dir = "${POLICY_DIR}"
		fetch_timeout = "30s"
		metrics_addr = ":9093"
	EOF

	run timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$disabled_config" \
		verify "$ref"
	[[ "$status" -ne 0 ]]
}
