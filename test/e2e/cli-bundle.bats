#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	start_registry
	generate_signing_key
	configure_insecure_registry

	BUNDLE_IMAGE=$(push_test_image "bundle-test:v1")
	BUNDLE_DIGEST=$(get_image_digest "$BUNDLE_IMAGE")
	export BUNDLE_IMAGE BUNDLE_DIGEST

	local pred_dir="${BATS_FILE_TMPDIR}/predicates"
	mkdir -p "$pred_dir"

	write_slsa_predicate "${pred_dir}/bundle-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$BUNDLE_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/bundle-slsa.json"

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

	write_plugin_config "warn"

	BUNDLE_SIGN_KEY="${BATS_FILE_TMPDIR}/bundle-sign.key"
	BUNDLE_SIGN_PUB="${BATS_FILE_TMPDIR}/bundle-sign.pub"
	openssl ecparam -genkey -name prime256v1 -noout -out "$BUNDLE_SIGN_KEY" 2>/dev/null
	openssl ec -in "$BUNDLE_SIGN_KEY" -pubout -out "$BUNDLE_SIGN_PUB" 2>/dev/null
	export BUNDLE_SIGN_KEY BUNDLE_SIGN_PUB
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

# -- bundle create tests --

@test "bundle create produces a tar.gz bundle" {
	local bundle_out="${BATS_TEST_TMPDIR}/test-bundle.tar.gz"
	local ref="${BUNDLE_IMAGE}@${BUNDLE_DIGEST}"
	run timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		bundle create \
		--image "$ref" \
		--output "$bundle_out"
	echo "# bundle create output: $output" >&2
	[[ "$status" -eq 0 ]]
	[[ -f "$bundle_out" ]]
	file "$bundle_out" | grep -q "gzip"
}

@test "bundle create with signing produces signed bundle" {
	local bundle_out="${BATS_TEST_TMPDIR}/signed-bundle.tar.gz"
	local ref="${BUNDLE_IMAGE}@${BUNDLE_DIGEST}"
	run timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		bundle create \
		--image "$ref" \
		--output "$bundle_out" \
		--sign-key "$BUNDLE_SIGN_KEY"
	echo "# bundle create output: $output" >&2
	[[ "$status" -eq 0 ]]
	[[ -f "$bundle_out" ]]
}

@test "bundle create fails without --output" {
	local ref="${BUNDLE_IMAGE}@${BUNDLE_DIGEST}"
	run timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		bundle create \
		--image "$ref"
	[[ "$status" -ne 0 ]]
}

@test "bundle create fails without --image" {
	run timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		bundle create \
		--output "${BATS_TEST_TMPDIR}/empty.tar.gz"
	[[ "$status" -ne 0 ]]
}

# -- bundle import and inspect round-trip --

@test "bundle create, import, and inspect round-trip" {
	local bundle_out="${BATS_TEST_TMPDIR}/roundtrip-bundle.tar.gz"
	local store_dir="${BATS_TEST_TMPDIR}/store"
	local ref="${BUNDLE_IMAGE}@${BUNDLE_DIGEST}"

	# Create
	run timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		bundle create \
		--image "$ref" \
		--output "$bundle_out"
	echo "# create output: $output" >&2
	[[ "$status" -eq 0 ]]

	# Import
	run timeout "$CMD_TIMEOUT" "$BINARY" \
		bundle import "$bundle_out" \
		--store "$store_dir"
	echo "# import output: $output" >&2
	[[ "$status" -eq 0 ]]
	[[ -d "$store_dir" ]]

	# Inspect (table format)
	run timeout "$CMD_TIMEOUT" "$BINARY" \
		bundle inspect "$store_dir"
	echo "# inspect output: $output" >&2
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q "VERSION"
	echo "$output" | grep -q "IMAGES"

	# Inspect (JSON format)
	local json_out
	json_out=$(timeout "$CMD_TIMEOUT" "$BINARY" \
		bundle inspect "$store_dir" \
		--output json 2>/dev/null)
	echo "# inspect JSON: $json_out" >&2
	echo "$json_out" | python3 -c "
import sys, json
data = json.load(sys.stdin)
assert data['version'] == 1, f'expected version 1, got {data[\"version\"]}'
assert data['imageCount'] > 0, 'expected at least one image'
"
}

# -- bundle verify tests --

@test "bundle verify checks integrity" {
	local bundle_out="${BATS_TEST_TMPDIR}/verify-bundle.tar.gz"
	local store_dir="${BATS_TEST_TMPDIR}/verify-store"
	local ref="${BUNDLE_IMAGE}@${BUNDLE_DIGEST}"

	timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		bundle create \
		--image "$ref" \
		--output "$bundle_out"

	timeout "$CMD_TIMEOUT" "$BINARY" \
		bundle import "$bundle_out" \
		--store "$store_dir"

	run timeout "$CMD_TIMEOUT" "$BINARY" \
		bundle verify "$store_dir"
	echo "# verify output: $output" >&2
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q "Blob integrity: OK"
	echo "$output" | grep -q "Bundle verification passed"
}

@test "bundle verify with signature" {
	local bundle_out="${BATS_TEST_TMPDIR}/signed-verify-bundle.tar.gz"
	local store_dir="${BATS_TEST_TMPDIR}/signed-verify-store"
	local ref="${BUNDLE_IMAGE}@${BUNDLE_DIGEST}"

	timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		bundle create \
		--image "$ref" \
		--output "$bundle_out" \
		--sign-key "$BUNDLE_SIGN_KEY"

	timeout "$CMD_TIMEOUT" "$BINARY" \
		bundle import "$bundle_out" \
		--store "$store_dir"

	run timeout "$CMD_TIMEOUT" "$BINARY" \
		bundle verify "$store_dir" \
		--key "$BUNDLE_SIGN_PUB"
	echo "# verify output: $output" >&2
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q "Signature: OK"
	echo "$output" | grep -q "Bundle verification passed"
}

@test "bundle verify with wrong key fails" {
	local bundle_out="${BATS_TEST_TMPDIR}/wrongkey-bundle.tar.gz"
	local store_dir="${BATS_TEST_TMPDIR}/wrongkey-store"
	local ref="${BUNDLE_IMAGE}@${BUNDLE_DIGEST}"

	# Create a second key pair
	local wrong_key="${BATS_TEST_TMPDIR}/wrong.key"
	local wrong_pub="${BATS_TEST_TMPDIR}/wrong.pub"
	openssl ecparam -genkey -name prime256v1 -noout -out "$wrong_key" 2>/dev/null
	openssl ec -in "$wrong_key" -pubout -out "$wrong_pub" 2>/dev/null

	timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		bundle create \
		--image "$ref" \
		--output "$bundle_out" \
		--sign-key "$BUNDLE_SIGN_KEY"

	timeout "$CMD_TIMEOUT" "$BINARY" \
		bundle import "$bundle_out" \
		--store "$store_dir"

	run timeout "$CMD_TIMEOUT" "$BINARY" \
		bundle verify "$store_dir" \
		--key "$wrong_pub"
	echo "# verify output: $output" >&2
	[[ "$status" -ne 0 ]]
}

# -- bundle import with signature verification --

@test "bundle import with valid signature key succeeds" {
	local bundle_out="${BATS_TEST_TMPDIR}/import-sig-bundle.tar.gz"
	local store_dir="${BATS_TEST_TMPDIR}/import-sig-store"
	local ref="${BUNDLE_IMAGE}@${BUNDLE_DIGEST}"

	timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		bundle create \
		--image "$ref" \
		--output "$bundle_out" \
		--sign-key "$BUNDLE_SIGN_KEY"

	run timeout "$CMD_TIMEOUT" "$BINARY" \
		bundle import "$bundle_out" \
		--store "$store_dir" \
		--key "$BUNDLE_SIGN_PUB"
	echo "# import output: $output" >&2
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q "Bundle imported"
}

@test "bundle import with wrong signature key fails" {
	local bundle_out="${BATS_TEST_TMPDIR}/import-wrongsig-bundle.tar.gz"
	local store_dir="${BATS_TEST_TMPDIR}/import-wrongsig-store"
	local ref="${BUNDLE_IMAGE}@${BUNDLE_DIGEST}"

	local wrong_key="${BATS_TEST_TMPDIR}/wrong2.key"
	local wrong_pub="${BATS_TEST_TMPDIR}/wrong2.pub"
	openssl ecparam -genkey -name prime256v1 -noout -out "$wrong_key" 2>/dev/null
	openssl ec -in "$wrong_key" -pubout -out "$wrong_pub" 2>/dev/null

	timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		bundle create \
		--image "$ref" \
		--output "$bundle_out" \
		--sign-key "$BUNDLE_SIGN_KEY"

	run timeout "$CMD_TIMEOUT" "$BINARY" \
		bundle import "$bundle_out" \
		--store "$store_dir" \
		--key "$wrong_pub"
	echo "# import output: $output" >&2
	[[ "$status" -ne 0 ]]
	[[ ! -d "$store_dir" ]]
}

@test "bundle import without --store fails" {
	local bundle_out="${BATS_TEST_TMPDIR}/nostore-bundle.tar.gz"
	local ref="${BUNDLE_IMAGE}@${BUNDLE_DIGEST}"

	timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		bundle create \
		--image "$ref" \
		--output "$bundle_out"

	run timeout "$CMD_TIMEOUT" "$BINARY" \
		bundle import "$bundle_out"
	[[ "$status" -ne 0 ]]
}

# -- bundle verify with max-age --

@test "bundle verify with max-age rejects old bundles" {
	local bundle_out="${BATS_TEST_TMPDIR}/age-bundle.tar.gz"
	local store_dir="${BATS_TEST_TMPDIR}/age-store"
	local ref="${BUNDLE_IMAGE}@${BUNDLE_DIGEST}"

	timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		bundle create \
		--image "$ref" \
		--output "$bundle_out"

	timeout "$CMD_TIMEOUT" "$BINARY" \
		bundle import "$bundle_out" \
		--store "$store_dir"

	# 1ns max-age should always fail since any bundle is older than 1ns
	run timeout "$CMD_TIMEOUT" "$BINARY" \
		bundle verify "$store_dir" \
		--max-age "1ns"
	echo "# verify output: $output" >&2
	[[ "$status" -ne 0 ]]
}
