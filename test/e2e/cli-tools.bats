#!/usr/bin/env bats

load helpers

bats_require_minimum_version 1.5.0

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	start_registry
	generate_signing_key
	configure_insecure_registry

	CLI_IMAGE=$(push_test_image "cli-test:v1")
	CLI_DIGEST=$(get_image_digest "$CLI_IMAGE")
	export CLI_IMAGE CLI_DIGEST

	local pred_dir="${BATS_FILE_TMPDIR}/predicates"
	mkdir -p "$pred_dir"

	write_slsa_predicate "${pred_dir}/cli-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$CLI_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/cli-slsa.json"

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

	write_policy "production" "$(
		cat <<-EOF
			{
			  "inherits": true,
			  "slsa": {"missingPolicy": "deny"}
			}
		EOF
	)"

	write_plugin_config "warn"
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

# -- effective-policy tests --

@test "effective-policy shows default policy" {
	local json_out
	json_out=$(timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		effective-policy 2>/dev/null)
	echo "# effective-policy output: $json_out" >&2
	echo "$json_out" | python3 -c "
import sys, json
data = json.load(sys.stdin)
assert data['namespace'] == 'default', f'expected default namespace, got {data[\"namespace\"]}'
assert data['source'] == 'default', f'expected source default, got {data[\"source\"]}'
assert data['ruleIndex'] == -1, f'expected ruleIndex -1, got {data[\"ruleIndex\"]}'
assert data['policy'] is not None, 'expected non-null policy'
"
}

@test "effective-policy shows namespace policy" {
	local json_out
	json_out=$(timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		effective-policy --namespace production 2>/dev/null)
	echo "# effective-policy output: $json_out" >&2
	echo "$json_out" | python3 -c "
import sys, json
data = json.load(sys.stdin)
assert data['namespace'] == 'production', f'expected production namespace, got {data[\"namespace\"]}'
assert data['source'] == 'namespace', f'expected source namespace, got {data[\"source\"]}'
assert data['policy'] is not None, 'expected non-null policy'
"
}

@test "effective-policy falls back to default for unknown namespace" {
	local json_out
	json_out=$(timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		effective-policy --namespace nonexistent 2>/dev/null)
	echo "# effective-policy output: $json_out" >&2
	echo "$json_out" | python3 -c "
import sys, json
data = json.load(sys.stdin)
assert data['namespace'] == 'nonexistent'
assert data['source'] == 'default', f'expected source default, got {data[\"source\"]}'
assert data['policy'] is not None, 'expected fallback to default policy'
"
}

@test "effective-policy outputs valid JSON" {
	local json_out
	json_out=$(timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		effective-policy 2>/dev/null)
	echo "$json_out" | python3 -c "import sys, json; json.load(sys.stdin)"
}

# -- inspect tests --

@test "inspect lists attestations" {
	local ref="${CLI_IMAGE}@${CLI_DIGEST}"
	local json_out
	json_out=$(timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		inspect "$ref" \
		--output json 2>/dev/null)
	echo "# inspect output: $json_out" >&2
	echo "$json_out" | python3 -c "
import sys, json
data = json.load(sys.stdin)
assert 'attestations' in data, 'expected attestations field'
assert len(data['attestations']) > 0, 'expected at least one attestation'
"
}

@test "inspect default table output shows Image and Digest" {
	local ref="${CLI_IMAGE}@${CLI_DIGEST}"
	local table_out
	table_out=$(timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		inspect "$ref" 2>/dev/null)
	echo "# inspect output: $table_out" >&2
	echo "$table_out" | grep -q "Image:"
	echo "$table_out" | grep -q "Digest:"
	echo "$table_out" | grep -q "Attestations:"
}

@test "inspect outputs valid JSON" {
	local ref="${CLI_IMAGE}@${CLI_DIGEST}"
	local json_out
	json_out=$(timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		inspect "$ref" \
		--output json 2>/dev/null)
	echo "$json_out" | python3 -c "import sys, json; json.load(sys.stdin)"
}

# -- json-schema config tests --

@test "json-schema config outputs valid JSON schema" {
	local json_out
	json_out=$(timeout "$CMD_TIMEOUT" "$BINARY" json-schema config 2>/dev/null)
	echo "# json-schema config output (first 200 chars): ${json_out:0:200}" >&2
	echo "$json_out" | python3 -c "
import sys, json
schema = json.load(sys.stdin)
assert '\$schema' in schema or '\$ref' in schema or 'properties' in schema, \
    'expected JSON Schema structure'
"
}

# -- verbose verify tests --

@test "verify --verbose shows diagnostic output" {
	local ref="${CLI_IMAGE}@${CLI_DIGEST}"
	local verbose_out
	verbose_out=$(timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		verify "$ref" --verbose 2>&1)
	echo "# verbose verify output: $verbose_out" >&2
	echo "$verbose_out" | grep -q "Mode:"
	echo "$verbose_out" | grep -q "Policy dir:"
	echo "$verbose_out" | grep -q "Images:"
}

# -- preview tests --

@test "preview summarizes an attested image" {
	local ref="${CLI_IMAGE}@${CLI_DIGEST}"
	run --separate-stderr timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		preview "$ref" --output json
	echo "# preview output: $output" >&2
	[[ "$status" -eq 0 ]]
	echo "$output" | python3 -c "
import sys, json
data = json.load(sys.stdin)
summary = data['summary']
assert summary['total'] == 1, f'expected 1 image, got {summary[\"total\"]}'
assert summary['allowed'] == 1, f'expected 1 allowed image, got {summary[\"allowed\"]}'
assert summary['checks']['slsa']['pass'] == 1, f'expected SLSA to pass, got {summary[\"checks\"]}'
"
}

@test "preview --images-file previews the listed images" {
	local ref="${CLI_IMAGE}@${CLI_DIGEST}"
	local images_file="${BATS_FILE_TMPDIR}/preview-images.txt"
	cat >"$images_file" <<-EOF
		# images to preview
		${ref}

		${ref}
	EOF
	run --separate-stderr timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$PLUGIN_CONFIG" \
		preview --images-file "$images_file" --output json
	echo "# preview output: $output" >&2
	[[ "$status" -eq 0 ]]
	echo "$output" | python3 -c "
import sys, json
data = json.load(sys.stdin)
assert data['summary']['total'] == 1, f'expected duplicates to be removed, got {data[\"summary\"]}'
assert data['images'][0]['image'] == '${ref}'
"
}

@test "preview --compare-policy reports images the proposed policy denies" {
	local ref="${CLI_IMAGE}@${CLI_DIGEST}"
	local proposed_dir="${BATS_FILE_TMPDIR}/proposed-policies"
	local enforce_config="${BATS_FILE_TMPDIR}/preview-enforce.toml"
	mkdir -p "$proposed_dir"
	cat >"${proposed_dir}/default.json" <<-EOF
		{
		  "trust": {
		    "builders": [{"id": "https://test-builder.example.com", "maxLevel": 3}],
		    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
		  },
		  "slsa": {"missingPolicy": "deny"},
		  "vex": {"missingPolicy": "deny"},
		  "signatures": {"requireTransparencyLog": false}
		}
	EOF
	sed 's/^verification = .*/verification = "enforce"/' "$PLUGIN_CONFIG" >"$enforce_config"

	run --separate-stderr timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$enforce_config" \
		preview "$ref" --compare-policy "$proposed_dir" --output json
	echo "# preview diff output: $output" >&2
	# The image has no VEX attestation, so the proposed policy denies it.
	[[ "$status" -eq 1 ]]
	echo "$output" | python3 -c "
import sys, json
data = json.load(sys.stdin)
summary = data['summary']
assert summary['changed'] == 1, f'expected 1 changed image, got {summary}'
assert summary['newDenied'] == 1, f'expected 1 newly denied image, got {summary}'
assert data['images'][0]['current']['allowed'] is True
assert data['images'][0]['proposed']['allowed'] is False
"
}

@test "verify --preview-policy ignores the configured OCI policy source" {
	local ref="${CLI_IMAGE}@${CLI_DIGEST}"
	local oci_config="${BATS_FILE_TMPDIR}/preview-oci.toml"
	local preview_policy="${BATS_FILE_TMPDIR}/preview-policy.json"
	cp "${POLICY_DIR}/default.json" "$preview_policy"
	# No policy artifact exists at oci_ref, so loading the OCI policies fails.
	cat >"$oci_config" <<-EOF
		verification = "warn"
		fetch_timeout = "30s"

		[policy]
		source = "oci"
		oci_ref = "${REGISTRY_HOST}/test/missing-policies:v1"
		keys = ["${COSIGN_PUB}"]
	EOF

	run --separate-stderr timeout "$CMD_TIMEOUT" "$BINARY" \
		--config "$oci_config" \
		verify "$ref" --preview-policy "$preview_policy" --output json
	echo "# verify output: $output" >&2
	echo "# verify stderr: $stderr" >&2
	[[ "$status" -eq 0 ]]
	echo "$output" | python3 -c "
import sys, json
data = json.load(sys.stdin)
assert data['allowed'] is True, f'expected allowed, got {data}'
assert data['previewPolicy'] == '${preview_policy}'
assert any(c['type'] == 'slsa' and c['status'] == 'pass' for c in data['checkResults']), data
"
}
