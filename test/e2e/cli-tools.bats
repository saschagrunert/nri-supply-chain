#!/usr/bin/env bats

load helpers

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
