#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	start_registry
	generate_signing_key
	configure_insecure_registry

	start_kubernix

	wait_for_node_ready

	write_nri_dropin
	reload_runtime

	create_sigstore_images

	restore_default_keybased_policy
	write_plugin_config "enforce"
	start_plugin
}

teardown_file() {
	stop_plugin
	stop_registry
	unconfigure_insecure_registry
	stop_kubernix
}

create_sigstore_images() {
	local pred_dir="${BATS_FILE_TMPDIR}/predicates"
	mkdir -p "$pred_dir"

	KEYBASED_IMAGE=$(push_test_image "keybased:v1")
	write_slsa_predicate "${pred_dir}/keybased.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$KEYBASED_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/keybased.json"

	export KEYBASED_IMAGE
}

@test "key-based verification with trusted public key passes" {
	restore_default_keybased_policy

	run_pod "keybased-ok" "$KEYBASED_IMAGE"
	assert_pod_verdict "keybased-ok" "verified"
}

@test "key-based verification with wrong key is rejected" {
	local wrong_key="${BATS_FILE_TMPDIR}/wrong"
	COSIGN_PASSWORD="" "$COSIGN" generate-key-pair --output-key-prefix "$wrong_key" 2>/dev/null

	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "wrong-verifier", "key": "${wrong_key}.pub"}]
			  },
			  "provenance": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "keybased-wrong" "$KEYBASED_IMAGE" || true
	assert_pod_verdict "keybased-wrong" "rejected"

	restore_default_keybased_policy
}

@test "transparency log required rejects key-based bundle without tlog" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": true}
			}
		EOF
	)"
	reload_plugin

	run_pod "tlog-reject" "$KEYBASED_IMAGE" || true
	assert_pod_verdict "tlog-reject" "rejected"

	restore_default_keybased_policy
}

@test "multiple verifiers with first matching passes" {
	local wrong_key="${BATS_FILE_TMPDIR}/multi-wrong"
	COSIGN_PASSWORD="" "$COSIGN" generate-key-pair --output-key-prefix "$wrong_key" 2>/dev/null

	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [
			      {"id": "wrong-verifier", "key": "${wrong_key}.pub"},
			      {"id": "correct-verifier", "key": "${COSIGN_PUB}"}
			    ]
			  },
			  "provenance": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "multi-verifier" "$KEYBASED_IMAGE"
	assert_pod_verdict "multi-verifier" "verified"

	restore_default_keybased_policy
}

@test "empty trust block rejects attested image" {
	write_policy "default" '{
		"trust": {},
		"provenance": {"missingPolicy": "deny"},
		"vex": {"missingPolicy": "allow"},
		"signatures": {"requireTransparencyLog": false}
	}'
	reload_plugin

	run_pod "no-trust" "$KEYBASED_IMAGE" || true
	assert_pod_verdict "no-trust" "rejected"

	restore_default_keybased_policy
}
