#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	start_registry
	generate_signing_key
	configure_insecure_registry

	"$KUBERNIX" --no-shell --root "$KUBERNIX_ROOT" &
	echo $! >"${BATS_FILE_TMPDIR}/kubernix.pid"

	wait_for_node_ready

	write_nri_dropin
	reload_crio

	create_slsa_images

	restore_default_keyless_policy
	write_plugin_config "enforce"
	start_plugin
}

teardown_file() {
	stop_plugin
	stop_registry
	unconfigure_insecure_registry
	stop_kubernix
}

restore_default_keyless_policy() {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "builders": [{"id": "https://test-builder.example.com", "maxLevel": 3}],
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}],
			    "sources": ["https://github.com/testorg/*"]
			  },
			  "provenance": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin
}

create_slsa_images() {
	local pred_dir="${BATS_FILE_TMPDIR}/predicates"
	mkdir -p "$pred_dir"

	SLSA_BT_IMAGE=$(push_test_image "slsa-bt:v1")
	write_slsa_predicate "${pred_dir}/slsa-bt.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		"https://example.com/CustomBuildType"
	attest_image "$SLSA_BT_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/slsa-bt.json"

	SLSA_PARAMS_IMAGE=$(push_test_image "slsa-params:v1")
	write_slsa_predicate "${pred_dir}/slsa-params.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		"" \
		"\"customKey\": \"customValue\""
	attest_image "$SLSA_PARAMS_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/slsa-params.json"

	SLSA_MULTI_IMAGE=$(push_test_image "slsa-multi:v1")
	write_slsa_predicate "${pred_dir}/slsa-multi-untrusted.json" \
		"https://untrusted-builder.example.com" \
		"https://github.com/otherorg/repo" \
		""
	attest_image "$SLSA_MULTI_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/slsa-multi-untrusted.json"
	write_slsa_predicate "${pred_dir}/slsa-multi-trusted.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$SLSA_MULTI_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/slsa-multi-trusted.json"

	SLSA_UNATTESTED_IMAGE=$(push_test_image "slsa-unattested:v1")

	export SLSA_BT_IMAGE SLSA_PARAMS_IMAGE SLSA_MULTI_IMAGE SLSA_UNATTESTED_IMAGE
}

@test "image with SLSA provenance v1 passes verification" {
	run_pod "slsa-trusted" "$SLSA_BT_IMAGE"
	wait_for_pod_status "slsa-trusted" "Running"
	assert_log_contains "Container verified"
}

@test "image with SLSA provenance from untrusted builder is rejected" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "builders": [{"id": "https://builder.example.com/untrusted", "maxLevel": 3}],
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "slsa-untrusted" "$SLSA_BT_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keyless_policy
}

@test "image with trusted source repo passes" {
	run_pod "slsa-source" "$SLSA_BT_IMAGE"
	wait_for_pod_status "slsa-source" "Running"
}

@test "image with unknown source repo is rejected" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "builders": [{"id": "https://test-builder.example.com", "maxLevel": 3}],
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}],
			    "sources": ["https://github.com/myorg/*"]
			  },
			  "provenance": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "slsa-badsource" "$SLSA_BT_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keyless_policy
}

@test "image with buildType matching policy passes" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "builders": [{"id": "https://test-builder.example.com", "maxLevel": 3}],
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}],
			    "buildTypes": ["https://example.com/CustomBuildType"]
			  },
			  "provenance": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "bt-match" "$SLSA_BT_IMAGE"
	wait_for_pod_status "bt-match" "Running"

	restore_default_keyless_policy
}

@test "image with untrusted buildType is rejected" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "builders": [{"id": "https://test-builder.example.com", "maxLevel": 3}],
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}],
			    "buildTypes": ["https://example.com/WrongBuildType"]
			  },
			  "provenance": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "bt-mismatch" "$SLSA_BT_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keyless_policy
}

@test "rejectUnknownParameters=true rejects provenance with non-standard externalParameters" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "deny", "rejectUnknownParameters": true},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "params-reject" "$SLSA_PARAMS_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keyless_policy
}

@test "rejectUnknownParameters=false allows any externalParameters" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "builders": [{"id": "https://test-builder.example.com", "maxLevel": 3}],
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "deny", "rejectUnknownParameters": false},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "slsa-params-ok" "$SLSA_PARAMS_IMAGE"
	wait_for_pod_status "slsa-params-ok" "Running"

	restore_default_keyless_policy
}

@test "multiple provenance attestations accept if any passes" {
	run_pod "multi-prov" "$SLSA_MULTI_IMAGE"
	wait_for_pod_status "multi-prov" "Running"
	assert_log_contains "Supply chain audit"
}

@test "unattested image from local registry is rejected" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "unattested" "$SLSA_UNATTESTED_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keyless_policy
}

@test "image without provenance rejected when missingPolicy is deny" {
	run_pod "no-prov" "registry.k8s.io/pause:3.10" || true
	assert_log_contains "Container rejected"
}
