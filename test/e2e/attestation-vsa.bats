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

	create_vsa_images

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

create_vsa_images() {
	local pred_dir="${BATS_FILE_TMPDIR}/predicates"
	mkdir -p "$pred_dir"

	VSA_PASS_IMAGE=$(push_test_image "vsa-pass:v1")
	VSA_PASS_DIGEST=$(get_image_digest "$VSA_PASS_IMAGE")
	local vsa_resource_uri="${REGISTRY_HOST}/test/vsa-pass@${VSA_PASS_DIGEST}"
	write_vsa_predicate "${pred_dir}/vsa-pass.json" \
		"test-verifier" \
		"$vsa_resource_uri" \
		"PASSED" \
		"SLSA_BUILD_LEVEL_3"
	attest_image "$VSA_PASS_IMAGE" "https://slsa.dev/verification_summary/v1" "${pred_dir}/vsa-pass.json"

	VSA_LOW_IMAGE=$(push_test_image "vsa-low:v1")
	VSA_LOW_DIGEST=$(get_image_digest "$VSA_LOW_IMAGE")
	local vsa_low_uri="${REGISTRY_HOST}/test/vsa-low@${VSA_LOW_DIGEST}"
	write_vsa_predicate "${pred_dir}/vsa-low.json" \
		"test-verifier" \
		"$vsa_low_uri" \
		"PASSED" \
		"SLSA_BUILD_LEVEL_1"
	attest_image "$VSA_LOW_IMAGE" "https://slsa.dev/verification_summary/v1" "${pred_dir}/vsa-low.json"
	write_slsa_predicate "${pred_dir}/vsa-low-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$VSA_LOW_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/vsa-low-slsa.json"

	VSA_FAILED_IMAGE=$(push_test_image "vsa-failed:v1")
	VSA_FAILED_DIGEST=$(get_image_digest "$VSA_FAILED_IMAGE")
	local vsa_failed_uri="${REGISTRY_HOST}/test/vsa-failed@${VSA_FAILED_DIGEST}"
	write_vsa_predicate "${pred_dir}/vsa-failed.json" \
		"test-verifier" \
		"$vsa_failed_uri" \
		"FAILED"
	attest_image "$VSA_FAILED_IMAGE" "https://slsa.dev/verification_summary/v1" "${pred_dir}/vsa-failed.json"

	VSA_UNTRUSTED_IMAGE=$(push_test_image "vsa-untrusted:v1")
	VSA_UNTRUSTED_DIGEST=$(get_image_digest "$VSA_UNTRUSTED_IMAGE")
	local vsa_untrusted_uri="${REGISTRY_HOST}/test/vsa-untrusted@${VSA_UNTRUSTED_DIGEST}"
	write_vsa_predicate "${pred_dir}/vsa-untrusted.json" \
		"https://untrusted-verifier.example.com" \
		"$vsa_untrusted_uri" \
		"PASSED"
	attest_image "$VSA_UNTRUSTED_IMAGE" "https://slsa.dev/verification_summary/v1" "${pred_dir}/vsa-untrusted.json"
	write_slsa_predicate "${pred_dir}/vsa-untrusted-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$VSA_UNTRUSTED_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/vsa-untrusted-slsa.json"

	VSA_BADURI_IMAGE=$(push_test_image "vsa-baduri:v1")
	write_vsa_predicate "${pred_dir}/vsa-baduri.json" \
		"test-verifier" \
		"wrong-registry.example.com/wrong-image@sha256:wrong" \
		"PASSED"
	attest_image "$VSA_BADURI_IMAGE" "https://slsa.dev/verification_summary/v1" "${pred_dir}/vsa-baduri.json"

	VSA_BADPOLICY_IMAGE=$(push_test_image "vsa-badpolicy:v1")
	VSA_BADPOLICY_DIGEST=$(get_image_digest "$VSA_BADPOLICY_IMAGE")
	local vsa_badpolicy_uri="${REGISTRY_HOST}/test/vsa-badpolicy@${VSA_BADPOLICY_DIGEST}"
	write_vsa_predicate "${pred_dir}/vsa-badpolicy.json" \
		"test-verifier" \
		"$vsa_badpolicy_uri" \
		"PASSED" \
		"SLSA_BUILD_LEVEL_3" \
		"2025-01-01T00:00:00Z" \
		"https://wrong-policy.example.com"
	attest_image "$VSA_BADPOLICY_IMAGE" "https://slsa.dev/verification_summary/v1" "${pred_dir}/vsa-badpolicy.json"

	VSA_EXPIRED_IMAGE=$(push_test_image "vsa-expired:v1")
	VSA_EXPIRED_DIGEST=$(get_image_digest "$VSA_EXPIRED_IMAGE")
	local vsa_expired_uri="${REGISTRY_HOST}/test/vsa-expired@${VSA_EXPIRED_DIGEST}"
	write_vsa_predicate "${pred_dir}/vsa-expired.json" \
		"test-verifier" \
		"$vsa_expired_uri" \
		"PASSED" \
		"SLSA_BUILD_LEVEL_3" \
		"2020-01-01T00:00:00Z"
	attest_image "$VSA_EXPIRED_IMAGE" "https://slsa.dev/verification_summary/v1" "${pred_dir}/vsa-expired.json"
	write_slsa_predicate "${pred_dir}/vsa-expired-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$VSA_EXPIRED_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/vsa-expired-slsa.json"

	VSA_FUTURE_IMAGE=$(push_test_image "vsa-future:v1")
	VSA_FUTURE_DIGEST=$(get_image_digest "$VSA_FUTURE_IMAGE")
	local vsa_future_uri="${REGISTRY_HOST}/test/vsa-future@${VSA_FUTURE_DIGEST}"
	write_vsa_predicate "${pred_dir}/vsa-future.json" \
		"test-verifier" \
		"$vsa_future_uri" \
		"PASSED" \
		"SLSA_BUILD_LEVEL_3" \
		"2099-01-01T00:00:00Z"
	attest_image "$VSA_FUTURE_IMAGE" "https://slsa.dev/verification_summary/v1" "${pred_dir}/vsa-future.json"

	VSA_OLDSLSA_IMAGE=$(push_test_image "vsa-oldslsa:v1")
	VSA_OLDSLSA_DIGEST=$(get_image_digest "$VSA_OLDSLSA_IMAGE")
	local vsa_oldslsa_uri="${REGISTRY_HOST}/test/vsa-oldslsa@${VSA_OLDSLSA_DIGEST}"
	write_vsa_predicate "${pred_dir}/vsa-oldslsa.json" \
		"test-verifier" \
		"$vsa_oldslsa_uri" \
		"PASSED" \
		"SLSA_BUILD_LEVEL_3" \
		"2025-01-01T00:00:00Z" \
		"" \
		"0.2"
	attest_image "$VSA_OLDSLSA_IMAGE" "https://slsa.dev/verification_summary/v1" "${pred_dir}/vsa-oldslsa.json"

	export VSA_PASS_IMAGE VSA_PASS_DIGEST VSA_LOW_IMAGE VSA_FAILED_IMAGE
	export VSA_UNTRUSTED_IMAGE VSA_BADURI_IMAGE VSA_BADPOLICY_IMAGE
	export VSA_EXPIRED_IMAGE VSA_FUTURE_IMAGE VSA_OLDSLSA_IMAGE
}

@test "VSA with sufficient level passes and skips direct verification" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "slsa": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "deny"},
			  "vsa": {"minimumLevel": 2},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vsa-pass" "$VSA_PASS_IMAGE"
	wait_for_pod_status "vsa-pass" "Running"
	assert_log_contains "VSA verification passed"

	restore_default_keybased_policy
}

@test "VSA with insufficient level falls through to direct checks" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "allow"},
			  "vsa": {"minimumLevel": 3},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vsa-low" "$VSA_LOW_IMAGE"
	wait_for_pod_status "vsa-low" "Running"
	assert_log_contains "Supply chain audit"

	restore_default_keybased_policy
}

@test "VSA with verificationResult FAILED from trusted verifier is a hard reject" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "allow"},
			  "vsa": {"minimumLevel": 1},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vsa-failed" "$VSA_FAILED_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "VSA from untrusted verifier is ignored" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "allow"},
			  "vsa": {"minimumLevel": 1},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vsa-untrusted" "$VSA_UNTRUSTED_IMAGE"
	wait_for_pod_status "vsa-untrusted" "Running"

	restore_default_keybased_policy
}

@test "VSA resource URI mismatch is rejected" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "slsa": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "vsa": {"minimumLevel": 1},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vsa-baduri" "$VSA_BADURI_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "VSA policy URI mismatch is rejected" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "slsa": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "vsa": {"minimumLevel": 1, "policy": "https://correct-policy.example.com"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vsa-badpolicy" "$VSA_BADPOLICY_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "VSA with expired timeVerified falls through to direct checks" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "allow"},
			  "vsa": {"minimumLevel": 1, "maxAge": "1h"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vsa-expired" "$VSA_EXPIRED_IMAGE"
	wait_for_pod_status "vsa-expired" "Running"
	assert_log_contains "Supply chain audit"

	restore_default_keybased_policy
}

@test "VSA with future timeVerified is rejected" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "slsa": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "vsa": {"minimumLevel": 1},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vsa-future" "$VSA_FUTURE_IMAGE" || true
	assert_log_contains "Container rejected\|VSA verification error"

	restore_default_keybased_policy
}

@test "VSA with SLSA version below 1.0 is rejected" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "slsa": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "vsa": {"minimumLevel": 1},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vsa-oldslsa" "$VSA_OLDSLSA_IMAGE" || true
	assert_log_contains "Container rejected\|VSA verification error"

	restore_default_keybased_policy
}
