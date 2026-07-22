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

	create_vex_images

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

create_vex_images() {
	local pred_dir="${BATS_FILE_TMPDIR}/predicates"
	mkdir -p "$pred_dir"

	for vex_status in not_affected fixed affected under_investigation; do
		local var_name="VEX_${vex_status^^}_IMAGE"
		local img
		img=$(push_test_image "vex-${vex_status}:v1")
		local digest
		digest=$(get_image_digest "$img")
		eval "${var_name}=\$img"

		write_slsa_predicate "${pred_dir}/vex-${vex_status}-slsa.json" \
			"https://test-builder.example.com" \
			"https://github.com/testorg/repo" \
			""
		attest_image "$img" "https://slsa.dev/provenance/v1" "${pred_dir}/vex-${vex_status}-slsa.json"

		local product
		product="pkg:oci/vex-${vex_status}@${digest}"
		write_vex_predicate "${pred_dir}/vex-${vex_status}.json" "$vex_status" "$product"
		attest_image "$img" "https://openvex.dev/ns" "${pred_dir}/vex-${vex_status}.json"
	done

	VEX_NOMATCH_IMAGE=$(push_test_image "vex-nomatch:v1")
	write_slsa_predicate "${pred_dir}/vex-nomatch-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$VEX_NOMATCH_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/vex-nomatch-slsa.json"
	write_vex_predicate "${pred_dir}/vex-nomatch.json" "affected" "pkg:oci/other@sha256:unrelated"
	attest_image "$VEX_NOMATCH_IMAGE" "https://openvex.dev/ns" "${pred_dir}/vex-nomatch.json"

	VEX_MULTI_IMAGE=$(push_test_image "vex-multi:v1")
	VEX_MULTI_DIGEST=$(get_image_digest "$VEX_MULTI_IMAGE")
	write_slsa_predicate "${pred_dir}/vex-multi-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$VEX_MULTI_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/vex-multi-slsa.json"
	local multi_product="pkg:oci/vex-multi@${VEX_MULTI_DIGEST}"
	write_vex_predicate "${pred_dir}/vex-multi-ok.json" "not_affected" "$multi_product" "CVE-2024-0001"
	attest_image "$VEX_MULTI_IMAGE" "https://openvex.dev/ns" "${pred_dir}/vex-multi-ok.json"
	write_vex_predicate "${pred_dir}/vex-multi-bad.json" "affected" "$multi_product" "CVE-2024-0002"
	attest_image "$VEX_MULTI_IMAGE" "https://openvex.dev/ns" "${pred_dir}/vex-multi-bad.json"

	VEX_MISSING_IMAGE=$(push_test_image "vex-missing:v1")
	write_slsa_predicate "${pred_dir}/vex-missing-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$VEX_MISSING_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/vex-missing-slsa.json"

	export VEX_NOT_AFFECTED_IMAGE VEX_FIXED_IMAGE VEX_AFFECTED_IMAGE VEX_UNDER_INVESTIGATION_IMAGE
	export VEX_NOMATCH_IMAGE VEX_MULTI_IMAGE VEX_MISSING_IMAGE
}

@test "VEX attestation with not_affected status allows pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vex-na" "$VEX_NOT_AFFECTED_IMAGE"
	wait_for_pod_status "vex-na" "Running"

	restore_default_keybased_policy
}

@test "VEX attestation with fixed status allows pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vex-fixed" "$VEX_FIXED_IMAGE"
	wait_for_pod_status "vex-fixed" "Running"

	restore_default_keybased_policy
}

@test "VEX attestation with affected status rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vex-affected" "$VEX_AFFECTED_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "VEX under_investigation with underInvestigationPolicy=allow passes" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "deny", "underInvestigationPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vex-ui-allow" "$VEX_UNDER_INVESTIGATION_IMAGE"
	wait_for_pod_status "vex-ui-allow" "Running"

	restore_default_keybased_policy
}

@test "VEX under_investigation with underInvestigationPolicy=warn passes with warning" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "deny", "underInvestigationPolicy": "warn"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vex-ui-warn" "$VEX_UNDER_INVESTIGATION_IMAGE"
	wait_for_pod_status "vex-ui-warn" "Running"
	assert_log_contains "Supply chain audit"

	restore_default_keybased_policy
}

@test "VEX under_investigation with underInvestigationPolicy=deny rejects" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "deny", "underInvestigationPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vex-ui-deny" "$VEX_UNDER_INVESTIGATION_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "VEX with no matching products for the image is skipped" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vex-nomatch" "$VEX_NOMATCH_IMAGE"
	wait_for_pod_status "vex-nomatch" "Running"

	restore_default_keybased_policy
}

@test "multiple VEX documents with one affected rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vex-multi" "$VEX_MULTI_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "missing VEX attestation with missingPolicy=deny rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vex-missing" "$VEX_MISSING_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}
