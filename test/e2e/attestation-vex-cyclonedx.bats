#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	start_registry
	generate_signing_key
	configure_insecure_registry

	start_kubernix_with_retry

	create_cyclonedx_vex_images

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

create_cyclonedx_vex_images() {
	local pred_dir="${BATS_FILE_TMPDIR}/predicates"
	mkdir -p "$pred_dir"

	for vex_state in not_affected resolved exploitable in_triage; do
		local var_name="CDX_VEX_${vex_state^^}_IMAGE"
		local img
		img=$(push_test_image "cdx-vex-${vex_state}:v1")
		local digest
		digest=$(get_image_digest "$img")
		eval "${var_name}=\$img"

		write_slsa_predicate "${pred_dir}/cdx-vex-${vex_state}-slsa.json" \
			"https://test-builder.example.com" \
			"https://github.com/testorg/repo" \
			""
		attest_image "$img" "https://slsa.dev/provenance/v1" "${pred_dir}/cdx-vex-${vex_state}-slsa.json"

		local product
		product="pkg:oci/cdx-vex-${vex_state}@${digest}"
		write_cyclonedx_vex_predicate "${pred_dir}/cdx-vex-${vex_state}.json" "$vex_state" "$product"
		attest_image "$img" "https://cyclonedx.org/bom" "${pred_dir}/cdx-vex-${vex_state}.json"
	done

	CDX_VEX_MISSING_IMAGE=$(push_test_image "cdx-vex-missing:v1")
	write_slsa_predicate "${pred_dir}/cdx-vex-missing-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$CDX_VEX_MISSING_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/cdx-vex-missing-slsa.json"

	export CDX_VEX_NOT_AFFECTED_IMAGE CDX_VEX_RESOLVED_IMAGE CDX_VEX_EXPLOITABLE_IMAGE CDX_VEX_IN_TRIAGE_IMAGE
	export CDX_VEX_MISSING_IMAGE
}

@test "CycloneDX VEX with not_affected state allows pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "cdx-vex-na" "$CDX_VEX_NOT_AFFECTED_IMAGE"
	wait_for_pod_status "cdx-vex-na" "Running"

	restore_default_keybased_policy
}

@test "CycloneDX VEX with resolved state allows pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "cdx-vex-resolved" "$CDX_VEX_RESOLVED_IMAGE"
	wait_for_pod_status "cdx-vex-resolved" "Running"

	restore_default_keybased_policy
}

@test "CycloneDX VEX with exploitable state rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "cdx-vex-exploitable" "$CDX_VEX_EXPLOITABLE_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "CycloneDX VEX in_triage with underInvestigationPolicy=allow passes" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "deny", "underInvestigationPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "cdx-vex-triage-allow" "$CDX_VEX_IN_TRIAGE_IMAGE"
	wait_for_pod_status "cdx-vex-triage-allow" "Running"

	restore_default_keybased_policy
}

@test "CycloneDX VEX in_triage with underInvestigationPolicy=deny rejects" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "deny", "underInvestigationPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "cdx-vex-triage-deny" "$CDX_VEX_IN_TRIAGE_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "missing CycloneDX VEX attestation with missingPolicy=deny rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "cdx-vex-missing" "$CDX_VEX_MISSING_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}
