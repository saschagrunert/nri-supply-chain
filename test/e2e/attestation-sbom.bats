#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	start_registry
	generate_signing_key
	configure_insecure_registry

	start_kubernix_with_retry

	write_nri_dropin
	reload_runtime

	create_sbom_images

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

@test "SBOM with allowed license passes verification" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "sbom": {
			    "missingPolicy": "deny",
			    "license": {"deny": ["AGPL-3.0", "GPL-3.0"]}
			  },
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "sbom-allowed" "$SBOM_ALLOWED_IMAGE"
	wait_for_pod_status "sbom-allowed" "Running"

	restore_default_keybased_policy
}

@test "SBOM with denied license rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "sbom": {
			    "missingPolicy": "deny",
			    "license": {"deny": ["AGPL-3.0", "GPL-3.0"]}
			  },
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "sbom-denied-lic" "$SBOM_DENIED_LIC_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "SBOM with denied component rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "sbom": {
			    "missingPolicy": "deny",
			    "component": {"deny": ["pkg:npm/event-stream@3.3.6"]}
			  },
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "sbom-denied-comp" "$SBOM_DENIED_COMP_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "missing SBOM with missingPolicy=deny rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "sbom": {"missingPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "sbom-missing-deny" "$SBOM_MISSING_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "missing SBOM with missingPolicy=allow allows pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "sbom": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "sbom-missing-allow" "$SBOM_MISSING_IMAGE"
	wait_for_pod_status "sbom-missing-allow" "Running"

	restore_default_keybased_policy
}

@test "CycloneDX SBOM with denied license rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "allow"},
			  "sbom": {
			    "missingPolicy": "deny",
			    "license": {"deny": ["GPL-3.0"]}
			  },
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "sbom-cdx-denied" "$SBOM_CDX_DENIED_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "CVSS threshold exceeded rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "allow"},
			  "sbom": {
			    "missingPolicy": "deny",
			    "cvss": {"maxScore": 7.0}
			  },
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "sbom-cvss-fail" "$SBOM_CVSS_CRITICAL_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "CVSS score under threshold allows pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "allow"},
			  "sbom": {
			    "missingPolicy": "deny",
			    "cvss": {"maxScore": 7.0}
			  },
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "sbom-cvss-pass" "$SBOM_CVSS_LOW_IMAGE"
	wait_for_pod_status "sbom-cvss-pass" "Running"

	restore_default_keybased_policy
}

@test "CVSS ignored CVE allows pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "allow"},
			  "sbom": {
			    "missingPolicy": "deny",
			    "cvss": {
			      "maxScore": 7.0,
			      "ignoreCVEs": ["CVE-2024-9999"]
			    }
			  },
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "sbom-cvss-ignored" "$SBOM_CVSS_CRITICAL_IMAGE"
	wait_for_pod_status "sbom-cvss-ignored" "Running"

	restore_default_keybased_policy
}
