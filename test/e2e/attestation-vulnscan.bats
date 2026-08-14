#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	start_registry
	generate_signing_key
	configure_insecure_registry

	start_kubernix_with_retry

	create_vulnscan_images

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

@test "vuln scan with low-severity vulnerabilities passes threshold" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vulnScan": {
			    "missingPolicy": "deny",
			    "maxScore": 7.0
			  },
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vulnscan-pass" "$VULNSCAN_PASS_IMAGE"
	wait_for_pod_status "vulnscan-pass" "Running"

	restore_default_keybased_policy
}

@test "vuln scan with critical vulnerability exceeds threshold" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vulnScan": {
			    "missingPolicy": "deny",
			    "maxScore": 7.0
			  },
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vulnscan-critical" "$VULNSCAN_CRITICAL_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "vuln scan with ignored CVE allows pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vulnScan": {
			    "missingPolicy": "deny",
			    "maxScore": 7.0,
			    "ignoreCVEs": ["CVE-2024-9999"]
			  },
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vulnscan-ignored" "$VULNSCAN_CRITICAL_IMAGE"
	wait_for_pod_status "vulnscan-ignored" "Running"

	restore_default_keybased_policy
}

@test "missing vuln scan with missingPolicy=deny rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vulnScan": {"missingPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vulnscan-missing-deny" "$VULNSCAN_MISSING_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "missing vuln scan with missingPolicy=allow allows pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "vulnScan": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "vulnscan-missing-allow" "$VULNSCAN_MISSING_IMAGE"
	wait_for_pod_status "vulnscan-missing-allow" "Running"

	restore_default_keybased_policy
}
