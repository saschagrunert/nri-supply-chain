#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	start_registry
	generate_signing_key
	configure_insecure_registry

	start_kubernix_with_retry

	create_buildenv_images

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

@test "build env with required properties passes verification" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "buildEnv": {
			    "missingPolicy": "deny",
			    "requiredProperties": ["HERMETIC"]
			  },
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "buildenv-pass" "$BUILDENV_PASS_IMAGE"
	wait_for_pod_status "buildenv-pass" "Running"

	restore_default_keybased_policy
}

@test "build env with forbidden property rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "buildEnv": {
			    "missingPolicy": "deny",
			    "forbiddenProperties": ["ALLOW_NETWORK"]
			  },
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "buildenv-forbidden" "$BUILDENV_FORBIDDEN_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "missing build env with missingPolicy=deny rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "buildEnv": {"missingPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "buildenv-missing-deny" "$BUILDENV_MISSING_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "missing build env with missingPolicy=allow allows pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "buildEnv": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "buildenv-missing-allow" "$BUILDENV_MISSING_IMAGE"
	wait_for_pod_status "buildenv-missing-allow" "Running"

	restore_default_keybased_policy
}
