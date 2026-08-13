#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	start_registry
	generate_signing_key
	configure_insecure_registry

	start_kubernix_with_retry

	create_source_images

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

@test "source attestation from trusted repo passes verification" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}],
			    "sources": ["https://github.com/testorg/**"]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "source": {"missingPolicy": "deny", "minimumLevel": 2},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "source-trusted" "$SOURCE_TRUSTED_IMAGE"
	wait_for_pod_status "source-trusted" "Running"

	restore_default_keybased_policy
}

@test "source attestation from untrusted repo rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}],
			    "sources": ["https://github.com/testorg/**"]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "source": {"missingPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "source-untrusted" "$SOURCE_UNTRUSTED_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "missing source attestation with missingPolicy=deny rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}],
			    "sources": ["https://github.com/testorg/**"]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "source": {"missingPolicy": "deny"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "source-missing-deny" "$SOURCE_MISSING_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}

@test "missing source attestation with missingPolicy=allow allows pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}],
			    "sources": ["https://github.com/testorg/**"]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "source": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "source-missing-allow" "$SOURCE_MISSING_IMAGE"
	wait_for_pod_status "source-missing-allow" "Running"

	restore_default_keybased_policy
}

@test "source level below minimum rejects pod" {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}],
			    "sources": ["https://github.com/testorg/**"]
			  },
			  "slsa": {"missingPolicy": "allow"},
			  "source": {"missingPolicy": "deny", "minimumLevel": 2},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin

	run_pod "source-low-level" "$SOURCE_LOW_LEVEL_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}
