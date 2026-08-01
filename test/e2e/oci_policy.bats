#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	cat >"$POLICY_DIR/default.json" <<-'EOF'
		{
		  "slsa": {"missingPolicy": "allow"},
		  "vex": {"missingPolicy": "allow"}
		}
	EOF

	start_registry
	configure_insecure_registry

	# Push a default allow-all policy to the OCI registry.
	OCI_POLICY_DIR=$(mktemp -d)
	cat >"${OCI_POLICY_DIR}/default.json" <<-'EOF'
		{
		  "slsa": {"missingPolicy": "allow"},
		  "vex": {"missingPolicy": "allow"}
		}
	EOF
	OCI_POLICY_REF=$(push_policy_to_registry "test:v1" "${OCI_POLICY_DIR}/default.json")
	export OCI_POLICY_REF OCI_POLICY_DIR

	start_kubernix_with_retry
	write_nri_dropin
	reload_runtime

	POLICY_IMAGE=$(push_test_image "oci-policy-test:v1")
	export POLICY_IMAGE

	write_plugin_config_oci "warn" "$OCI_POLICY_REF" "1m"
	start_plugin
}

teardown_file() {
	stop_plugin
	stop_registry
	unconfigure_insecure_registry
	stop_kubernix
	rm -rf "${OCI_POLICY_DIR:-}"
}

@test "OCI source: plugin starts and loads policies from registry" {
	# shellcheck disable=SC2034
	LOG_OFFSET=0
	assert_log_contains "Loaded policies from OCI"
	assert_log_contains "Connected to runtime"
}

@test "OCI source: allow-all policy permits pod" {
	run_pod "oci-allow-pod" "$POLICY_IMAGE"
	wait_for_pod_status "oci-allow-pod" "Running"
}

@test "OCI source: deny policy rejects pod in enforce mode" {
	stop_plugin

	# Push a deny policy.
	cat >"${OCI_POLICY_DIR}/default.json" <<-'EOF'
		{
		  "slsa": {"missingPolicy": "deny"},
		  "vex": {"missingPolicy": "allow"}
		}
	EOF
	local deny_ref
	deny_ref=$(push_policy_to_registry "test:deny" "${OCI_POLICY_DIR}/default.json")

	write_plugin_config_oci "enforce" "$deny_ref" "1m"
	start_plugin

	run_pod "oci-deny-pod" "$POLICY_IMAGE" || true
	assert_log_contains "Container rejected"

	# Restore allow-all config.
	write_plugin_config_oci "warn" "$OCI_POLICY_REF" "1m"
	stop_plugin
	start_plugin
}

@test "OCI source: polling detects policy update" {
	stop_plugin

	# Start with allow-all policy and short poll interval.
	cat >"${OCI_POLICY_DIR}/default.json" <<-'EOF'
		{
		  "slsa": {"missingPolicy": "allow"},
		  "vex": {"missingPolicy": "allow"}
		}
	EOF
	local allow_ref
	allow_ref=$(push_policy_to_registry "test:poll" "${OCI_POLICY_DIR}/default.json")

	write_plugin_config_oci "enforce" "$allow_ref" "30s"
	start_plugin

	# Verify the initial allow policy works.
	run_pod "poll-allow-pod" "$POLICY_IMAGE"
	wait_for_pod_status "poll-allow-pod" "Running"

	# Push updated deny policy to the same tag.
	cat >"${OCI_POLICY_DIR}/default.json" <<-'EOF'
		{
		  "slsa": {"missingPolicy": "deny"},
		  "vex": {"missingPolicy": "allow"}
		}
	EOF
	push_policy_to_registry "test:poll" "${OCI_POLICY_DIR}/default.json"

	# Wait for the poller to pick up the change.
	assert_log_contains "OCI policy update detected" 90

	# The updated deny policy should now reject pods.
	run_pod "poll-deny-pod" "$POLICY_IMAGE" || true
	assert_log_contains "Container rejected"

	# Restore.
	write_plugin_config_oci "warn" "$OCI_POLICY_REF" "1m"
	stop_plugin
	start_plugin
}

@test "OCI source: SIGHUP reloads OCI config" {
	stop_plugin

	# Start with allow-all policy.
	write_plugin_config_oci "warn" "$OCI_POLICY_REF" "1m"
	start_plugin

	run_pod "oci-reload-allow" "$POLICY_IMAGE"
	wait_for_pod_status "oci-reload-allow" "Running"

	# Push a deny policy.
	cat >"${OCI_POLICY_DIR}/default.json" <<-'EOF'
		{
		  "slsa": {"missingPolicy": "deny"},
		  "vex": {"missingPolicy": "allow"}
		}
	EOF
	local deny_ref
	deny_ref=$(push_policy_to_registry "test:reload" "${OCI_POLICY_DIR}/default.json")

	# Change config to point to the deny policy and reload.
	write_plugin_config_oci "enforce" "$deny_ref" "1m"
	reload_plugin
	assert_log_contains "Config reloaded successfully"

	run_pod "oci-reload-deny" "$POLICY_IMAGE" || true
	assert_log_contains "Container rejected"

	# Restore.
	write_plugin_config_oci "warn" "$OCI_POLICY_REF" "1m"
	reload_plugin
}
