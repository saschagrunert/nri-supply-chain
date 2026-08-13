#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"
	echo '{}' >"$POLICY_DIR/default.json"

	start_kubernix_with_retry

	write_plugin_config "disabled"
	start_plugin
}

teardown_file() {
	stop_plugin
	stop_kubernix
}

@test "pod with any image is admitted in disabled mode" {
	run_pod "disabled-pod" "$PAUSE_IMAGE"
	wait_for_pod_status "disabled-pod" "Running"
}

@test "no attestation fetch is attempted in disabled mode" {
	run_pod "nofetch-pod" "$PAUSE_IMAGE"
	wait_for_pod_status "nofetch-pod" "Running"
	# Wait for the NRI callback log entry to confirm the container was
	# processed, then assert verification was never attempted.
	assert_log_contains "NRI container info"
	run ! plugin_log_contains "Verifying image"
}

@test "no verification metrics are recorded in disabled mode" {
	local metrics
	metrics=$(curl_metrics)
	run grep 'nri_supply_chain_verification_total' <<<"$metrics"
	[[ "$status" -ne 0 ]]
}
