#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"
	echo '{}' >"$POLICY_DIR/default.json"

	start_kubernix

	wait_for_node_ready
	write_nri_dropin
	reload_runtime

	write_plugin_config "disabled"
	start_plugin
}

teardown_file() {
	stop_plugin
	stop_kubernix
}

@test "pod with any image is admitted in disabled mode" {
	run_pod "disabled-pod" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "disabled-pod" "Running"
}

@test "no attestation fetch is attempted in disabled mode" {
	run_pod "nofetch-pod" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "nofetch-pod" "Running"
	sleep 2
	run ! plugin_log_contains "Verifying image"
}

@test "no verification metrics are recorded in disabled mode" {
	local metrics
	metrics=$(curl_metrics)
	run grep 'nri_supply_chain_verification_total' <<<"$metrics"
	[[ "$status" -ne 0 ]]
}
