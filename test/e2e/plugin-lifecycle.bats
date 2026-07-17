#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"
	echo '{}' >"$POLICY_DIR/default.json"

	"$KUBERNIX" --no-shell --root "$KUBERNIX_ROOT" &
	echo $! >"${BATS_FILE_TMPDIR}/kubernix.pid"

	wait_for_node_ready
	write_nri_dropin
	reload_crio

	write_plugin_config "warn"
	start_plugin
}

teardown_file() {
	stop_plugin
	stop_kubernix
}

@test "plugin connects to CRI-O via NRI" {
	# shellcheck disable=SC2034
	LOG_OFFSET=0
	assert_log_contains "Connected to runtime"
}

@test "plugin logs startup with name and index" {
	# shellcheck disable=SC2034
	LOG_OFFSET=0
	assert_log_contains "Starting NRI plugin"
}

@test "metrics server starts on configured port" {
	run curl_metrics
	[[ "$status" -eq 0 ]]
	[[ "$output" == *"nri_supply_chain"* ]]
}

@test "pod with any image is admitted in warn mode" {
	run_pod "lifecycle-pod" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "lifecycle-pod" "Running"
}

@test "container verification is logged for admitted pod" {
	run_pod "verified-pod" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "verified-pod" "Running"
	assert_log_contains "Container verified"
}

@test "plugin shuts down cleanly on SIGTERM" {
	stop_plugin
	local exit_code=$?
	[[ "$exit_code" -eq 0 ]]
	assert_log_contains "Shutting down"
	start_plugin
}

@test "debug log level shows verbose output" {
	stop_plugin
	write_plugin_config "warn"
	"$BINARY" \
		--config "$PLUGIN_CONFIG" \
		--log-level debug \
		>"$PLUGIN_LOG" 2>&1 &
	echo $! >"$PLUGIN_PID_FILE"
	# shellcheck disable=SC2034
	LOG_OFFSET=0
	local elapsed=0
	while [[ $elapsed -lt 10 ]]; do
		if grep -q "Connected to runtime" "$PLUGIN_LOG" 2>/dev/null; then
			break
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done

	run_pod "debug-pod" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "debug-pod" "Running"
	assert_log_contains "Verifying image"
}

@test "custom plugin-name and plugin-idx are reflected in startup log" {
	stop_plugin
	write_plugin_config "warn"
	# shellcheck disable=SC2034
	LOG_OFFSET=0
	"$BINARY" \
		--config "$PLUGIN_CONFIG" \
		--log-level debug \
		--plugin-name "custom-chain" \
		--plugin-idx "20" \
		>"$PLUGIN_LOG" 2>&1 &
	echo $! >"$PLUGIN_PID_FILE"
	local elapsed=0
	while [[ $elapsed -lt 10 ]]; do
		if grep -q "Connected to runtime" "$PLUGIN_LOG" 2>/dev/null; then
			break
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done

	assert_log_contains "custom-chain"
	stop_plugin
	start_plugin
}

@test "plugin starts with explicit config file" {
	stop_plugin
	write_plugin_config "warn"
	start_plugin
	assert_log_contains "Starting NRI plugin"
	assert_log_contains "Connected to runtime"
}

@test "log output is structured JSON" {
	stop_plugin
	write_plugin_config "warn"
	start_plugin
	local first_json_line
	first_json_line=$(grep -m1 '^{' "$PLUGIN_LOG")
	echo "$first_json_line" | python3 -c "import sys, json; json.load(sys.stdin)"
}
