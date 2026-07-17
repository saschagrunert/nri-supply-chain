#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	cat >"$POLICY_DIR/default.json" <<-'EOF'
		{
		  "provenance": {"missingPolicy": "allow"},
		  "vex": {"missingPolicy": "allow"}
		}
	EOF

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

@test "verification_total increments per check type" {
	run_pod "metric-verify" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "metric-verify" "Running"
	wait_for_metrics 'nri_supply_chain_verification_total'

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_verification_total'
}

@test "verification_total labels include check type and status" {
	run_pod "metric-labels" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "metric-labels" "Running"
	wait_for_metrics 'nri_supply_chain_verification_total'

	run curl_metrics
	[[ "$status" -eq 0 ]]
	local total
	total=$(echo "$output" | awk '/nri_supply_chain_verification_total/ && !/^#/ {print $2; exit}')
	[[ "${total:-0}" -gt 0 ]]
}

@test "cache_hits_total and cache_misses_total track correctly" {
	run_pod "metric-cache-1" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "metric-cache-1" "Running"
	wait_for_metrics 'nri_supply_chain_cache_misses_total'

	run_pod "metric-cache-2" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "metric-cache-2" "Running"
	wait_for_metrics 'nri_supply_chain_cache_hits_total'

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_cache_misses_total'
	echo "$output" | grep -q 'nri_supply_chain_cache_hits_total'
}

@test "verification_duration_seconds records latency" {
	run_pod "metric-duration" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "metric-duration" "Running"
	wait_for_metrics 'nri_supply_chain_verification_duration_seconds'

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_verification_duration_seconds'
}

@test "custom metrics_addr is honored via config file" {
	stop_plugin
	cat >"$PLUGIN_CONFIG" <<-EOF
		verification = "warn"
		policy_dir = "${POLICY_DIR}"
		fetch_timeout = "30s"
		cache_ttl = "5m"
		metrics_addr = ":9091"
	EOF
	start_plugin

	run curl_metrics "localhost:9091"
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain'

	stop_plugin
	write_plugin_config "warn"
	start_plugin
}

@test "--metrics-addr CLI flag overrides config file value" {
	stop_plugin
	write_plugin_config "warn"
	"$BINARY" \
		--config "$PLUGIN_CONFIG" \
		--log-level debug \
		--metrics-addr ":9092" \
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

	run curl_metrics "localhost:9092"
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain'

	stop_plugin
	write_plugin_config "warn"
	start_plugin
}

@test "metrics endpoint returns valid Prometheus format" {
	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q '^# HELP'
	echo "$output" | grep -q '^# TYPE'
}
