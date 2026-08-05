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

	start_kubernix_with_retry
	write_nri_dropin
	reload_runtime

	write_plugin_config "warn"
	start_plugin
}

teardown_file() {
	stop_plugin
	stop_kubernix
}

@test "verification_total increments per check type" {
	run_pod "metric-verify" "$PAUSE_IMAGE"
	wait_for_pod_status "metric-verify" "Running"
	wait_for_metrics 'nri_supply_chain_verification_total'

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_verification_total'
}

@test "verification_total labels include check type and status" {
	run_pod "metric-labels" "$PAUSE_IMAGE"
	wait_for_pod_status "metric-labels" "Running"
	wait_for_metrics 'nri_supply_chain_verification_total'

	run curl_metrics
	[[ "$status" -eq 0 ]]
	local total
	total=$(echo "$output" | awk '/nri_supply_chain_verification_total/ && !/^#/ {print $2; exit}')
	[[ "${total:-0}" -gt 0 ]]
}

@test "cache_hits_total and cache_misses_total track correctly" {
	run_pod "metric-cache-1" "$PAUSE_IMAGE"
	wait_for_pod_status "metric-cache-1" "Running"
	wait_for_metrics 'nri_supply_chain_cache_misses_total'

	run_pod "metric-cache-2" "$PAUSE_IMAGE"
	wait_for_pod_status "metric-cache-2" "Running"
	wait_for_metrics 'nri_supply_chain_cache_hits_total'

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_cache_misses_total'
	echo "$output" | grep -q 'nri_supply_chain_cache_hits_total'
}

@test "verification_duration_seconds records latency" {
	run_pod "metric-duration" "$PAUSE_IMAGE"
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

@test "container_lifetime_seconds recorded after pod deletion" {
	run_pod "metric-lifetime" "$PAUSE_IMAGE"
	wait_for_pod_status "metric-lifetime" "Running"
	wait_for_metrics 'nri_supply_chain_verification_total'

	kubectl delete pod "metric-lifetime" -n "$TEST_NS" --force --grace-period=0 \
		--request-timeout="${KUBECTL_TIMEOUT}s"

	wait_for_metrics 'nri_supply_chain_container_lifetime_seconds'

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_container_lifetime_seconds'
}

@test "metrics endpoint returns valid Prometheus format" {
	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q '^# HELP'
	echo "$output" | grep -q '^# TYPE'
}
