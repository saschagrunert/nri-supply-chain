#!/usr/bin/env bats

load helpers

FEED_DIR="${BATS_FILE_TMPDIR}/feeds"

write_plugin_config_remediation() {
	local mode="${1:-warn}"
	local remediation_mode="${2:-warn}"
	local interval="${3:-30s}"
	cat >"$PLUGIN_CONFIG" <<-EOF
		verification = "${mode}"
		policy_dir = "${POLICY_DIR}"
		fetch_timeout = "30s"
		fetch_failure_policy = "deny"
		cache_ttl = "5m"
		metrics_addr = ":9090"

		[remediation]
		mode = "${remediation_mode}"
		interval = "${interval}"
		batch_size = 10
		cooldown = "5m"
		feed_dir = "${FEED_DIR}"

		[remediation.throttle]
		cpu_quota_percent = 10
		memory_limit_percent = 50

		[remediation.triggers]
		on_new_cve = true
		on_attestation_revoked = true
		on_policy_change = true
	EOF
}

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR" "$FEED_DIR"

	cat >"$POLICY_DIR/default.json" <<-'EOF'
		{
		  "slsa": {"missingPolicy": "allow"},
		  "vex": {"missingPolicy": "allow"}
		}
	EOF

	start_kubernix_with_retry

	write_plugin_config_remediation "warn" "warn" "30s"
	start_plugin
}

teardown_file() {
	stop_plugin
	stop_kubernix
}

@test "continuous verifier starts when remediation mode is set" {
	LOG_OFFSET=0
	assert_log_contains "Continuous verifier started" 90
}

@test "continuous verifier runs a timer-triggered cycle" {
	run_pod "cv-timer" "$PAUSE_IMAGE"
	wait_for_pod_status "cv-timer" "Running"

	assert_log_contains "Continuous verification cycle completed" 60
}

@test "re-verification metrics are emitted" {
	run_pod "cv-metric" "$PAUSE_IMAGE"
	wait_for_pod_status "cv-metric" "Running"

	assert_log_contains "Continuous verification cycle completed" 60

	wait_for_metrics "nri_supply_chain_reverification_total" "localhost:9090" 30

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_reverification_total'
}

@test "tracked container gauge reflects running containers" {
	run_pod "cv-gauge" "$PAUSE_IMAGE"
	wait_for_pod_status "cv-gauge" "Running"

	assert_log_contains "Continuous verification cycle completed" 60

	wait_for_metrics "nri_supply_chain_tracked_containers" "localhost:9090" 30

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_tracked_containers'
}

@test "re-verification duration histogram is populated" {
	run_pod "cv-duration" "$PAUSE_IMAGE"
	wait_for_pod_status "cv-duration" "Running"

	assert_log_contains "Continuous verification cycle completed" 60

	wait_for_metrics "nri_supply_chain_reverification_duration_seconds" "localhost:9090" 30

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_reverification_duration_seconds'
}

@test "continuous verifier last run gauge is updated" {
	run_pod "cv-lastrun" "$PAUSE_IMAGE"
	wait_for_pod_status "cv-lastrun" "Running"

	assert_log_contains "Continuous verification cycle completed" 60

	wait_for_metrics "nri_supply_chain_continuous_verifier_last_run" "localhost:9090" 30

	run curl_metrics
	[[ "$status" -eq 0 ]]
	local last_run
	last_run=$(echo "$output" | awk '/nri_supply_chain_continuous_verifier_last_run/ && !/^#/ {print $2; exit}')
	[[ "${last_run:-0}" != "0" ]]
}

@test "feed file triggers re-verification of affected containers" {
	run_pod "cv-feed" "$PAUSE_IMAGE"
	wait_for_pod_status "cv-feed" "Running"

	# Wait for at least one cycle so the container has PURLs populated
	assert_log_contains "Continuous verification cycle completed" 60

	# Write an OSV feed file to trigger PURL-based re-verification
	cat >"${FEED_DIR}/test-cve.json" <<-'EOF'
		{
		  "id": "GHSA-test-0001",
		  "affected": [
		    {"package": {"purl": "pkg:golang/stdlib@1.21.0"}}
		  ]
		}
	EOF

	# The feed watcher should detect the file and log processing
	assert_log_contains "Feed directory updated" 30
}

@test "SIGHUP with remediation config change reloads mode" {
	# Change remediation mode from warn to throttle
	write_plugin_config_remediation "warn" "throttle" "30s"
	reload_plugin
	assert_log_contains "Config reloaded successfully"

	# Verify the plugin is still functional
	run curl_metrics
	[[ "$status" -eq 0 ]]

	# Restore original config
	write_plugin_config_remediation "warn" "warn" "30s"
	reload_plugin
}

@test "SIGHUP with on_policy_change triggers re-verification" {
	run_pod "cv-policy-trigger" "$PAUSE_IMAGE"
	wait_for_pod_status "cv-policy-trigger" "Running"

	# Wait for at least one cycle
	assert_log_contains "Continuous verification cycle completed" 60

	# Record log offset so we can detect new cycle
	# shellcheck disable=SC2034
	LOG_OFFSET=$(wc -c <"$PLUGIN_LOG")

	# Reload config (triggers on_policy_change)
	write_plugin_config_remediation "warn" "warn" "30s"
	reload_plugin

	# A new verification cycle should be triggered
	assert_log_contains "Continuous verification cycle completed" 30
}

@test "disabling remediation mode stops continuous verifier cycles" {
	stop_plugin

	# Start with remediation disabled (no mode set)
	write_plugin_config "warn"
	start_plugin

	# The continuous verifier should not start
	sleep 5
	run ! plugin_log_contains "Continuous verifier started"

	# Re-enable for remaining tests
	stop_plugin
	write_plugin_config_remediation "warn" "warn" "30s"
	start_plugin
	assert_log_contains "Continuous verifier started" 90
}

@test "feed processing metrics are emitted" {
	cat >"${FEED_DIR}/metric-cve.json" <<-'EOF'
		{
		  "id": "GHSA-metric-test",
		  "affected": [
		    {"package": {"purl": "pkg:npm/test-pkg@1.0.0"}}
		  ]
		}
	EOF

	assert_log_contains "Feed directory updated" 30

	wait_for_metrics "nri_supply_chain_feed_files_processed_total" "localhost:9090" 30

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_feed_files_processed_total'

	rm -f "${FEED_DIR}/metric-cve.json"
}

@test "remediation with invalid config does not crash plugin" {
	cat >"$PLUGIN_CONFIG" <<-EOF
		verification = "warn"
		policy_dir = "${POLICY_DIR}"
		fetch_timeout = "30s"
		cache_ttl = "5m"
		metrics_addr = ":9090"

		[remediation]
		mode = "invalid_mode"
		interval = "5m"
		batch_size = 10
	EOF
	reload_plugin
	assert_log_contains "Config reload failed"

	# Plugin should still be responsive
	run curl_metrics
	[[ "$status" -eq 0 ]]

	# Restore valid config
	write_plugin_config_remediation "warn" "warn" "30s"
	reload_plugin
}
