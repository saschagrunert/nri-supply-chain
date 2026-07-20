#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	cat >"$POLICY_DIR/default.json" <<-'EOF'
		{
		  "trust": {
		    "issuers": ["https://token.actions.githubusercontent.com"],
		    "sanPatterns": ["*"]
		  },
		  "provenance": {"missingPolicy": "deny"},
		  "vex": {"missingPolicy": "allow"},
		  "signatures": {"requireTransparencyLog": true}
		}
	EOF

	start_registry
	configure_insecure_registry

	"$KUBERNIX" --no-shell --log-level debug --root "$KUBERNIX_ROOT" &
	echo $! >"${BATS_FILE_TMPDIR}/kubernix.pid"

	wait_for_node_ready
	write_nri_dropin
	reload_crio

	FETCH_IMAGE=$(push_test_image "fetch-test:v1")
	export FETCH_IMAGE

	write_plugin_config_with_fetch_policy "disabled" "allow"
	start_plugin
	wait_for_service_account "default"
	kubectl run "prepull" --namespace default --image "$FETCH_IMAGE" --restart=Never
	wait_for_pod_status "prepull" "Running" 60 "default"
	kubectl delete pod "prepull" -n default --force --grace-period=0 2>/dev/null || true
	stop_plugin

	stop_registry
}

teardown_file() {
	stop_plugin
	stop_registry
	unconfigure_insecure_registry
	stop_kubernix
}

write_plugin_config_with_fetch_policy() {
	local mode="$1"
	local fetch_policy="$2"
	cat >"$PLUGIN_CONFIG" <<-EOF
		verification = "${mode}"
		policy_dir = "${POLICY_DIR}"
		fetch_timeout = "30s"
		fetch_failure_policy = "${fetch_policy}"
		cache_ttl = "0s"
		metrics_addr = ":9090"
	EOF
}

@test "fetch_failure_policy allow admits pod on network error" {
	stop_plugin
	write_plugin_config_with_fetch_policy "enforce" "allow"
	start_plugin

	run_pod "fetch-allow" "$FETCH_IMAGE"
	wait_for_pod_status "fetch-allow" "Running"
	assert_log_contains "Container verified"
}

@test "fetch_failure_policy warn admits pod with warning on network error" {
	stop_plugin
	write_plugin_config_with_fetch_policy "enforce" "warn"
	start_plugin

	run_pod "fetch-warn" "$FETCH_IMAGE"
	wait_for_pod_status "fetch-warn" "Running"
	assert_log_contains "Container verified"
	assert_log_contains "Supply chain audit"
}

@test "fetch_failure_policy deny rejects pod on network error" {
	stop_plugin
	write_plugin_config_with_fetch_policy "enforce" "deny"
	start_plugin

	run_pod "fetch-deny" "$FETCH_IMAGE" || true
	assert_log_contains "Container rejected"
}

@test "fetch timeout triggers fetch failure policy" {
	stop_plugin
	cat >"$PLUGIN_CONFIG" <<-EOF
		verification = "enforce"
		policy_dir = "${POLICY_DIR}"
		fetch_timeout = "1s"
		fetch_failure_policy = "deny"
		cache_ttl = "0s"
		metrics_addr = ":9090"
	EOF
	start_plugin

	run_pod "fetch-timeout" "$FETCH_IMAGE" || true
	assert_log_contains "Container rejected"
}

@test "fetch error increments fetch_errors_total metric" {
	stop_plugin
	write_plugin_config_with_fetch_policy "enforce" "allow"
	start_plugin

	run_pod "fetch-metric" "$FETCH_IMAGE"
	wait_for_pod_status "fetch-metric" "Running"
	wait_for_metrics 'nri_supply_chain_fetch_errors_total'

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_fetch_errors_total'
}
