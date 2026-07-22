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
		  "slsa": {"missingPolicy": "deny"},
		  "vex": {"missingPolicy": "allow"},
		  "signatures": {"requireTransparencyLog": true}
		}
	EOF

	start_registry
	configure_insecure_registry

	start_kubernix --log-level debug

	wait_for_node_ready
	write_nri_dropin
	reload_runtime

	CB_IMAGE=$(push_test_image "cb-test:v1")
	CB_DIGEST=$(get_image_digest "$CB_IMAGE")
	export CB_IMAGE CB_DIGEST

	# Pre-pull the image so the kubelet can start containers
	# after the registry goes down.
	write_plugin_config_cb "disabled" "allow"
	start_plugin
	wait_for_service_account "default"
	kubectl run "cb-prepull" --namespace default --image "$CB_IMAGE" --restart=Never
	wait_for_pod_status "cb-prepull" "Running" 60 "default"
	kubectl delete pod "cb-prepull" -n default --force --grace-period=0 2>/dev/null || true
	stop_plugin

	stop_registry
}

setup() {
	TEST_NS="test-$(date +%s)-${BATS_TEST_NUMBER}"
	export TEST_NS
	kubectl create namespace "$TEST_NS" 2>/dev/null || true
	wait_for_service_account "$TEST_NS"
	if [[ -f "$PLUGIN_LOG" ]]; then
		export LOG_OFFSET
		LOG_OFFSET=$(wc -c <"$PLUGIN_LOG")
	else
		export LOG_OFFSET=0
	fi
}

teardown_file() {
	stop_plugin
	unconfigure_insecure_registry
	stop_kubernix
}

# Use digest references so containerd NRI annotations include the
# digest even after the registry is stopped.
cb_image_ref() {
	local repo
	repo="${CB_IMAGE%:*}"
	echo "${repo}@${CB_DIGEST}"
}

write_plugin_config_cb() {
	local mode="$1"
	local fetch_policy="$2"
	cat >"$PLUGIN_CONFIG" <<-EOF
		verification = "${mode}"
		policy_dir = "${POLICY_DIR}"
		fetch_timeout = "5s"
		fetch_failure_policy = "${fetch_policy}"
		cache_ttl = "0s"
		cache_failure_ttl = "0s"
		metrics_addr = ":9090"
		circuit_breaker_threshold = 2
		circuit_breaker_cooldown = "30s"
	EOF
}

@test "circuit breaker trips after threshold failures" {
	stop_plugin
	write_plugin_config_cb "warn" "allow"
	start_plugin

	local ref
	ref=$(cb_image_ref)

	run_pod "cb-trip-1" "$ref" --image-pull-policy=IfNotPresent
	wait_for_pod_status "cb-trip-1" "Running"
	assert_pod_verdict "cb-trip-1" "verified"

	run_pod "cb-trip-2" "$ref" --image-pull-policy=IfNotPresent
	wait_for_pod_status "cb-trip-2" "Running"
	assert_pod_verdict "cb-trip-2" "verified"

	wait_for_metrics 'nri_supply_chain_circuit_breaker_trips_total'

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_circuit_breaker_trips_total'
}

@test "circuit breaker open skips remote fetch" {
	stop_plugin
	write_plugin_config_cb "warn" "allow"
	start_plugin

	local ref
	ref=$(cb_image_ref)

	# Trigger enough failures to open the breaker.
	run_pod "cb-open-1" "$ref" --image-pull-policy=IfNotPresent
	wait_for_pod_status "cb-open-1" "Running"

	run_pod "cb-open-2" "$ref" --image-pull-policy=IfNotPresent
	wait_for_pod_status "cb-open-2" "Running"

	# Third request hits the open breaker.
	run_pod "cb-open-3" "$ref" --image-pull-policy=IfNotPresent
	wait_for_pod_status "cb-open-3" "Running"
	assert_log_contains "circuit breaker open"
}
