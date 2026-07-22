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

	FETCH_IMAGE=$(push_test_image "fetch-test:v1")
	FETCH_DIGEST=$(get_image_digest "$FETCH_IMAGE")
	export FETCH_IMAGE FETCH_DIGEST

	write_plugin_config_with_fetch_policy "disabled" "allow"
	start_plugin
	wait_for_service_account "default"
	kubectl run "prepull" --namespace default --image "$FETCH_IMAGE" --restart=Never
	wait_for_pod_status "prepull" "Running" 60 "default"
	kubectl delete pod "prepull" -n default --force --grace-period=0 2>/dev/null || true
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
	stop_registry
	unconfigure_insecure_registry
	stop_kubernix
}

# Use digest references so containerd NRI annotations include the
# digest even after the registry is stopped.
fetch_image_ref() {
	local repo
	repo="${FETCH_IMAGE%:*}"
	echo "${repo}@${FETCH_DIGEST}"
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
		cache_failure_ttl = "0s"
		metrics_addr = ":9090"
	EOF
}

@test "fetch_failure_policy allow admits pod on network error" {
	stop_plugin
	write_plugin_config_with_fetch_policy "enforce" "allow"
	start_plugin

	local ref
	ref=$(fetch_image_ref)

	run_pod "fetch-allow" "$ref" --image-pull-policy=IfNotPresent
	wait_for_pod_status "fetch-allow" "Running"
	assert_pod_verdict "fetch-allow" "verified"
}

@test "fetch_failure_policy warn admits pod with warning on network error" {
	stop_plugin
	write_plugin_config_with_fetch_policy "enforce" "warn"
	start_plugin

	local ref
	ref=$(fetch_image_ref)

	run_pod "fetch-warn" "$ref" --image-pull-policy=IfNotPresent
	wait_for_pod_status "fetch-warn" "Running"
	assert_pod_verdict "fetch-warn" "verified"
	assert_log_contains "Supply chain audit"
}

@test "fetch_failure_policy deny rejects pod on network error" {
	stop_plugin
	write_plugin_config_with_fetch_policy "enforce" "deny"
	start_plugin

	local ref
	ref=$(fetch_image_ref)

	run_pod "fetch-deny" "$ref" --image-pull-policy=IfNotPresent || true
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
		cache_failure_ttl = "0s"
		metrics_addr = ":9090"
	EOF
	start_plugin

	local ref
	ref=$(fetch_image_ref)

	run_pod "fetch-timeout" "$ref" --image-pull-policy=IfNotPresent || true
	assert_log_contains "Container rejected"
}

@test "fetch error increments fetch_errors_total metric" {
	stop_plugin
	write_plugin_config_with_fetch_policy "enforce" "allow"
	start_plugin

	local ref
	ref=$(fetch_image_ref)

	run_pod "fetch-metric" "$ref" --image-pull-policy=IfNotPresent
	wait_for_pod_status "fetch-metric" "Running"
	wait_for_metrics 'nri_supply_chain_fetch_errors_total'

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_fetch_errors_total'
}
