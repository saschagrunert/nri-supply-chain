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

	start_kubernix

	wait_for_node_ready
	write_nri_dropin
	reload_runtime

	write_plugin_config "warn"
	start_plugin
}

teardown_file() {
	stop_plugin
	stop_kubernix
}

@test "second pod with same image hits cache" {
	run_pod "cache-first" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "cache-first" "Running"
	assert_pod_verdict "cache-first" "verified"

	run_pod "cache-second" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "cache-second" "Running"
	wait_for_metrics "nri_supply_chain_cache_hits_total"

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_cache_hits_total'

	local hits
	hits=$(echo "$output" | awk '/nri_supply_chain_cache_hits_total/ && !/^#/ {print $2; exit}')
	[[ "${hits:-0}" -gt 0 ]]
}

@test "different namespace same image is a cache miss" {
	local ns1="cache-ns1"
	local ns2="cache-ns2"
	kubectl create namespace "$ns1" 2>/dev/null || true
	kubectl create namespace "$ns2" 2>/dev/null || true
	wait_for_service_account "$ns1"
	wait_for_service_account "$ns2"

	kubectl run "cache-ns1-pod" \
		--namespace "$ns1" \
		--image "registry.k8s.io/pause:3.10" \
		--restart=Never
	wait_for_pod_status "cache-ns1-pod" "Running" 60 "$ns1"
	assert_pod_verdict "cache-ns1-pod" "verified" "$ns1"

	local misses_before
	misses_before=$(curl_metrics | awk '/nri_supply_chain_cache_misses_total/ && !/^#/ {print $2; exit}')

	kubectl run "cache-ns2-pod" \
		--namespace "$ns2" \
		--image "registry.k8s.io/pause:3.10" \
		--restart=Never
	wait_for_pod_status "cache-ns2-pod" "Running" 60 "$ns2"
	assert_pod_verdict "cache-ns2-pod" "verified" "$ns2"

	local misses_after
	misses_after=$(curl_metrics | awk '/nri_supply_chain_cache_misses_total/ && !/^#/ {print $2; exit}')

	[[ "${misses_after:-0}" -gt "${misses_before:-0}" ]]

	kubectl delete pods --all -n "$ns1" --force --grace-period=0 2>/dev/null || true
	kubectl delete pods --all -n "$ns2" --force --grace-period=0 2>/dev/null || true
	kubectl delete namespace "$ns1" 2>/dev/null || true
	kubectl delete namespace "$ns2" 2>/dev/null || true
}

@test "cache disabled with cache_ttl=0s always verifies" {
	stop_plugin
	cat >"$PLUGIN_CONFIG" <<-EOF
		verification = "warn"
		policy_dir = "${POLICY_DIR}"
		fetch_timeout = "30s"
		cache_ttl = "0s"
		metrics_addr = ":9090"
	EOF
	start_plugin

	run_pod "nocache-1" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "nocache-1" "Running"
	assert_pod_verdict "nocache-1" "verified"

	run_pod "nocache-2" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "nocache-2" "Running"
	wait_for_metrics

	run curl_metrics
	[[ "$status" -eq 0 ]]
	local hits
	hits=$(echo "$output" | awk '/nri_supply_chain_cache_hits_total/ && !/^#/ {print $2; exit}')
	[[ "${hits:-0}" -eq 0 ]]

	stop_plugin
	write_plugin_config "warn"
	start_plugin
}

@test "cache expires after TTL" {
	stop_plugin
	cat >"$PLUGIN_CONFIG" <<-EOF
		verification = "warn"
		policy_dir = "${POLICY_DIR}"
		fetch_timeout = "30s"
		cache_ttl = "3s"
		metrics_addr = ":9090"
	EOF
	start_plugin

	run_pod "ttl-first" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "ttl-first" "Running"
	assert_pod_verdict "ttl-first" "verified"

	local misses_before
	misses_before=$(curl_metrics | awk '/nri_supply_chain_cache_misses_total/ && !/^#/ {print $2; exit}')

	# Cache eviction is lazy (only on Get), so wait for TTL + jitter to expire
	sleep 5

	run_pod "ttl-second" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "ttl-second" "Running"
	assert_pod_verdict "ttl-second" "verified"

	local misses_after
	misses_after=$(curl_metrics | awk '/nri_supply_chain_cache_misses_total/ && !/^#/ {print $2; exit}')

	[[ "${misses_after:-0}" -gt "${misses_before:-0}" ]]

	stop_plugin
	write_plugin_config "warn"
	start_plugin
}
