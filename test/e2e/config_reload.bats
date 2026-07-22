#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	cat >"$POLICY_DIR/default.json" <<-'EOF'
		{
		  "slsa": {"missingPolicy": "deny"},
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

@test "SIGHUP reloads config: change warn to enforce rejects pods" {
	run_pod "before-reload" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "before-reload" "Running"

	write_plugin_config "enforce"
	reload_plugin
	assert_log_contains "Config reloaded successfully"

	run_pod "after-reload" "registry.k8s.io/pause:3.10" || true
	assert_log_contains "Container rejected"

	write_plugin_config "warn"
	reload_plugin
}

@test "SIGHUP reloads policies from policy_dir" {
	local ns="reload-policy-ns"
	kubectl create namespace "$ns" 2>/dev/null || true
	wait_for_service_account "$ns"

	write_plugin_config "enforce" "allow"
	reload_plugin

	write_policy "$ns" '{
		"slsa": {"missingPolicy": "allow"},
		"vex": {"missingPolicy": "allow"}
	}'
	reload_plugin

	kubectl run "reload-policy-pod" \
		--namespace "$ns" \
		--image "registry.k8s.io/pause:3.10" \
		--restart=Never
	wait_for_pod_status "reload-policy-pod" "Running" 60 "$ns"

	kubectl delete pod "reload-policy-pod" -n "$ns" --force --grace-period=0 2>/dev/null || true
	kubectl delete namespace "$ns" 2>/dev/null || true
	rm -f "${POLICY_DIR}/${ns}.json"
	write_plugin_config "warn"
	reload_plugin
}

@test "SIGHUP with invalid config does not crash plugin" {
	echo "invalid toml {{{{" >"$PLUGIN_CONFIG"
	reload_plugin
	assert_log_contains "Config reload failed"

	run curl_metrics
	[[ "$status" -eq 0 ]]

	write_plugin_config "warn"
	reload_plugin
}

@test "SIGHUP with valid TOML but failed runtime validation does not crash" {
	cat >"$PLUGIN_CONFIG" <<-EOF
		verification = "enforce"
		policy_dir = "/nonexistent/path/that/does/not/exist"
		fetch_timeout = "30s"
		cache_ttl = "5m"
		metrics_addr = ":9090"
	EOF
	reload_plugin
	assert_log_contains "Config reload validation failed"

	run curl_metrics
	[[ "$status" -eq 0 ]]

	write_plugin_config "warn"
	reload_plugin
}

@test "SIGHUP with valid config but malformed policy JSON does not crash" {
	echo "not valid json {{{" >"${POLICY_DIR}/default.json"
	reload_plugin
	assert_log_contains "Verifier reload failed"

	run curl_metrics
	[[ "$status" -eq 0 ]]

	cat >"${POLICY_DIR}/default.json" <<-'EOF'
		{
		  "slsa": {"missingPolicy": "deny"},
		  "vex": {"missingPolicy": "allow"}
		}
	EOF
	write_plugin_config "warn"
	reload_plugin
}

@test "SIGHUP without --config is a no-op" {
	stop_plugin

	"$BINARY" \
		--log-level debug \
		>"$PLUGIN_LOG" 2>&1 &
	echo $! >"$PLUGIN_PID_FILE"
	# shellcheck disable=SC2034
	LOG_OFFSET=0
	local elapsed=0
	while [[ $elapsed -lt 10 ]]; do
		if grep -qE "Connected to runtime|Starting NRI plugin" "$PLUGIN_LOG" 2>/dev/null; then
			break
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done

	reload_plugin
	assert_log_contains "No config file specified, skipping reload"

	stop_plugin
	write_plugin_config "warn"
	start_plugin
}

@test "mode change from enforce to disabled stops rejecting" {
	write_plugin_config "enforce"
	reload_plugin

	run_pod "enforce-pod" "registry.k8s.io/pause:3.10" || true
	assert_log_contains "Container rejected"

	write_plugin_config "disabled"
	reload_plugin

	run_pod "disabled-after" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "disabled-after" "Running"

	write_plugin_config "warn"
	reload_plugin
}

@test "mode change from disabled to warn starts logging" {
	write_plugin_config "disabled"
	reload_plugin

	run_pod "disabled-nolog" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "disabled-nolog" "Running"

	# shellcheck disable=SC2034
	LOG_OFFSET=$(wc -c <"$PLUGIN_LOG")

	write_plugin_config "warn"
	reload_plugin

	run_pod "warn-log" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "warn-log" "Running"
	assert_log_contains "Verification failed (warn mode, allowing)"
}

@test "cache is cleared on config reload" {
	stop_plugin
	write_plugin_config "warn"
	start_plugin

	run_pod "cache-hit-1" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "cache-hit-1" "Running"

	run_pod "cache-hit-2" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "cache-hit-2" "Running"
	wait_for_metrics "nri_supply_chain_cache_hits_total"

	local hits_before
	hits_before=$(curl_metrics | awk '/nri_supply_chain_cache_hits_total/ && !/^#/ {print $2; exit}')
	hits_before="${hits_before:-0}"
	echo "hits_before=$hits_before" >&2
	[[ "${hits_before%.*}" -ge 1 ]]

	local misses_before
	misses_before=$(curl_metrics | awk '/nri_supply_chain_cache_misses_total/ && !/^#/ {print $2; exit}')
	misses_before="${misses_before:-0}"

	write_plugin_config "warn" "allow"
	reload_plugin

	run_pod "cache-after" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "cache-after" "Running"
	wait_for_metrics "nri_supply_chain_cache_misses_total"

	local misses_after
	misses_after=$(curl_metrics | awk '/nri_supply_chain_cache_misses_total/ && !/^#/ {print $2; exit}')
	misses_after="${misses_after:-0}"
	echo "misses_before=$misses_before misses_after=$misses_after" >&2
	[[ "${misses_after%.*}" -gt "${misses_before%.*}" ]]

	write_plugin_config "warn"
	reload_plugin
}
