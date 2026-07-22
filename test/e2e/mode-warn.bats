#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	cat >"$POLICY_DIR/default.json" <<-'EOF'
		{
		  "trust": {
		    "builders": [
		      {"id": "https://github.com/actions/runner", "maxLevel": 3}
		    ]
		  },
		  "provenance": {"missingPolicy": "deny"},
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

@test "pod with unsigned image is admitted with warning" {
	run_pod "unsigned-pod" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "unsigned-pod" "Running"
	assert_log_contains "Verification failed (warn mode, allowing)"
}

@test "pod with image lacking provenance is admitted in warn mode" {
	run_pod "noprov-pod" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "noprov-pod" "Running"
	assert_log_contains "Supply chain audit"
}

@test "pod with image lacking VEX is admitted with default allow" {
	run_pod "novex-pod" "registry.k8s.io/pause:3.10"
	wait_for_pod_status "novex-pod" "Running"
}

@test "multiple containers in one pod are each verified" {
	kubectl run "multi-pod" \
		--namespace "$TEST_NS" \
		--image "registry.k8s.io/pause:3.10" \
		--restart=Never \
		--overrides='{
			"spec": {
				"containers": [
					{"name": "c1", "image": "registry.k8s.io/pause:3.10"},
					{"name": "c2", "image": "registry.k8s.io/pause:3.10"}
				]
			}
		}'

	local count=0 elapsed=0
	while [[ $elapsed -lt 30 ]]; do
		count=$(tail -c +"$((LOG_OFFSET + 1))" "$PLUGIN_LOG" | grep -c "Container verified" || true)
		if [[ "$count" -ge 2 ]]; then
			break
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	[[ "$count" -ge 2 ]]
}

@test "init containers are verified" {
	kubectl run "init-pod" \
		--namespace "$TEST_NS" \
		--image "registry.k8s.io/pause:3.10" \
		--restart=Never \
		--overrides='{
			"spec": {
				"initContainers": [
					{"name": "init", "image": "registry.k8s.io/pause:3.10"}
				],
				"containers": [
					{"name": "main", "image": "registry.k8s.io/pause:3.10"}
				]
			}
		}'
	assert_log_contains "Container verified"
}
