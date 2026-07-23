#!/usr/bin/env bats

load helpers

DAEMONSET_IMAGE="${REGISTRY_HOST}/nri-supply-chain/plugin:test"

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	cat >"$POLICY_DIR/default.json" <<-'EOF'
		{
		  "slsa": {"missingPolicy": "allow"},
		  "vex": {"missingPolicy": "allow"}
		}
	EOF

	# Configure insecure registry and start it BEFORE kubernix so:
	# - CRI-O reads registries.conf at startup (SIGHUP won't reload it)
	# - containerd config gets patched with config_path for certs.d
	start_registry
	configure_insecure_registry

	start_kubernix

	wait_for_node_ready
	write_nri_dropin
	reload_runtime

	# Symlink /var/run/nri to the kubernix NRI socket directory so the
	# DaemonSet hostPath volume mount finds the socket.
	if [[ ! -e /var/run/nri ]]; then
		ln -s "${KUBERNIX_ROOT}/nri" /var/run/nri
	fi

	build_daemonset_image "$DAEMONSET_IMAGE"
	deploy_daemonset "$DAEMONSET_IMAGE"
	wait_for_daemonset_ready
	start_metrics_portforward
}

teardown_file() {
	stop_metrics_portforward
	kubectl delete -f "$DAEMONSET_MANIFEST" 2>/dev/null || true
	[[ -L /var/run/nri ]] && rm -f /var/run/nri
	unconfigure_insecure_registry
	stop_registry
	stop_kubernix
}

# --- Deployment tests ---

@test "daemonset pod reaches Running state" {
	local pod
	pod=$(get_daemonset_pod_name)
	local phase
	phase=$(kubectl get pod "$pod" -n "$DAEMONSET_NS" \
		-o jsonpath='{.status.phase}')
	[[ "$phase" == "Running" ]]
}

@test "daemonset pod passes readiness probe" {
	local pod
	pod=$(get_daemonset_pod_name)
	local ready
	ready=$(kubectl get pod "$pod" -n "$DAEMONSET_NS" \
		-o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
	[[ "$ready" == "True" ]]
}

@test "daemonset has correct desired vs ready count" {
	local desired ready
	desired=$(kubectl get daemonset nri-supply-chain -n "$DAEMONSET_NS" \
		-o jsonpath='{.status.desiredNumberScheduled}')
	ready=$(kubectl get daemonset nri-supply-chain -n "$DAEMONSET_NS" \
		-o jsonpath='{.status.numberReady}')
	[[ "$desired" -gt 0 ]]
	[[ "$ready" -eq "$desired" ]]
}

@test "daemonset container is currently running" {
	local pod
	pod=$(get_daemonset_pod_name)
	local state
	state=$(kubectl get pod "$pod" -n "$DAEMONSET_NS" \
		-o jsonpath='{.status.containerStatuses[0].state.running.startedAt}')
	[[ -n "$state" ]]
}

# --- Probe tests ---

@test "healthz endpoint responds via port-forward" {
	ensure_metrics_portforward
	run curl -sf "http://localhost:${DAEMONSET_METRICS_PORT}/healthz"
	[[ "$status" -eq 0 ]]
}

@test "readyz endpoint responds via port-forward" {
	ensure_metrics_portforward
	run curl -sf "http://localhost:${DAEMONSET_METRICS_PORT}/readyz"
	[[ "$status" -eq 0 ]]
}

# --- Metrics tests ---

@test "metrics endpoint returns build_info" {
	ensure_metrics_portforward
	run curl -sf "http://localhost:${DAEMONSET_METRICS_PORT}/metrics"
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_build_info'
}

@test "metrics endpoint returns valid Prometheus format" {
	ensure_metrics_portforward
	run curl -sf "http://localhost:${DAEMONSET_METRICS_PORT}/metrics"
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q '^# HELP'
	echo "$output" | grep -q '^# TYPE'
}

# --- NRI interception tests ---

@test "plugin logs connected to runtime" {
	assert_daemonset_log_contains "Connected to runtime"
}

@test "creating a pod triggers verification in daemonset plugin" {
	local test_ns
	test_ns="ds-test-$(date +%s)"
	kubectl create namespace "$test_ns" 2>/dev/null || true

	local elapsed=0
	while [[ $elapsed -lt 30 ]]; do
		if kubectl get serviceaccount default -n "$test_ns" &>/dev/null; then
			break
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done

	# Use a local registry image so the plugin can resolve referrers
	# quickly (no external network dependency). System images from
	# registry.k8s.io are excluded in the DaemonSet policy.
	local test_image="${REGISTRY_HOST}/test/ds-verify:latest"
	"$CRANE" copy registry.k8s.io/pause:3.10 "$test_image" --insecure

	kubectl run ds-verify-pod \
		--namespace "$test_ns" \
		--image "$test_image" \
		--restart=Never

	local pod_elapsed=0
	while [[ $pod_elapsed -lt 60 ]]; do
		local phase
		phase=$(kubectl get pod ds-verify-pod -n "$test_ns" \
			-o jsonpath='{.status.phase}' 2>/dev/null || true)
		if [[ "$phase" == "Running" ]]; then
			break
		fi
		sleep 2
		pod_elapsed=$((pod_elapsed + 2))
	done

	assert_daemonset_log_contains "Container verified" 30

	kubectl delete pod ds-verify-pod -n "$test_ns" --force --grace-period=0 2>/dev/null || true
	kubectl delete namespace "$test_ns" 2>/dev/null || true
}
