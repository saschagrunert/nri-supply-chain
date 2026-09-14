#!/usr/bin/env bats

load helpers

DAEMONSET_IMAGE="${REGISTRY_HOST}/nri-supply-chain/plugin:test"

setup_file() {
	mkdir -p "$KUBERNIX_ROOT"

	# Configure insecure registry and start it BEFORE kubernix so:
	# - CRI-O reads registries.conf at startup (SIGHUP won't reload it)
	# - containerd config gets patched with config_path for certs.d
	start_registry
	configure_insecure_registry

	start_kubernix_with_retry

	# Symlink /var/run/nri to the kubernix NRI socket directory so the
	# DaemonSet hostPath volume mount finds the socket.
	if [[ ! -e /var/run/nri ]]; then
		ln -s "${KUBERNIX_ROOT}/nri" /var/run/nri
	fi

	build_daemonset_image "$DAEMONSET_IMAGE"
	deploy_helm_chart "$DAEMONSET_IMAGE"
	wait_for_daemonset_ready
	start_metrics_portforward
}

teardown_file() {
	stop_metrics_portforward
	kubectl delete -f "$DAEMONSET_MANIFEST" --request-timeout="${KUBECTL_TIMEOUT}s" 2>/dev/null || true
	[[ -L /var/run/nri ]] && rm -f /var/run/nri
	unconfigure_insecure_registry
	stop_registry
	stop_kubernix
}

@test "helm chart pod runs with the shipped security context" {
	local pod
	pod=$(get_daemonset_pod_name)

	local phase
	phase=$(kubectl get pod "$pod" -n "$DAEMONSET_NS" \
		-o jsonpath='{.status.phase}' --request-timeout="${KUBECTL_TIMEOUT}s")
	[[ "$phase" == "Running" ]]

	local read_only
	read_only=$(kubectl get pod "$pod" -n "$DAEMONSET_NS" \
		-o jsonpath='{.spec.containers[0].securityContext.readOnlyRootFilesystem}' \
		--request-timeout="${KUBECTL_TIMEOUT}s")
	[[ "$read_only" == "true" ]]

	local dropped
	dropped=$(kubectl get pod "$pod" -n "$DAEMONSET_NS" \
		-o jsonpath='{.spec.containers[0].securityContext.capabilities.drop[*]}' \
		--request-timeout="${KUBECTL_TIMEOUT}s")
	[[ "$dropped" == "ALL" ]]
}

@test "helm chart pod passes readiness probe" {
	local pod
	pod=$(get_daemonset_pod_name)
	local ready
	ready=$(kubectl get pod "$pod" -n "$DAEMONSET_NS" \
		-o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' --request-timeout="${KUBECTL_TIMEOUT}s")
	[[ "$ready" == "True" ]]
}

@test "helm chart metrics endpoint returns build_info" {
	ensure_metrics_portforward
	run curl -sf --max-time "$CURL_TIMEOUT" "http://localhost:${DAEMONSET_METRICS_PORT}/metrics"
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_build_info'
}

@test "helm chart plugin connects to runtime" {
	assert_daemonset_log_contains "Connected to runtime"
}

@test "creating a pod triggers verification in helm chart plugin" {
	local test_ns
	test_ns="helm-test-$(date +%s)"
	kubectl create namespace "$test_ns" --request-timeout="${KUBECTL_TIMEOUT}s" 2>/dev/null || true

	local elapsed=0
	while [[ $elapsed -lt 30 ]]; do
		if kubectl get serviceaccount default -n "$test_ns" --request-timeout="${CURL_TIMEOUT}s" &>/dev/null; then
			break
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done

	# Use a local registry image so the plugin can resolve referrers
	# quickly. System images from registry.k8s.io are excluded by the
	# chart's default policy.
	local test_image="${REGISTRY_HOST}/test/helm-verify:latest"
	timeout "$CMD_TIMEOUT" "$CRANE" copy "$PAUSE_IMAGE" "$test_image" --insecure

	kubectl run helm-verify-pod \
		--namespace "$test_ns" \
		--image "$test_image" \
		--restart=Never \
		--request-timeout="${KUBECTL_TIMEOUT}s"

	assert_daemonset_log_contains "Container verified" 60

	kubectl delete pod helm-verify-pod -n "$test_ns" --force --grace-period=0 --request-timeout="${KUBECTL_TIMEOUT}s" 2>/dev/null || true
	kubectl delete namespace "$test_ns" --request-timeout="${KUBECTL_TIMEOUT}s" 2>/dev/null || true
}
