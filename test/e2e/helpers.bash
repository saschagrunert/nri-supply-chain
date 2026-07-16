#!/usr/bin/env bash

BINARY="${BINARY:-build/nri-supply-chain}"
KUBERNIX="${KUBERNIX:-build/kubernix}"
KUBERNIX_ROOT="${BATS_FILE_TMPDIR}/kubernix"
PLUGIN_PID_FILE="${BATS_FILE_TMPDIR}/plugin.pid"
PLUGIN_LOG="${BATS_FILE_TMPDIR}/plugin.log"
PLUGIN_CONFIG="${BATS_FILE_TMPDIR}/config.toml"
POLICY_DIR="${BATS_FILE_TMPDIR}/policies"
KUBECONFIG="${KUBERNIX_ROOT}/kubeconfig"
NRI_SOCKET="${KUBERNIX_ROOT}/nri/nri.sock"

export KUBECONFIG

export NODE_READY_TIMEOUT=120
export POD_TIMEOUT=60

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	echo '{}' >"$POLICY_DIR/default.json"

	"$KUBERNIX" --no-shell --root "$KUBERNIX_ROOT" &
	echo $! >"${BATS_FILE_TMPDIR}/kubernix.pid"

	wait_for_node_ready

	write_nri_dropin
	reload_crio

	write_plugin_config "warn"
	start_plugin
}

teardown_file() {
	stop_plugin

	if [[ -f "${BATS_FILE_TMPDIR}/kubernix.pid" ]]; then
		kill "$(cat "${BATS_FILE_TMPDIR}/kubernix.pid")" 2>/dev/null || true
		wait "$(cat "${BATS_FILE_TMPDIR}/kubernix.pid")" 2>/dev/null || true
	fi
}

setup() {
	TEST_NS="test-$(date +%s)-${BATS_TEST_NUMBER}"
	kubectl create namespace "$TEST_NS" 2>/dev/null || true
}

teardown() {
	kubectl delete pods --all -n "$TEST_NS" --force --grace-period=0 2>/dev/null || true
	kubectl delete namespace "$TEST_NS" 2>/dev/null || true
}

wait_for_node_ready() {
	local elapsed=0
	while [[ $elapsed -lt $NODE_READY_TIMEOUT ]]; do
		if kubectl get nodes 2>/dev/null | grep -q " Ready"; then
			return 0
		fi
		sleep 2
		elapsed=$((elapsed + 2))
	done
	echo "ERROR: Node not ready after ${NODE_READY_TIMEOUT}s" >&2
	return 1
}

write_nri_dropin() {
	local crio_conf_dir
	crio_conf_dir="${KUBERNIX_ROOT}/crio/conf.d"
	mkdir -p "$crio_conf_dir"

	cat >"${crio_conf_dir}/10-nri.conf" <<-EOF
		[crio.nri]
		enable_nri = true
		nri_plugin_dir = ""
		nri_socket = "${NRI_SOCKET}"
	EOF
}

reload_crio() {
	local crio_pid
	crio_pid=$(pgrep -f "crio.*--root.*${KUBERNIX_ROOT}" || true)
	if [[ -n "$crio_pid" ]]; then
		kill -HUP "$crio_pid"
		sleep 2
	fi
}

write_plugin_config() {
	local mode="${1:-warn}"
	cat >"$PLUGIN_CONFIG" <<-EOF
		verification = "${mode}"
		policy_dir = "${POLICY_DIR}"
		fetch_timeout = "30s"
		cache_ttl = "5m"
		metrics_addr = ":9090"
	EOF
}

start_plugin() {
	"$BINARY" \
		--config "$PLUGIN_CONFIG" \
		--log-level debug \
		>"$PLUGIN_LOG" 2>&1 &
	echo $! >"$PLUGIN_PID_FILE"
	sleep 2
}

stop_plugin() {
	if [[ -f "$PLUGIN_PID_FILE" ]]; then
		kill "$(cat "$PLUGIN_PID_FILE")" 2>/dev/null || true
		wait "$(cat "$PLUGIN_PID_FILE")" 2>/dev/null || true
		rm -f "$PLUGIN_PID_FILE"
	fi
}

reload_plugin() {
	if [[ -f "$PLUGIN_PID_FILE" ]]; then
		kill -HUP "$(cat "$PLUGIN_PID_FILE")"
		sleep 1
	fi
}

run_pod() {
	local name="$1"
	local image="$2"
	shift 2
	kubectl run "$name" \
		--namespace "$TEST_NS" \
		--image "$image" \
		--restart=Never \
		"$@"
}

wait_for_pod_status() {
	local name="$1"
	local expected="$2"
	local timeout="${3:-$POD_TIMEOUT}"
	local elapsed=0

	while [[ $elapsed -lt $timeout ]]; do
		local status
		status=$(kubectl get pod "$name" -n "$TEST_NS" -o jsonpath='{.status.phase}' 2>/dev/null || true)
		if [[ "$status" == "$expected" ]]; then
			return 0
		fi

		local container_status
		container_status=$(kubectl get pod "$name" -n "$TEST_NS" -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || true)
		if [[ "$expected" == "CreateContainerError" && "$container_status" == "CreateContainerError" ]]; then
			return 0
		fi

		sleep 2
		elapsed=$((elapsed + 2))
	done

	echo "ERROR: Pod $name did not reach status $expected after ${timeout}s (current: ${status:-unknown}, container: ${container_status:-unknown})" >&2
	return 1
}

plugin_log_contains() {
	local pattern="$1"
	grep -q "$pattern" "$PLUGIN_LOG"
}

curl_metrics() {
	local addr="${1:-localhost:9090}"
	curl -sf "http://${addr}/metrics"
}

write_policy() {
	local namespace="$1"
	local content="$2"
	local filename

	if [[ "$namespace" == "default" ]]; then
		filename="default.json"
	else
		filename="${namespace}.json"
	fi

	echo "$content" >"${POLICY_DIR}/${filename}"
}
