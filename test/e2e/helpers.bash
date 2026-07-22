#!/usr/bin/env bash

bats_require_minimum_version 1.5.0

BINARY="${BINARY:-build/nri-supply-chain}"
KUBERNIX="${KUBERNIX:-build/kubernix}"
COSIGN="${COSIGN:-build/cosign}"
CRANE="${CRANE:-build/crane}"
CRI_RUNTIME="${CRI_RUNTIME:-crio}"
KUBERNIX_ROOT="${BATS_FILE_TMPDIR}/kubernix"
PLUGIN_PID_FILE="${BATS_FILE_TMPDIR}/plugin.pid"
PLUGIN_LOG="${BATS_FILE_TMPDIR}/plugin.log"
PLUGIN_CONFIG="${BATS_FILE_TMPDIR}/config.toml"
POLICY_DIR="${BATS_FILE_TMPDIR}/policies"
KUBECONFIG="${KUBERNIX_ROOT}/kubeconfig/admin.kubeconfig"
NRI_SOCKET="${KUBERNIX_ROOT}/nri/nri.sock"

export KUBECONFIG

is_containerd() {
	[[ "$CRI_RUNTIME" == "containerd" ]]
}

start_kubernix() {
	local patcher_pid=""

	# containerd terminates on SIGHUP so we cannot reload its config
	# after startup. Patch config_path into the generated config before
	# containerd reads it by polling in a background process.
	if is_containerd && [[ -d "/etc/containerd/certs.d" ]]; then
		_patch_containerd_registry_config &
		patcher_pid=$!
	fi

	"$KUBERNIX" --no-shell --cri-runtime "$CRI_RUNTIME" "$@" --root "$KUBERNIX_ROOT" &
	echo $! >"${BATS_FILE_TMPDIR}/kubernix.pid"

	if [[ -n "$patcher_pid" ]]; then
		wait "$patcher_pid" 2>/dev/null || true
	fi
}

_patch_containerd_registry_config() {
	local config elapsed=0
	while [[ $elapsed -lt 3000 ]]; do
		config=$(find "${KUBERNIX_ROOT}" -name "config.toml" \
			-path "*/containerd/*" 2>/dev/null | head -1)
		if [[ -n "$config" ]]; then
			cat >>"$config" <<-EOF

				[plugins."io.containerd.cri.v1.images".registry]
				config_path = "/etc/containerd/certs.d"
			EOF
			return
		fi
		sleep 0.01
		elapsed=$((elapsed + 1))
	done
	echo "ERROR: containerd config.toml not found in ${KUBERNIX_ROOT} after 30s" >&2
	return 1
}

export NODE_READY_TIMEOUT=120
export POD_TIMEOUT=60

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	echo '{}' >"$POLICY_DIR/default.json"

	start_kubernix --log-level debug

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

stop_kubernix() {
	if [[ -f "${BATS_FILE_TMPDIR}/kubernix.pid" ]]; then
		local pid
		pid=$(cat "${BATS_FILE_TMPDIR}/kubernix.pid")
		kill "$pid" 2>/dev/null || true
		local elapsed=0
		while kill -0 "$pid" 2>/dev/null && [[ $elapsed -lt 10 ]]; do
			sleep 1
			elapsed=$((elapsed + 1))
		done
		if kill -0 "$pid" 2>/dev/null; then
			kill -9 "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
		fi
	fi
	pkill -f "${KUBERNIX_ROOT}" 2>/dev/null || true
	sleep 1
	pkill -9 -f "${KUBERNIX_ROOT}" 2>/dev/null || true

	# Unmount leftover mounts (overlay, shm, projected volumes) to allow
	# bats temp directory cleanup to succeed.
	if command -v findmnt &>/dev/null; then
		findmnt -rn -o TARGET | grep "${BATS_FILE_TMPDIR}" | sort -r | while read -r mp; do
			umount -l "$mp" 2>/dev/null || true
		done
	fi
}

setup() {
	TEST_NS="test-$(date +%s)-${BATS_TEST_NUMBER}"
	kubectl create namespace "$TEST_NS" 2>/dev/null || true
	wait_for_service_account "$TEST_NS"
	if [[ -f "$PLUGIN_LOG" ]]; then
		LOG_OFFSET=$(wc -c <"$PLUGIN_LOG")
	else
		LOG_OFFSET=0
	fi
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
	echo "DEBUG: kubectl get nodes:" >&2
	kubectl get nodes -o wide 2>&1 >&2 || true
	echo "DEBUG: node conditions:" >&2
	kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}: {range .status.conditions[*]}{.type}={.status} ({.reason}: {.message}) {end}{"\n"}{end}' 2>&1 >&2 || true
	return 1
}

wait_for_service_account() {
	local ns="${1}"
	local elapsed=0
	while [[ $elapsed -lt 30 ]]; do
		if kubectl get serviceaccount default -n "$ns" &>/dev/null; then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	echo "ERROR: Default service account not created in $ns after 30s" >&2
	return 1
}

write_nri_dropin() {
	# NRI is enabled by default in containerd v2, nothing to configure.
	# Registry config_path is handled by start_kubernix.
	if is_containerd; then
		return
	fi

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

reload_runtime() {
	# containerd terminates on SIGHUP, config is patched before startup.
	if is_containerd; then
		return
	fi

	local crio_pid
	crio_pid=$(pgrep -f "crio.*--root.*${KUBERNIX_ROOT}" || true)
	if [[ -n "$crio_pid" ]]; then
		kill -HUP "$crio_pid"
		sleep 2
	fi
}

write_plugin_config() {
	local mode="${1:-warn}"
	local fetch_failure="${2:-deny}"
	cat >"$PLUGIN_CONFIG" <<-EOF
		verification = "${mode}"
		policy_dir = "${POLICY_DIR}"
		fetch_timeout = "30s"
		fetch_failure_policy = "${fetch_failure}"
		cache_ttl = "5m"
		metrics_addr = ":9090"
	EOF
}

start_plugin() {
	LOG_OFFSET=0
	"$BINARY" \
		--config "$PLUGIN_CONFIG" \
		--log-level debug \
		>"$PLUGIN_LOG" 2>&1 &
	echo $! >"$PLUGIN_PID_FILE"
	local elapsed=0
	while [[ $elapsed -lt 10 ]]; do
		if grep -q "Connected to runtime" "$PLUGIN_LOG" 2>/dev/null; then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
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
		local before_count
		before_count=$(grep -c "Config reloaded\|Config reload\|No config file" "$PLUGIN_LOG" 2>/dev/null || true)
		kill -HUP "$(cat "$PLUGIN_PID_FILE")"
		local elapsed=0
		while [[ $elapsed -lt 10 ]]; do
			local after_count
			after_count=$(grep -c "Config reloaded\|Config reload\|No config file" "$PLUGIN_LOG" 2>/dev/null || true)
			if [[ "$after_count" -gt "$before_count" ]]; then
				return 0
			fi
			sleep 1
			elapsed=$((elapsed + 1))
		done
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
	local ns="${4:-$TEST_NS}"
	local elapsed=0

	while [[ $elapsed -lt $timeout ]]; do
		local status
		status=$(kubectl get pod "$name" -n "$ns" -o jsonpath='{.status.phase}' 2>/dev/null || true)
		if [[ "$status" == "$expected" ]]; then
			return 0
		fi

		local container_status
		container_status=$(kubectl get pod "$name" -n "$ns" -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || true)
		if [[ "$expected" == "CreateContainerError" && "$container_status" == "CreateContainerError" ]]; then
			return 0
		fi

		sleep 2
		elapsed=$((elapsed + 2))
	done

	echo "ERROR: Pod $name did not reach status $expected after ${timeout}s (current: ${status:-unknown}, container: ${container_status:-unknown})" >&2
	echo "DEBUG: kubectl describe pod $name -n $ns:" >&2
	kubectl describe pod "$name" -n "$ns" 2>&1 >&2 || true
	echo "DEBUG: plugin log (NRI container info + errors):" >&2
	grep -E '(NRI container|Container rejected|Container verified|Missing image)' "$PLUGIN_LOG" 2>&1 | tail -10 >&2 || true
	echo "DEBUG: plugin log (attestation fetch):" >&2
	grep -E '(Referrers lookup|Referrer manifest|Failed to extract|listing referrers|fetching attestation|no provenance|all referrer)' "$PLUGIN_LOG" 2>&1 | tail -10 >&2 || true
	return 1
}

plugin_log_contains() {
	local pattern="$1"
	tail -c +"$((LOG_OFFSET + 1))" "$PLUGIN_LOG" | grep -q "$pattern"
}

assert_log_contains() {
	local pattern="$1"
	local timeout="${2:-30}"
	local elapsed=0
	while [[ $elapsed -lt $timeout ]]; do
		if plugin_log_contains "$pattern"; then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	echo "ASSERTION FAILED: plugin log does not contain '$pattern' after ${timeout}s" >&2
	echo "=== Plugin log tail (from offset $LOG_OFFSET) ===" >&2
	tail -c +"$((LOG_OFFSET + 1))" "$PLUGIN_LOG" | tail -30 >&2
	echo "=== End plugin log ===" >&2
	return 1
}

assert_pod_verdict() {
	local pod_name="$1"
	local verdict="$2"
	local ns="${3:-$TEST_NS}"
	local timeout="${4:-60}"
	local msg="Container ${verdict}"
	local elapsed=0
	while [[ $elapsed -lt $timeout ]]; do
		if tail -c +"$((LOG_OFFSET + 1))" "$PLUGIN_LOG" | grep "${ns}/${pod_name}" | grep -q "${msg}"; then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	echo "ASSERTION FAILED: pod ${ns}/${pod_name} not ${verdict} after ${timeout}s" >&2
	echo "=== Plugin log tail (from offset $LOG_OFFSET) ===" >&2
	tail -c +"$((LOG_OFFSET + 1))" "$PLUGIN_LOG" | tail -30 >&2
	echo "=== End plugin log ===" >&2
	return 1
}

restore_default_keybased_policy() {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin
}

curl_metrics() {
	local addr="${1:-localhost:9090}"
	curl -sf "http://${addr}/metrics"
}

wait_for_metrics() {
	local pattern="${1:-nri_supply_chain}"
	local addr="${2:-localhost:9090}"
	local timeout="${3:-10}"
	local elapsed=0
	while [[ $elapsed -lt $timeout ]]; do
		if curl -sf "http://${addr}/metrics" 2>/dev/null | grep -q "$pattern"; then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	return 1
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

# --- Local registry and attestation helpers ---

REGISTRY_PORT=5050
REGISTRY_HOST="localhost:${REGISTRY_PORT}"
REGISTRY_PID_FILE="${BATS_FILE_TMPDIR:-/tmp}/registry.pid"
COSIGN_KEY="${BATS_FILE_TMPDIR:-/tmp}/cosign.key"
COSIGN_PUB="${BATS_FILE_TMPDIR:-/tmp}/cosign.pub"
COSIGN_PASSWORD=""
export COSIGN_PASSWORD COSIGN_PUB

start_registry() {
	"$CRANE" registry serve --address ":${REGISTRY_PORT}" &
	echo $! >"$REGISTRY_PID_FILE"
	local elapsed=0
	while [[ $elapsed -lt 10 ]]; do
		if curl -sf "http://${REGISTRY_HOST}/v2/" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	echo "ERROR: Registry not reachable on ${REGISTRY_HOST} after 10s" >&2
	return 1
}

stop_registry() {
	if [[ -f "$REGISTRY_PID_FILE" ]]; then
		kill "$(cat "$REGISTRY_PID_FILE")" 2>/dev/null || true
		wait "$(cat "$REGISTRY_PID_FILE")" 2>/dev/null || true
		rm -f "$REGISTRY_PID_FILE"
	fi
}

generate_signing_key() {
	"$COSIGN" generate-key-pair --output-key-prefix "${BATS_FILE_TMPDIR}/cosign"
}

push_test_image() {
	local tag="$1"
	local ref="${REGISTRY_HOST}/test/${tag}"
	local output
	if ! output=$("$CRANE" copy --platform linux/amd64 registry.k8s.io/pause:3.10 "$ref" --insecure 2>&1); then
		echo "ERROR: crane copy failed for $ref: $output" >&2
		return 1
	fi
	if ! output=$("$CRANE" mutate --label "nri-test=${tag}" "$ref" --insecure 2>&1); then
		echo "ERROR: crane mutate failed for $ref: $output" >&2
		return 1
	fi
	echo "$ref"
}

get_image_digest() {
	local ref="$1"
	local digest
	if ! digest=$("$CRANE" digest "$ref" --insecure 2>&1); then
		echo "ERROR: crane digest failed for $ref: $digest" >&2
		return 1
	fi
	echo "$digest"
}

configure_insecure_registry() {
	if is_containerd; then
		local hosts_dir="/etc/containerd/certs.d/${REGISTRY_HOST}"
		mkdir -p "$hosts_dir"
		cat >"${hosts_dir}/hosts.toml" <<-EOF
			server = "http://${REGISTRY_HOST}"

			[host."http://${REGISTRY_HOST}"]
			  capabilities = ["pull", "resolve", "push"]
			  skip_verify = true
		EOF

		return
	fi

	mkdir -p /etc/containers/registries.conf.d
	cat >/etc/containers/registries.conf.d/test-insecure-registry.conf <<-EOF
		[[registry]]
		location = "${REGISTRY_HOST}"
		insecure = true
	EOF
}

unconfigure_insecure_registry() {
	if is_containerd; then
		rm -rf "/etc/containerd/certs.d/${REGISTRY_HOST}"

		return
	fi

	rm -f /etc/containers/registries.conf.d/test-insecure-registry.conf
}

create_signing_config() {
	local config_file="${BATS_FILE_TMPDIR}/signing-config.json"
	if [[ ! -f "$config_file" ]]; then
		"$COSIGN" signing-config create >"$config_file"
	fi
	echo "$config_file"
}

attest_image() {
	local ref="$1"
	local predicate_type="$2"
	local predicate_file="$3"
	local signing_config
	signing_config=$(create_signing_config)
	local output
	if ! output=$("$COSIGN" attest \
		--key "$COSIGN_KEY" \
		--type "$predicate_type" \
		--predicate "$predicate_file" \
		--signing-config "$signing_config" \
		--allow-insecure-registry \
		"$ref" 2>&1); then
		echo "ERROR: cosign attest failed for $ref: $output" >&2
		return 1
	fi
}

write_slsa_predicate() {
	local file="$1"
	local builder_id="$2"
	local source="$3"
	local build_type="${4:-}"
	local extra_params="${5:-}"

	local ext_params
	ext_params="{\"source\": \"${source}\"${extra_params:+, ${extra_params}}}"

	cat >"$file" <<-EOF
		{
		  "buildDefinition": {
		    "buildType": "${build_type:-https://github.com/actions/runner}",
		    "externalParameters": ${ext_params},
		    "internalParameters": {}
		  },
		  "runDetails": {
		    "builder": {"id": "${builder_id}"},
		    "metadata": {"invocationId": "test-invocation"}
		  }
		}
	EOF
}

write_vex_predicate() {
	local file="$1"
	local status="$2"
	local product="$3"
	local vuln_id="${4:-CVE-2024-0001}"

	cat >"$file" <<-EOF
		{
		  "@context": "https://openvex.dev/ns/v0.2.0",
		  "@id": "https://openvex.dev/docs/example/vex-test",
		  "author": "test",
		  "timestamp": "2024-01-01T00:00:00Z",
		  "statements": [
		    {
		      "vulnerability": {"name": "${vuln_id}"},
		      "products": [{"@id": "${product}"}],
		      "status": "${status}"
		    }
		  ]
		}
	EOF
}

write_vsa_predicate() {
	local file="$1"
	local verifier_id="$2"
	local resource_uri="$3"
	local result="$4"
	local level="${5:-SLSA_BUILD_LEVEL_3}"
	local time_verified="${6:-2025-01-01T00:00:00Z}"
	local policy_uri="${7:-}"
	local slsa_version="${8:-1.0}"

	local policy_block=""
	if [[ -n "$policy_uri" ]]; then
		policy_block=", \"policy\": {\"uri\": \"${policy_uri}\"}"
	fi

	cat >"$file" <<-EOF
		{
		  "verifier": {"id": "${verifier_id}"},
		  "timeVerified": "${time_verified}",
		  "resourceUri": "${resource_uri}",
		  "verificationResult": "${result}",
		  "verifiedLevels": ["${level}"],
		  "slsaVersion": "${slsa_version}"
		  ${policy_block}
		}
	EOF
}
