#!/usr/bin/env bash

bats_require_minimum_version 1.5.0

BINARY="${BINARY:-build/nri-supply-chain}"
KUBERNIX="${KUBERNIX:-build/kubernix}"
COSIGN="${COSIGN:-build/cosign}"
CRANE="${CRANE:-build/crane}"
CRI_RUNTIME="${CRI_RUNTIME:-crio}"
PAUSE_IMAGE="${PAUSE_IMAGE:-registry.k8s.io/pause:3.10}"
KUBERNIX_ROOT="${BATS_FILE_TMPDIR}/kubernix"
PLUGIN_PID_FILE="${BATS_FILE_TMPDIR}/plugin.pid"
PLUGIN_LOG="${BATS_FILE_TMPDIR}/plugin.log"
PLUGIN_CONFIG="${BATS_FILE_TMPDIR}/config.toml"
POLICY_DIR="${BATS_FILE_TMPDIR}/policies"
KUBECONFIG="${KUBERNIX_ROOT}/kubeconfig/admin.kubeconfig"
NRI_SOCKET="${KUBERNIX_ROOT}/nri/nri.sock"

export KUBECONFIG

CMD_TIMEOUT=120
KUBECTL_TIMEOUT=30
CURL_TIMEOUT=10

is_containerd() {
	[[ "$CRI_RUNTIME" == "containerd" ]]
}

stop_process_from_pidfile() {
	local pidfile=$1
	local name=$2
	if [[ -f "$pidfile" ]]; then
		local pid
		pid=$(cat "$pidfile")
		kill "$pid" 2>/dev/null || true
		local elapsed=0
		while kill -0 "$pid" 2>/dev/null && [[ $elapsed -lt 10 ]]; do
			sleep 1
			elapsed=$((elapsed + 1))
		done
		if kill -0 "$pid" 2>/dev/null; then
			kill -9 "$pid" 2>/dev/null || true
		fi
		wait "$pid" 2>/dev/null || true
		rm -f "$pidfile"
	fi
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
KUBERNIX_MAX_RETRIES=3
KUBERNIX_RETRY_BUDGET=300

wait_for_apiserver_ready() {
	local timeout="${1:-120}"
	local start_time
	start_time=$(date +%s)
	while (($(date +%s) - start_time < timeout)); do
		if kubectl get --raw /healthz --request-timeout="${CURL_TIMEOUT}s" &>/dev/null; then
			return 0
		fi
		sleep 2
	done
	echo "ERROR: API server healthz check failed after ${timeout}s" >&2
	kubectl get --raw '/healthz?verbose' --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
	return 1
}

wait_for_controller_manager() {
	local timeout="${1:-30}"
	local start_time
	start_time=$(date +%s)
	while (($(date +%s) - start_time < timeout)); do
		if kubectl get serviceaccount default -n default --request-timeout="${CURL_TIMEOUT}s" &>/dev/null; then
			return 0
		fi
		sleep 2
	done
	echo "ERROR: controller-manager not functional after ${timeout}s (default SA missing)" >&2
	return 1
}

start_kubernix_with_retry() {
	local attempt
	local retry_start
	retry_start=$(date +%s)
	for attempt in $(seq 1 "$KUBERNIX_MAX_RETRIES"); do
		if [[ $attempt -gt 1 ]]; then
			local elapsed=$(($(date +%s) - retry_start))
			if ((elapsed >= KUBERNIX_RETRY_BUDGET)); then
				echo "ERROR: kubernix retry budget (${KUBERNIX_RETRY_BUDGET}s) exhausted after $((attempt - 1)) attempts" >&2
				return 1
			fi
			echo "Retrying kubernix startup (attempt ${attempt}/${KUBERNIX_MAX_RETRIES}, ${elapsed}s elapsed)..." >&2
			stop_kubernix
			rm -rf "$KUBERNIX_ROOT"
			mkdir -p "$KUBERNIX_ROOT"
		fi

		start_kubernix "$@"

		if wait_for_node_ready && wait_for_apiserver_ready && wait_for_controller_manager; then
			sleep 3
			if wait_for_apiserver_ready 10 && write_nri_dropin && reload_runtime; then
				return 0
			fi
			echo "Cluster became unstable after passing health checks, retrying..." >&2
		fi
	done

	echo "ERROR: kubernix failed to start after $KUBERNIX_MAX_RETRIES attempts" >&2
	return 1
}

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	echo '{}' >"$POLICY_DIR/default.json"

	start_kubernix_with_retry --log-level debug

	write_plugin_config "warn"
	start_plugin
}

teardown_file() {
	stop_plugin
	stop_kubernix
}

stop_kubernix() {
	stop_process_from_pidfile "${BATS_FILE_TMPDIR}/kubernix.pid" "kubernix"
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
	kubectl create namespace "$TEST_NS" --request-timeout="${KUBECTL_TIMEOUT}s" 2>/dev/null || true
	wait_for_service_account "$TEST_NS"
	if [[ -f "$PLUGIN_LOG" ]]; then
		LOG_OFFSET=$(wc -c <"$PLUGIN_LOG")
	else
		LOG_OFFSET=0
	fi
	if [[ -f "$POLICY_DIR/default.json" ]]; then
		SAVED_DEFAULT_POLICY=$(cat "$POLICY_DIR/default.json")
	fi
}

EXTRA_NAMESPACES=()

register_namespace() {
	EXTRA_NAMESPACES+=("$1")
	kubectl create namespace "$1" --request-timeout="${KUBECTL_TIMEOUT}s" 2>/dev/null || true
}

teardown() {
	if [[ -n "${SAVED_DEFAULT_POLICY:-}" ]]; then
		echo "$SAVED_DEFAULT_POLICY" >"$POLICY_DIR/default.json"
	fi
	kubectl delete pods --all -n "$TEST_NS" --force --grace-period=0 --request-timeout="${KUBECTL_TIMEOUT}s" 2>/dev/null || true
	kubectl delete namespace "$TEST_NS" --request-timeout="${KUBECTL_TIMEOUT}s" 2>/dev/null || true
	for ns in "${EXTRA_NAMESPACES[@]}"; do
		kubectl delete pods --all -n "$ns" --force --grace-period=0 --request-timeout="${KUBECTL_TIMEOUT}s" 2>/dev/null || true
		kubectl delete namespace "$ns" --request-timeout="${KUBECTL_TIMEOUT}s" 2>/dev/null || true
	done
	EXTRA_NAMESPACES=()
}

wait_for_node_ready() {
	local kubernix_pid=""
	if [[ -f "${BATS_FILE_TMPDIR}/kubernix.pid" ]]; then
		kubernix_pid=$(cat "${BATS_FILE_TMPDIR}/kubernix.pid")
	fi

	local start_time
	start_time=$(date +%s)
	while (($(date +%s) - start_time < NODE_READY_TIMEOUT)); do
		if [[ -n "$kubernix_pid" ]] && ! kill -0 "$kubernix_pid" 2>/dev/null; then
			echo "ERROR: kubernix process (PID $kubernix_pid) died during startup" >&2
			return 1
		fi
		if kubectl get nodes --request-timeout="${CURL_TIMEOUT}s" 2>/dev/null | grep -q " Ready"; then
			return 0
		fi
		sleep 2
	done
	echo "ERROR: Node not ready after ${NODE_READY_TIMEOUT}s" >&2
	echo "DEBUG: kubectl get nodes:" >&2
	kubectl get nodes -o wide --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
	echo "DEBUG: node conditions:" >&2
	kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}: {range .status.conditions[*]}{.type}={.status} ({.reason}: {.message}) {end}{"\n"}{end}' --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
	return 1
}

wait_for_service_account() {
	local ns="${1}"
	local start_time
	start_time=$(date +%s)
	while (($(date +%s) - start_time < 30)); do
		if kubectl get serviceaccount default -n "$ns" --request-timeout="${CURL_TIMEOUT}s" &>/dev/null; then
			return 0
		fi
		sleep 1
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
	if [[ -z "$crio_pid" ]]; then
		echo "ERROR: CRI-O process not found for ${KUBERNIX_ROOT}" >&2
		return 1
	fi
	if ! kill -HUP "$crio_pid" 2>/dev/null; then
		echo "ERROR: Failed to send SIGHUP to CRI-O (PID $crio_pid)" >&2
		return 1
	fi
	sleep 2
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
	local start_time
	start_time=$(date +%s)
	while (($(date +%s) - start_time < 10)); do
		if grep -q "Connected to runtime" "$PLUGIN_LOG" 2>/dev/null; then
			return 0
		fi
		sleep 1
	done
	echo "ERROR: plugin did not connect within 10s" >&2
	return 1
}

stop_plugin() {
	stop_process_from_pidfile "$PLUGIN_PID_FILE" "plugin"
}

reload_plugin() {
	if [[ -f "$PLUGIN_PID_FILE" ]]; then
		local before_count
		before_count=$(grep -c "Config reloaded\|Config reload\|No config file" "$PLUGIN_LOG" 2>/dev/null || true)
		kill -HUP "$(cat "$PLUGIN_PID_FILE")"
		local start_time
		start_time=$(date +%s)
		while (($(date +%s) - start_time < 10)); do
			local after_count
			after_count=$(grep -c "Config reloaded\|Config reload\|No config file" "$PLUGIN_LOG" 2>/dev/null || true)
			if [[ "$after_count" -gt "$before_count" ]]; then
				return 0
			fi
			sleep 1
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
		--request-timeout="${KUBECTL_TIMEOUT}s" \
		"$@"
}

wait_for_pod_status() {
	local name="$1"
	local expected="$2"
	local timeout="${3:-$POD_TIMEOUT}"
	local ns="${4:-$TEST_NS}"
	local start_time
	start_time=$(date +%s)

	while (($(date +%s) - start_time < timeout)); do
		local status
		status=$(kubectl get pod "$name" -n "$ns" -o jsonpath='{.status.phase}' --request-timeout="${CURL_TIMEOUT}s" 2>/dev/null || true)
		if [[ "$status" == "$expected" ]]; then
			return 0
		fi

		local container_status
		container_status=$(kubectl get pod "$name" -n "$ns" -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' --request-timeout="${CURL_TIMEOUT}s" 2>/dev/null || true)
		if [[ "$expected" == "CreateContainerError" && "$container_status" == "CreateContainerError" ]]; then
			return 0
		fi

		sleep 2
	done

	echo "ERROR: Pod $name did not reach status $expected after ${timeout}s (current: ${status:-unknown}, container: ${container_status:-unknown})" >&2
	echo "DEBUG: kubectl describe pod $name -n $ns:" >&2
	kubectl describe pod "$name" -n "$ns" --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
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
	local start_time
	start_time=$(date +%s)
	while (($(date +%s) - start_time < timeout)); do
		if plugin_log_contains "$pattern"; then
			return 0
		fi
		sleep 1
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
	local start_time
	start_time=$(date +%s)
	while (($(date +%s) - start_time < timeout)); do
		if tail -c +"$((LOG_OFFSET + 1))" "$PLUGIN_LOG" | grep "${ns}/${pod_name}" | grep -q "${msg}"; then
			return 0
		fi
		sleep 1
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
			    "verifiers": [{"id": "test-verifier", "keys": ["${COSIGN_PUB}"]}]
			  },
			  "slsa": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	reload_plugin
}

curl_metrics() {
	local addr="${1:-localhost:9090}"
	curl -sf --max-time "$CURL_TIMEOUT" "http://${addr}/metrics"
}

wait_for_metrics() {
	local pattern="${1:-nri_supply_chain}"
	local addr="${2:-localhost:9090}"
	local timeout="${3:-10}"
	local start_time
	start_time=$(date +%s)
	while (($(date +%s) - start_time < timeout)); do
		if curl -sf --max-time "$CURL_TIMEOUT" "http://${addr}/metrics" 2>/dev/null | grep -q "$pattern"; then
			return 0
		fi
		sleep 1
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

REGISTRY_PORT="${REGISTRY_PORT:-5050}"
REGISTRY_HOST="localhost:${REGISTRY_PORT}"
REGISTRY_PID_FILE="${BATS_FILE_TMPDIR:-/tmp}/registry.pid"
COSIGN_KEY="${BATS_FILE_TMPDIR:-/tmp}/cosign.key"
COSIGN_PUB="${BATS_FILE_TMPDIR:-/tmp}/cosign.pub"
COSIGN_PASSWORD=""
export COSIGN_PASSWORD COSIGN_PUB

start_registry() {
	"$CRANE" registry serve --address ":${REGISTRY_PORT}" &
	echo $! >"$REGISTRY_PID_FILE"
	local start_time
	start_time=$(date +%s)
	while (($(date +%s) - start_time < 10)); do
		if curl -sf --max-time "$CURL_TIMEOUT" "http://${REGISTRY_HOST}/v2/" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	echo "ERROR: Registry not reachable on ${REGISTRY_HOST} after 10s" >&2
	return 1
}

stop_registry() {
	stop_process_from_pidfile "$REGISTRY_PID_FILE" "registry"
}

generate_signing_key() {
	timeout "$KUBECTL_TIMEOUT" "$COSIGN" generate-key-pair --output-key-prefix "${BATS_FILE_TMPDIR}/cosign"
}

push_test_image() {
	local tag="$1"
	local ref="${REGISTRY_HOST}/test/${tag}"
	local output
	if ! output=$(timeout "$CMD_TIMEOUT" "$CRANE" copy --platform linux/amd64 "$PAUSE_IMAGE" "$ref" --insecure 2>&1); then
		echo "ERROR: crane copy failed for $ref: $output" >&2
		return 1
	fi
	if ! output=$(timeout "$CMD_TIMEOUT" "$CRANE" mutate --label "nri-test=${tag}" "$ref" --insecure 2>&1); then
		echo "ERROR: crane mutate failed for $ref: $output" >&2
		return 1
	fi
	echo "$ref"
}

get_image_digest() {
	local ref="$1"
	local digest
	if ! digest=$(timeout "$CMD_TIMEOUT" "$CRANE" digest "$ref" --insecure 2>&1); then
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
		timeout "$KUBECTL_TIMEOUT" "$COSIGN" signing-config create >"$config_file"
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
	if ! output=$(timeout "$CMD_TIMEOUT" "$COSIGN" attest \
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

write_cyclonedx_vex_predicate() {
	local file="$1"
	local state="$2"
	local product_purl="$3"
	local vuln_id="${4:-CVE-2024-0001}"

	# Extract the image name from the PURL (e.g. "image-name" from
	# "pkg:oci/image-name@sha256:abc123...").
	local name
	name=$(echo "$product_purl" | sed 's|pkg:oci/||; s|@.*||')

	cat >"$file" <<-EOF
		{
		  "bomFormat": "CycloneDX",
		  "specVersion": "1.5",
		  "version": 1,
		  "components": [
		    {
		      "type": "container",
		      "name": "${name}",
		      "bom-ref": "comp-1",
		      "purl": "${product_purl}"
		    }
		  ],
		  "vulnerabilities": [
		    {
		      "id": "${vuln_id}",
		      "affects": [{"ref": "comp-1"}],
		      "analysis": {"state": "${state}"}
		    }
		  ]
		}
	EOF
}

# --- DaemonSet deployment helpers ---

DAEMONSET_MANIFEST="${BATS_FILE_TMPDIR}/daemonset.yaml"
DAEMONSET_NS="nri-supply-chain"
METRICS_PORTFORWARD_PID_FILE="${BATS_FILE_TMPDIR}/metrics-portforward.pid"
DAEMONSET_METRICS_PORT=9091

build_daemonset_image() {
	local image_ref="$1"
	local layer_dir
	layer_dir=$(mktemp -d)
	mkdir -p "${layer_dir}/usr/local/bin"
	cp "$BINARY" "${layer_dir}/usr/local/bin/nri-supply-chain"
	chmod 755 "${layer_dir}/usr/local/bin/nri-supply-chain"

	local layer_tar="${BATS_FILE_TMPDIR}/layer.tar"
	tar -cf "$layer_tar" -C "$layer_dir" usr

	local base_ref="${image_ref%:*}:base"
	timeout "$CMD_TIMEOUT" "$CRANE" pull gcr.io/distroless/static-debian12:latest "$BATS_FILE_TMPDIR/base.tar"
	timeout "$CMD_TIMEOUT" "$CRANE" push "$BATS_FILE_TMPDIR/base.tar" "$base_ref" --insecure
	timeout "$CMD_TIMEOUT" "$CRANE" append -b "$base_ref" -f "$layer_tar" -t "$image_ref" --insecure
	timeout "$CMD_TIMEOUT" "$CRANE" mutate "$image_ref" \
		--entrypoint "/usr/local/bin/nri-supply-chain" \
		--insecure

	rm -rf "$layer_dir" "$layer_tar"
}

deploy_daemonset() {
	local image_ref="$1"
	local src_manifest="${2:-deploy/kubernetes/daemonset.yaml}"

	cp "$src_manifest" "$DAEMONSET_MANIFEST"

	sed -i "s|ghcr.io/saschagrunert/nri-supply-chain:[^ ]*|${image_ref}|g" "$DAEMONSET_MANIFEST"

	# Remove security constraints so the plugin can access the
	# NRI socket owned by root and write its sigstore TUF cache.
	sed -i '/runAsNonRoot:/d' "$DAEMONSET_MANIFEST"
	sed -i '/runAsUser:/d' "$DAEMONSET_MANIFEST"
	sed -i '/runAsGroup:/d' "$DAEMONSET_MANIFEST"
	sed -i '/readOnlyRootFilesystem:/d' "$DAEMONSET_MANIFEST"

	# Enable debug logging for easier CI diagnosis.
	sed -i '/- \/etc\/nri-supply-chain\/config.toml$/a\            - --log-level\n            - debug' "$DAEMONSET_MANIFEST"

	# Use host networking so the plugin can reach the local insecure
	# registry on localhost and resolve image digests/referrers.
	sed -i '/serviceAccountName:/a\      hostNetwork: true\n      dnsPolicy: ClusterFirstWithHostNet' "$DAEMONSET_MANIFEST"

	# Exclude registry.k8s.io system images from verification so that
	# CreateContainer callbacks for coredns/kube-proxy etc. return
	# immediately and don't block past the ttrpc request timeout.
	sed -i 's|"gcr.io/distroless/\*"|"gcr.io/distroless/*", "registry.k8s.io/**"|' "$DAEMONSET_MANIFEST"

	# Remove the NetworkPolicy resource so the pod can reach the
	# local insecure registry without egress restrictions.
	awk '
		BEGIN { doc="" }
		/^---$/ {
			if (doc !~ /kind: NetworkPolicy/) printf "%s", doc
			doc = "---\n"
			next
		}
		{ doc = doc $0 "\n" }
		END { if (doc !~ /kind: NetworkPolicy/) printf "%s", doc }
	' "$DAEMONSET_MANIFEST" >"${DAEMONSET_MANIFEST}.tmp"
	mv "${DAEMONSET_MANIFEST}.tmp" "$DAEMONSET_MANIFEST"

	kubectl apply -f "$DAEMONSET_MANIFEST" --request-timeout="${KUBECTL_TIMEOUT}s"
}

wait_for_daemonset_ready() {
	local timeout="${1:-180}"
	local start_time
	start_time=$(date +%s)
	local stable=0
	while (($(date +%s) - start_time < timeout)); do
		local desired ready
		desired=$(kubectl get daemonset nri-supply-chain -n "$DAEMONSET_NS" \
			-o jsonpath='{.status.desiredNumberScheduled}' --request-timeout="${CURL_TIMEOUT}s" 2>/dev/null || echo "0")
		ready=$(kubectl get daemonset nri-supply-chain -n "$DAEMONSET_NS" \
			-o jsonpath='{.status.numberReady}' --request-timeout="${CURL_TIMEOUT}s" 2>/dev/null || echo "0")
		if [[ "$desired" -gt 0 && "$ready" -eq "$desired" ]]; then
			local pod
			pod=$(get_daemonset_pod_name 2>/dev/null || true)
			if [[ -n "$pod" ]]; then
				local container_ready
				container_ready=$(kubectl get pod "$pod" -n "$DAEMONSET_NS" \
					-o jsonpath='{.status.containerStatuses[0].ready}' --request-timeout="${CURL_TIMEOUT}s" 2>/dev/null || echo "false")
				if [[ "$container_ready" == "true" ]]; then
					stable=$((stable + 1))
					if [[ $stable -ge 3 ]]; then
						break
					fi
					sleep 2
					continue
				fi
			fi
		fi
		stable=0
		sleep 2
	done

	if [[ $stable -lt 3 ]]; then
		echo "ERROR: DaemonSet not ready after ${timeout}s (desired=${desired:-?}, ready=${ready:-?})" >&2
		kubectl describe daemonset nri-supply-chain -n "$DAEMONSET_NS" --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
		kubectl get pods -n "$DAEMONSET_NS" -o wide --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
		local pod
		pod=$(get_daemonset_pod_name 2>/dev/null || true)
		if [[ -n "$pod" ]]; then
			kubectl describe pod "$pod" -n "$DAEMONSET_NS" --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
			kubectl logs "$pod" -n "$DAEMONSET_NS" --tail=50 --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
			kubectl logs "$pod" -n "$DAEMONSET_NS" --previous --tail=50 --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
		fi
		return 1
	fi

	# Verify the container has been running for at least 15 seconds.
	# The container may briefly appear ready before an NRI connection
	# drop causes it to exit, so this catches that race.
	local pod
	pod=$(get_daemonset_pod_name)
	while (($(date +%s) - start_time < timeout)); do
		local started_at
		started_at=$(kubectl get pod "$pod" -n "$DAEMONSET_NS" \
			-o jsonpath='{.status.containerStatuses[0].state.running.startedAt}' --request-timeout="${CURL_TIMEOUT}s" 2>/dev/null || true)
		if [[ -n "$started_at" ]]; then
			local started_epoch now_epoch running_for
			started_epoch=$(date -d "$started_at" +%s 2>/dev/null || echo "0")
			now_epoch=$(date +%s)
			running_for=$((now_epoch - started_epoch))
			if [[ $running_for -ge 15 ]]; then
				return 0
			fi
		fi
		sleep 3
	done
	echo "ERROR: DaemonSet container not stable after ${timeout}s" >&2
	kubectl describe pod "$pod" -n "$DAEMONSET_NS" --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
	kubectl logs "$pod" -n "$DAEMONSET_NS" --tail=50 --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
	return 1
}

get_daemonset_pod_name() {
	kubectl get pods -n "$DAEMONSET_NS" \
		-l app.kubernetes.io/name=nri-supply-chain \
		-o jsonpath='{.items[0].metadata.name}' --request-timeout="${KUBECTL_TIMEOUT}s" 2>/dev/null
}

daemonset_log_contains() {
	local pattern="$1"
	local pod
	pod=$(get_daemonset_pod_name)
	kubectl logs "$pod" -n "$DAEMONSET_NS" --request-timeout="${KUBECTL_TIMEOUT}s" 2>/dev/null | grep -q "$pattern"
}

assert_daemonset_log_contains() {
	local pattern="$1"
	local timeout="${2:-30}"
	local start_time
	start_time=$(date +%s)
	while (($(date +%s) - start_time < timeout)); do
		if daemonset_log_contains "$pattern"; then
			return 0
		fi
		sleep 1
	done
	local pod
	pod=$(get_daemonset_pod_name 2>/dev/null || echo "unknown")
	echo "ASSERTION FAILED: DaemonSet pod log does not contain '$pattern' after ${timeout}s" >&2
	echo "=== DaemonSet pod log tail ===" >&2
	kubectl logs "$pod" -n "$DAEMONSET_NS" --tail=30 --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
	echo "=== End DaemonSet pod log ===" >&2
	return 1
}

start_metrics_portforward() {
	local pod
	pod=$(get_daemonset_pod_name)
	kubectl port-forward "pod/${pod}" -n "$DAEMONSET_NS" \
		"${DAEMONSET_METRICS_PORT}:9090" &
	echo $! >"$METRICS_PORTFORWARD_PID_FILE"
	local start_time
	start_time=$(date +%s)
	while (($(date +%s) - start_time < 60)); do
		if curl -sf --max-time "$CURL_TIMEOUT" "http://localhost:${DAEMONSET_METRICS_PORT}/healthz" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	echo "ERROR: port-forward not ready after 60s" >&2
	echo "=== Pod status ===" >&2
	kubectl get pod "$pod" -n "$DAEMONSET_NS" -o wide --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
	echo "=== Pod describe ===" >&2
	kubectl describe pod "$pod" -n "$DAEMONSET_NS" --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
	echo "=== Pod logs ===" >&2
	kubectl logs "$pod" -n "$DAEMONSET_NS" --tail=50 --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
	echo "=== Previous pod logs ===" >&2
	kubectl logs "$pod" -n "$DAEMONSET_NS" --previous --tail=50 --request-timeout="${KUBECTL_TIMEOUT}s" 2>&1 >&2 || true
	return 1
}

ensure_metrics_portforward() {
	if [[ -f "$METRICS_PORTFORWARD_PID_FILE" ]]; then
		local pid
		pid=$(cat "$METRICS_PORTFORWARD_PID_FILE")
		if kill -0 "$pid" 2>/dev/null; then
			if curl -sf --max-time "$CURL_TIMEOUT" "http://localhost:${DAEMONSET_METRICS_PORT}/healthz" >/dev/null 2>&1; then
				return 0
			fi
		fi
		stop_metrics_portforward
	fi
	start_metrics_portforward
}

stop_metrics_portforward() {
	stop_process_from_pidfile "$METRICS_PORTFORWARD_PID_FILE" "metrics-portforward"
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

write_spdx_sbom_predicate() {
	local file="$1"
	local pkg_name="$2"
	local license="$3"
	local purl="${4:-}"

	local ext_ref=""
	if [[ -n "$purl" ]]; then
		ext_ref=$(
			cat <<-EOFREF
				,
				      "externalRefs": [
				        {
				          "referenceCategory": "PACKAGE-MANAGER",
				          "referenceType": "purl",
				          "referenceLocator": "${purl}"
				        }
				      ]
			EOFREF
		)
	fi

	cat >"$file" <<-EOF
		{
		  "spdxVersion": "SPDX-2.3",
		  "dataLicense": "CC0-1.0",
		  "SPDXID": "SPDXRef-DOCUMENT",
		  "name": "test-sbom",
		  "packages": [
		    {
		      "name": "${pkg_name}",
		      "SPDXID": "SPDXRef-Package",
		      "licenseConcluded": "${license}",
		      "licenseDeclared": "${license}"${ext_ref}
		    }
		  ]
		}
	EOF
}

write_cyclonedx_sbom_predicate() {
	local file="$1"
	local comp_name="$2"
	local license="$3"
	local purl="${4:-}"

	local purl_field=""
	if [[ -n "$purl" ]]; then
		purl_field=",
		      \"purl\": \"${purl}\""
	fi

	cat >"$file" <<-EOF
		{
		  "bomFormat": "CycloneDX",
		  "specVersion": "1.5",
		  "version": 1,
		  "components": [
		    {
		      "type": "library",
		      "name": "${comp_name}",
		      "licenses": [{"license": {"id": "${license}"}}]${purl_field}
		    }
		  ]
		}
	EOF
}

write_cyclonedx_sbom_with_vulns_predicate() {
	local file="$1"
	local vuln_id="$2"
	local score="$3"
	local severity="$4"

	cat >"$file" <<-EOF
		{
		  "bomFormat": "CycloneDX",
		  "specVersion": "1.5",
		  "version": 1,
		  "components": [
		    {
		      "type": "library",
		      "name": "test-lib",
		      "licenses": [{"license": {"id": "MIT"}}]
		    }
		  ],
		  "vulnerabilities": [
		    {
		      "id": "${vuln_id}",
		      "ratings": [
		        {"score": ${score}, "severity": "${severity}", "method": "CVSSv31"}
		      ]
		    }
		  ]
		}
	EOF
}

create_sbom_images() {
	local pred_dir="${BATS_FILE_TMPDIR}/predicates"
	mkdir -p "$pred_dir"

	# Image with allowed license (MIT)
	SBOM_ALLOWED_IMAGE=$(push_test_image "sbom-allowed:v1")
	write_slsa_predicate "${pred_dir}/sbom-allowed-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$SBOM_ALLOWED_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/sbom-allowed-slsa.json"
	write_spdx_sbom_predicate "${pred_dir}/sbom-allowed.json" "test-pkg" "MIT"
	attest_image "$SBOM_ALLOWED_IMAGE" "https://spdx.dev/Document" "${pred_dir}/sbom-allowed.json"

	# Image with denied license (AGPL-3.0)
	SBOM_DENIED_LIC_IMAGE=$(push_test_image "sbom-denied-lic:v1")
	write_slsa_predicate "${pred_dir}/sbom-denied-lic-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$SBOM_DENIED_LIC_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/sbom-denied-lic-slsa.json"
	write_spdx_sbom_predicate "${pred_dir}/sbom-denied-lic.json" "bad-pkg" "AGPL-3.0"
	attest_image "$SBOM_DENIED_LIC_IMAGE" "https://spdx.dev/Document" "${pred_dir}/sbom-denied-lic.json"

	# Image with denied component (PURL)
	SBOM_DENIED_COMP_IMAGE=$(push_test_image "sbom-denied-comp:v1")
	write_slsa_predicate "${pred_dir}/sbom-denied-comp-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$SBOM_DENIED_COMP_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/sbom-denied-comp-slsa.json"
	write_spdx_sbom_predicate "${pred_dir}/sbom-denied-comp.json" "event-stream" "MIT" "pkg:npm/event-stream@3.3.6"
	attest_image "$SBOM_DENIED_COMP_IMAGE" "https://spdx.dev/Document" "${pred_dir}/sbom-denied-comp.json"

	# Image with no SBOM attestation (only SLSA)
	SBOM_MISSING_IMAGE=$(push_test_image "sbom-missing:v1")
	write_slsa_predicate "${pred_dir}/sbom-missing-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$SBOM_MISSING_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/sbom-missing-slsa.json"

	# CycloneDX image with denied license
	SBOM_CDX_DENIED_IMAGE=$(push_test_image "sbom-cdx-denied:v1")
	write_slsa_predicate "${pred_dir}/sbom-cdx-denied-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$SBOM_CDX_DENIED_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/sbom-cdx-denied-slsa.json"
	write_cyclonedx_sbom_predicate "${pred_dir}/sbom-cdx-denied.json" "bad-lib" "GPL-3.0"
	attest_image "$SBOM_CDX_DENIED_IMAGE" "https://cyclonedx.org/bom" "${pred_dir}/sbom-cdx-denied.json"

	# CycloneDX image with critical vulnerability (score 9.8)
	SBOM_CVSS_CRITICAL_IMAGE=$(push_test_image "sbom-cvss-critical:v1")
	write_slsa_predicate "${pred_dir}/sbom-cvss-critical-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$SBOM_CVSS_CRITICAL_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/sbom-cvss-critical-slsa.json"
	write_cyclonedx_sbom_with_vulns_predicate "${pred_dir}/sbom-cvss-critical.json" "CVE-2024-9999" "9.8" "critical"
	attest_image "$SBOM_CVSS_CRITICAL_IMAGE" "https://cyclonedx.org/bom" "${pred_dir}/sbom-cvss-critical.json"

	# CycloneDX image with low vulnerability (score 3.5)
	SBOM_CVSS_LOW_IMAGE=$(push_test_image "sbom-cvss-low:v1")
	write_slsa_predicate "${pred_dir}/sbom-cvss-low-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$SBOM_CVSS_LOW_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/sbom-cvss-low-slsa.json"
	write_cyclonedx_sbom_with_vulns_predicate "${pred_dir}/sbom-cvss-low.json" "CVE-2024-0001" "3.5" "low"
	attest_image "$SBOM_CVSS_LOW_IMAGE" "https://cyclonedx.org/bom" "${pred_dir}/sbom-cvss-low.json"

	export SBOM_ALLOWED_IMAGE SBOM_DENIED_LIC_IMAGE SBOM_DENIED_COMP_IMAGE
	export SBOM_MISSING_IMAGE SBOM_CDX_DENIED_IMAGE
	export SBOM_CVSS_CRITICAL_IMAGE SBOM_CVSS_LOW_IMAGE
}

# --- OCI policy helpers ---

write_plugin_config_oci() {
	local mode="${1:-warn}"
	local oci_ref="${2}"
	local poll_interval="${3:-1m}"
	cat >"$PLUGIN_CONFIG" <<-EOF
		verification = "${mode}"
		policy_dir = "${POLICY_DIR}"
		fetch_timeout = "30s"
		fetch_failure_policy = "deny"
		cache_ttl = "5m"
		metrics_addr = ":9090"

		[policy]
		source = "oci"
		oci_ref = "${oci_ref}"
		poll_interval = "${poll_interval}"
	EOF
}

push_policy_to_registry() {
	local tag="$1"
	shift
	local ref="${REGISTRY_HOST}/policies/${tag}"
	local layout_dir
	layout_dir=$(mktemp -d "${BATS_FILE_TMPDIR}/policy-layout-XXXXXX")

	local config='{"architecture":"amd64","os":"linux"}'
	local config_hash
	config_hash=$(printf '%s' "$config" | sha256sum | awk '{print $1}')
	local config_size=${#config}
	mkdir -p "${layout_dir}/blobs/sha256"
	printf '%s' "$config" >"${layout_dir}/blobs/sha256/${config_hash}"

	local layers_json=""
	local diff_ids=""
	for f in "$@"; do
		local content
		content=$(cat "$f")
		local blob_hash
		blob_hash=$(printf '%s' "$content" | sha256sum | awk '{print $1}')
		local blob_size=${#content}
		printf '%s' "$content" >"${layout_dir}/blobs/sha256/${blob_hash}"
		local fname
		fname=$(basename "$f")
		if [ -n "$layers_json" ]; then
			layers_json="${layers_json},"
			diff_ids="${diff_ids},"
		fi
		layers_json="${layers_json}{\"mediaType\":\"application/json\",\"size\":${blob_size},\"digest\":\"sha256:${blob_hash}\",\"annotations\":{\"org.opencontainers.image.title\":\"${fname}\"}}"
		diff_ids="${diff_ids}\"sha256:${blob_hash}\""
	done

	local manifest="{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"size\":${config_size},\"digest\":\"sha256:${config_hash}\"},\"layers\":[${layers_json}]}"
	local manifest_hash
	manifest_hash=$(printf '%s' "$manifest" | sha256sum | awk '{print $1}')
	local manifest_size=${#manifest}
	printf '%s' "$manifest" >"${layout_dir}/blobs/sha256/${manifest_hash}"

	printf '{"imageLayoutVersion":"1.0.0"}' >"${layout_dir}/oci-layout"
	printf '{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","size":%d,"digest":"sha256:%s"}]}' \
		"$manifest_size" "$manifest_hash" >"${layout_dir}/index.json"

	local output
	if ! output=$(timeout "$CMD_TIMEOUT" "$CRANE" push "${layout_dir}" "$ref" \
		--insecure --image-refs /dev/null 2>&1); then
		echo "ERROR: crane push failed for $ref: $output" >&2
		rm -rf "$layout_dir"
		return 1
	fi
	rm -rf "$layout_dir"
	echo "$ref"
}
