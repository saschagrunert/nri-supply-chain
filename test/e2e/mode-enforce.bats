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
		  "slsa": {"missingPolicy": "deny"},
		  "vex": {"missingPolicy": "allow"}
		}
	EOF

	start_registry
	generate_signing_key
	configure_insecure_registry

	start_kubernix

	wait_for_node_ready
	write_nri_dropin
	reload_runtime

	create_enforce_images

	write_plugin_config "enforce"
	start_plugin
}

teardown_file() {
	stop_plugin
	stop_registry
	unconfigure_insecure_registry
	stop_kubernix
}

create_enforce_images() {
	local pred_dir="${BATS_FILE_TMPDIR}/predicates"
	mkdir -p "$pred_dir"

	ATTESTED_IMAGE=$(push_test_image "enforce-attested:v1")
	write_slsa_predicate "${pred_dir}/enforce-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""
	attest_image "$ATTESTED_IMAGE" "https://slsa.dev/provenance/v1" "${pred_dir}/enforce-slsa.json"

	export ATTESTED_IMAGE
}

@test "pod with signed and attested image from trusted builder is admitted" {
	stop_plugin
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "builders": [{"id": "https://test-builder.example.com", "maxLevel": 3}],
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "slsa": {"missingPolicy": "deny"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
	write_plugin_config "enforce"
	start_plugin

	run_pod "attested-pod" "$ATTESTED_IMAGE"
	wait_for_pod_status "attested-pod" "Running"
	assert_log_contains "Container verified"

	stop_plugin
	write_policy "default" '{
		"trust": {
			"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 3}]
		},
		"slsa": {"missingPolicy": "deny"},
		"vex": {"missingPolicy": "allow"}
	}'
	write_plugin_config "enforce"
	start_plugin
}

@test "pod with unsigned image is rejected in enforce mode" {
	run_pod "rejected-pod" "registry.k8s.io/pause:3.10" || true
	assert_log_contains "Container rejected"
	wait_for_pod_status "rejected-pod" "CreateContainerError"
}

@test "rejected container is logged" {
	run_pod "logged-reject-pod" "registry.k8s.io/pause:3.10" || true
	assert_log_contains "Container rejected"
}

@test "multiple pods rejected in sequence without state leaks" {
	run_pod "seq-reject-1" "registry.k8s.io/pause:3.10" || true
	assert_pod_verdict "seq-reject-1" "rejected"
	run_pod "seq-reject-2" "registry.k8s.io/pause:3.10" || true
	assert_pod_verdict "seq-reject-2" "rejected"

	local count
	count=$(tail -c +"$((LOG_OFFSET + 1))" "$PLUGIN_LOG" | grep -c "Container rejected" || true)
	[[ "$count" -ge 2 ]]
}

@test "rejection event surfaces in kubectl describe pod" {
	run_pod "event-reject" "registry.k8s.io/pause:3.10" || true

	local found=false elapsed=0
	while [[ $elapsed -lt 30 ]]; do
		if kubectl get events -n "$TEST_NS" -o jsonpath='{.items[*].message}' 2>/dev/null | grep -q "supply chain"; then
			found=true
			break
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	if [[ "$found" != "true" ]]; then
		echo "ASSERTION FAILED: no supply chain event after 30s" >&2
		kubectl get events -n "$TEST_NS" >&2 || true
	fi
	[[ "$found" == "true" ]]
}

@test "ephemeral container via kubectl debug is verified" {
	run_pod "debug-target" "registry.k8s.io/pause:3.10" || true

	kubectl debug "debug-target" -n "$TEST_NS" \
		--image "registry.k8s.io/pause:3.10" \
		--target "debug-target" -- true 2>/dev/null || true

	assert_log_contains "Container rejected"
}

@test "concurrent pod creation is handled without races" {
	for i in $(seq 1 3); do
		run_pod "concurrent-$i" "registry.k8s.io/pause:3.10" &
	done
	wait

	local count=0 elapsed=0
	while [[ $elapsed -lt 30 ]]; do
		count=$(tail -c +"$((LOG_OFFSET + 1))" "$PLUGIN_LOG" | grep -c "Container rejected" || true)
		if [[ "$count" -ge 3 ]]; then
			break
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	[[ "$count" -ge 3 ]]
}
