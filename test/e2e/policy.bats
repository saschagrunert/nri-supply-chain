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
	configure_insecure_registry

	start_kubernix

	wait_for_node_ready
	write_nri_dropin
	reload_runtime

	POLICY_IMAGE=$(push_test_image "policy-test:v1")
	export POLICY_IMAGE

	write_plugin_config "enforce"
	start_plugin
}

teardown_file() {
	stop_plugin
	stop_registry
	unconfigure_insecure_registry
	stop_kubernix
}

@test "default policy applies to unlabeled namespace" {
	run_pod "default-policy-pod" "$POLICY_IMAGE" || true
	assert_log_contains "Container rejected"
}

@test "namespace-specific policy overrides default" {
	local ns="production"
	register_namespace "$ns"
	wait_for_service_account "$ns"

	write_policy "$ns" '{
		"slsa": {"missingPolicy": "allow"},
		"vex": {"missingPolicy": "allow"}
	}'
	reload_plugin

	kubectl run "ns-override-pod" \
		--namespace "$ns" \
		--image "$POLICY_IMAGE" \
		--restart=Never
	wait_for_pod_status "ns-override-pod" "Running" 60 "$ns"
}

@test "excluded image pattern skips verification" {
	write_policy "default" '{
		"exclude": ["localhost:5050/test/policy-test:*"],
		"slsa": {"missingPolicy": "deny"}
	}'
	reload_plugin

	run_pod "excluded-pod" "$POLICY_IMAGE"
	wait_for_pod_status "excluded-pod" "Running"
	assert_log_contains "image is excluded"

	write_policy "default" '{
		"trust": {
			"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 3}]
		},
		"slsa": {"missingPolicy": "deny"},
		"vex": {"missingPolicy": "allow"}
	}'
	reload_plugin
}

@test "exclude pattern with wildcard matches broadly" {
	write_policy "default" '{
		"exclude": ["localhost:5050/test/*"],
		"slsa": {"missingPolicy": "deny"}
	}'
	reload_plugin

	run_pod "wildcard-pod" "$POLICY_IMAGE"
	wait_for_pod_status "wildcard-pod" "Running"
	assert_log_contains "image is excluded"

	write_policy "default" '{
		"trust": {
			"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 3}]
		},
		"slsa": {"missingPolicy": "deny"},
		"vex": {"missingPolicy": "allow"}
	}'
	reload_plugin
}

@test "missing namespace policy falls back to default" {
	local ns="nonexistent-policy-ns"
	register_namespace "$ns"
	wait_for_service_account "$ns"

	kubectl run "fallback-pod" \
		--namespace "$ns" \
		--image "$POLICY_IMAGE" \
		--restart=Never || true
	assert_log_contains "Container rejected"
}

@test "empty policy allows pod" {
	write_policy "default" '{}'
	reload_plugin

	run_pod "empty-policy-pod" "$POLICY_IMAGE"
	wait_for_pod_status "empty-policy-pod" "Running"

	write_policy "default" '{
		"trust": {
			"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 3}]
		},
		"slsa": {"missingPolicy": "deny"},
		"vex": {"missingPolicy": "allow"}
	}'
	reload_plugin
}

@test "slsa missingPolicy deny rejects unsigned images" {
	write_policy "default" '{
		"slsa": {"missingPolicy": "deny"}
	}'
	reload_plugin

	run_pod "prov-deny-pod" "$POLICY_IMAGE" || true
	assert_log_contains "Container rejected"

	write_policy "default" '{
		"trust": {
			"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 3}]
		},
		"slsa": {"missingPolicy": "deny"},
		"vex": {"missingPolicy": "allow"}
	}'
	reload_plugin
}

@test "slsa missingPolicy allow passes unsigned images" {
	write_policy "default" '{
		"slsa": {"missingPolicy": "allow"}
	}'
	reload_plugin

	run_pod "prov-allow-pod" "$POLICY_IMAGE"
	wait_for_pod_status "prov-allow-pod" "Running"

	write_policy "default" '{
		"trust": {
			"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 3}]
		},
		"slsa": {"missingPolicy": "deny"},
		"vex": {"missingPolicy": "allow"}
	}'
	reload_plugin
}

@test "vex missingPolicy deny rejects images without VEX" {
	write_policy "default" '{
		"slsa": {"missingPolicy": "allow"},
		"vex": {"missingPolicy": "deny"}
	}'
	reload_plugin

	run_pod "vex-deny-pod" "$POLICY_IMAGE" || true
	assert_log_contains "Container rejected"

	write_policy "default" '{
		"trust": {
			"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 3}]
		},
		"slsa": {"missingPolicy": "deny"},
		"vex": {"missingPolicy": "allow"}
	}'
	reload_plugin
}

@test "vex missingPolicy warn logs warning for missing VEX but allows" {
	write_policy "default" '{
		"slsa": {"missingPolicy": "allow"},
		"vex": {"missingPolicy": "warn"}
	}'
	reload_plugin

	run_pod "vex-warn-pod" "$POLICY_IMAGE"
	wait_for_pod_status "vex-warn-pod" "Running"
	assert_log_contains "Supply chain audit"

	write_policy "default" '{
		"trust": {
			"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 3}]
		},
		"slsa": {"missingPolicy": "deny"},
		"vex": {"missingPolicy": "allow"}
	}'
	reload_plugin
}

@test "namespace policy with inherits merges with default" {
	local ns="inherit-ns"
	register_namespace "$ns"
	wait_for_service_account "$ns"

	write_policy "$ns" '{
		"inherits": true,
		"slsa": {"missingPolicy": "allow"}
	}'
	reload_plugin

	kubectl run "inherit-pod" \
		--namespace "$ns" \
		--image "$POLICY_IMAGE" \
		--restart=Never
	wait_for_pod_status "inherit-pod" "Running" 60 "$ns"

	# Default policy still denies in the default namespace.
	run_pod "inherit-default-pod" "$POLICY_IMAGE" || true
	assert_log_contains "Container rejected"
}
