#!/usr/bin/env bats

load helpers

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	start_registry
	generate_signing_key
	configure_insecure_registry

	start_kubernix

	wait_for_node_ready

	write_nri_dropin
	reload_runtime

	create_cosign_tag_images

	restore_default_keybased_policy
	write_plugin_config "enforce"
	start_plugin
}

teardown_file() {
	stop_plugin
	stop_registry
	unconfigure_insecure_registry
	stop_kubernix
}

restore_default_keybased_policy() {
	write_policy "default" "$(
		cat <<-EOF
			{
			  "trust": {
			    "verifiers": [{"id": "test-verifier", "key": "${COSIGN_PUB}"}]
			  },
			  "provenance": {"missingPolicy": "allow"},
			  "vex": {"missingPolicy": "allow"},
			  "signatures": {"requireTransparencyLog": false}
			}
		EOF
	)"
}

create_cosign_tag_images() {
	local pred_dir="${BATS_FILE_TMPDIR}/predicates"
	mkdir -p "$pred_dir"

	# Image with cosign tag attestation only (no OCI referrers)
	COSIGN_TAG_ONLY_IMAGE=$(push_test_image "cosign-tag-only:v1")

	write_slsa_predicate "${pred_dir}/cosign-tag-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""

	# Attest via OCI referrers first
	attest_image "$COSIGN_TAG_ONLY_IMAGE" \
		"https://slsa.dev/provenance/v1" \
		"${pred_dir}/cosign-tag-slsa.json"

	# Copy the bundle to a .att tag, then remove the OCI referrer
	move_referrer_to_att_tag "$COSIGN_TAG_ONLY_IMAGE"

	# Image with both OCI referrer and cosign tag
	COSIGN_TAG_BOTH_IMAGE=$(push_test_image "cosign-tag-both:v1")

	write_slsa_predicate "${pred_dir}/cosign-both-slsa.json" \
		"https://test-builder.example.com" \
		"https://github.com/testorg/repo" \
		""

	attest_image "$COSIGN_TAG_BOTH_IMAGE" \
		"https://slsa.dev/provenance/v1" \
		"${pred_dir}/cosign-both-slsa.json"

	# Also push to .att tag (keep the OCI referrer)
	copy_referrer_to_att_tag "$COSIGN_TAG_BOTH_IMAGE"

	# Image with no attestation at all
	COSIGN_TAG_NONE_IMAGE=$(push_test_image "cosign-tag-none:v1")

	export COSIGN_TAG_ONLY_IMAGE COSIGN_TAG_BOTH_IMAGE COSIGN_TAG_NONE_IMAGE
}

# Extract the bundle from OCI referrers and push it to the .att tag,
# then delete the referrer so only the .att tag remains.
move_referrer_to_att_tag() {
	copy_referrer_to_att_tag "$1"
	delete_oci_referrer "$1"
}

# Copy the bundle from OCI referrers to the .att tag.
# Uses the OCI tag fallback index (sha256-<hex> tag) since crane registry
# does not support the OCI Referrers API endpoint.
copy_referrer_to_att_tag() {
	local ref="$1"
	local digest
	digest=$("$CRANE" digest "$ref" --insecure)
	local att_tag="${digest//:/-}.att"
	local repo="${ref%:*}"
	local api_repo="${repo#*/}"

	# Get the referrer index via OCI tag fallback
	local oci_fallback_tag="${digest//:/-}"
	local referrers_json
	referrers_json=$(curl -sf \
		"http://${REGISTRY_HOST}/v2/${api_repo}/manifests/${oci_fallback_tag}" \
		-H "Accept: application/vnd.oci.image.index.v1+json")

	local bundle_digest
	bundle_digest=$(echo "$referrers_json" | jq -r '.manifests[0].digest')

	# Get the bundle image manifest
	local bundle_manifest
	bundle_manifest=$(curl -sf \
		"http://${REGISTRY_HOST}/v2/${api_repo}/manifests/${bundle_digest}" \
		-H "Accept: application/vnd.oci.image.manifest.v1+json")

	# Get the layer digest and config digest
	local layer_digest layer_size config_digest config_size
	layer_digest=$(echo "$bundle_manifest" | jq -r '.layers[0].digest')
	layer_size=$(echo "$bundle_manifest" | jq -r '.layers[0].size')
	config_digest=$(echo "$bundle_manifest" | jq -r '.config.digest')
	config_size=$(echo "$bundle_manifest" | jq -r '.config.size')

	# Build the .att tag manifest (reuses existing blobs)
	local att_manifest
	att_manifest=$(jq -n \
		--arg cd "$config_digest" \
		--argjson cs "$config_size" \
		--arg ld "$layer_digest" \
		--argjson ls "$layer_size" \
		'{
			schemaVersion: 2,
			mediaType: "application/vnd.oci.image.manifest.v1+json",
			config: {
				mediaType: "application/vnd.oci.image.config.v1+json",
				size: $cs,
				digest: $cd
			},
			layers: [{
				mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
				size: $ls,
				digest: $ld
			}]
		}')

	curl -sf -X PUT \
		"http://${REGISTRY_HOST}/v2/${api_repo}/manifests/${att_tag}" \
		-H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
		-d "$att_manifest" >/dev/null
}

# Delete OCI referrers by removing the tag fallback index and the
# attestation manifest it points to.
delete_oci_referrer() {
	local ref="$1"
	local digest
	digest=$("$CRANE" digest "$ref" --insecure)
	local repo="${ref%:*}"
	local api_repo="${repo#*/}"

	local oci_fallback_tag="${digest//:/-}"
	local referrers_json
	referrers_json=$(curl -sf \
		"http://${REGISTRY_HOST}/v2/${api_repo}/manifests/${oci_fallback_tag}" \
		-H "Accept: application/vnd.oci.image.index.v1+json")

	local bundle_digest
	bundle_digest=$(echo "$referrers_json" | jq -r '.manifests[0].digest')

	# Delete the attestation manifest
	curl -sf -X DELETE \
		"http://${REGISTRY_HOST}/v2/${api_repo}/manifests/${bundle_digest}" \
		>/dev/null 2>&1 || true

	# Delete the tag fallback index so remote.Referrers returns empty
	curl -sf -X DELETE \
		"http://${REGISTRY_HOST}/v2/${api_repo}/manifests/${oci_fallback_tag}" \
		>/dev/null 2>&1 || true
}

@test "cosign tag attestation allows pod in enforce mode" {
	run_pod "cosign-tag" "$COSIGN_TAG_ONLY_IMAGE"
	wait_for_pod_status "cosign-tag" "Running"
	assert_log_contains "cosign tag scheme"
}

@test "OCI referrers preferred over cosign tag" {
	run_pod "cosign-both" "$COSIGN_TAG_BOTH_IMAGE"
	wait_for_pod_status "cosign-both" "Running"
	run ! plugin_log_contains "cosign tag.*cosign-tag-both"
}

@test "image without any attestation is rejected" {
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

	run_pod "cosign-none" "$COSIGN_TAG_NONE_IMAGE" || true
	assert_log_contains "Container rejected"

	restore_default_keybased_policy
}
