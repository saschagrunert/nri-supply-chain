#!/usr/bin/env bats

# Verifies the Security Profiles Operator images promoted to registry.k8s.io
# with the shipped example policy, whose rule requires the image promoter's VSA
# signed as promoter-summaries@k8s-releng-prod.

load helpers

EXAMPLE_POLICY="deploy/examples/policies/registry-k8s-io.json"

# The promoted images are pinned by digest, so the tests don't change when the
# project releases again.
SPO_REPO="registry.k8s.io/security-profiles-operator"

# v1.1.1, the first release promoted under the provenance policy of the
# project. A digest gets the highest level of its provenances that pass the
# policy: level 3 for the container images, which have both the Cloud Build
# provenance (level 1) and the GitHub one (level 3), also in the repository of
# the manifest list, and level 1 for the OLM bundle, which only has the Cloud
# Build provenance.
SPO_V111_INDEX="${SPO_REPO}/security-profiles-operator@sha256:b110a24ae9d7dc22c1850b2b9598bd01a5047bd316d413066a9078691e844cef"
SPO_V111_AMD64_DIGEST="sha256:6777021cd97c6f5fb8493726770438057909b857e99778afc99964874ec21549"
SPO_V111_AMD64="${SPO_REPO}/security-profiles-operator-amd64@${SPO_V111_AMD64_DIGEST}"
SPO_V111_PLATFORM="${SPO_REPO}/security-profiles-operator@${SPO_V111_AMD64_DIGEST}"
SPO_V111_BUNDLE="${SPO_REPO}/security-profiles-operator-bundle@sha256:0b2ef455d3579ee0b72a6a2cfcaefcd10418bbb163ba58e5145b4c03359d36ab"

# v1.1.0: its provenance names a builder the policy doesn't trust, so the
# promoter's VSAs of its digests failed.
SPO_V110_INDEX="${SPO_REPO}/security-profiles-operator@sha256:beb927d0d1bd784857a457bb78e889341ebef2a33bbfb393d99e9dd1cb48dc82"
SPO_V110_AMD64="${SPO_REPO}/security-profiles-operator-amd64@sha256:b37ce90ac569d54c0a17a757ca9ec94423c7a16a34ecfb111bf9546f331ad1f4"

# verify_promoted_image verifies an image with the example policy in enforce
# mode.
verify_promoted_image() {
	mkdir -p "$TEST_DIR/policies"
	cp "$EXAMPLE_POLICY" "$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" verify "$1" --output json
	echo "# verify output: $output" >&2
}

# extract_docs_rule prints the example rule of docs/policy.md.
extract_docs_rule() {
	sed -n '/<!-- registry-k8s-io-spo-rule -->/,/<!-- \/registry-k8s-io-spo-rule -->/p' docs/policy.md |
		sed -n "/^\`\`\`json$/,/^\`\`\`$/p" |
		sed '1d;$d'
}

@test "docs show the rule of the registry.k8s.io example policy" {
	local docs example
	docs=$(extract_docs_rule | jq -S '.rules[0]')
	example=$(jq -S '.rules[] | select(.images == ["registry.k8s.io/security-profiles-operator/**"])' "$EXAMPLE_POLICY")
	[[ -n "$docs" ]]
	[[ "$docs" == "$example" ]]
}

@test "SPO v1.1.1 multi-arch image passes at SLSA build level 3" {
	skip_if_network_unavailable
	verify_promoted_image "$SPO_V111_INDEX"
	[[ "$status" -eq 0 ]]
	[[ "$output" == *'"allowed": true'* ]]
	[[ "$output" == *'"detail": "VSA verification passed"'* ]]
	[[ "$output" == *'"level": 3'* ]]
}

@test "SPO v1.1.1 platform image of the multi-arch repository passes at SLSA build level 3" {
	skip_if_network_unavailable
	verify_promoted_image "$SPO_V111_PLATFORM"
	[[ "$status" -eq 0 ]]
	[[ "$output" == *'"allowed": true'* ]]
	[[ "$output" == *'"detail": "VSA verification passed"'* ]]
	[[ "$output" == *'"level": 3'* ]]
}

@test "SPO v1.1.1 per-arch image passes at SLSA build level 3" {
	skip_if_network_unavailable
	verify_promoted_image "$SPO_V111_AMD64"
	[[ "$status" -eq 0 ]]
	[[ "$output" == *'"allowed": true'* ]]
	[[ "$output" == *'"detail": "VSA verification passed"'* ]]
	[[ "$output" == *'"level": 3'* ]]
}

@test "SPO v1.1.1 bundle passes at SLSA build level 1" {
	skip_if_network_unavailable
	verify_promoted_image "$SPO_V111_BUNDLE"
	[[ "$status" -eq 0 ]]
	[[ "$output" == *'"allowed": true'* ]]
	[[ "$output" == *'"detail": "VSA verification passed"'* ]]
	[[ "$output" == *'"level": 1'* ]]
}

@test "SPO v1.1.0 multi-arch image is denied with a failed promoter VSA" {
	skip_if_network_unavailable
	verify_promoted_image "$SPO_V110_INDEX"
	[[ "$status" -eq 1 ]]
	[[ "$output" == *'"allowed": false'* ]]
	[[ "$output" == *'"detail": "trusted verifier reported FAILED verification"'* ]]
}

@test "SPO v1.1.0 per-arch image is denied with a failed promoter VSA" {
	skip_if_network_unavailable
	verify_promoted_image "$SPO_V110_AMD64"
	[[ "$status" -eq 1 ]]
	[[ "$output" == *'"allowed": false'* ]]
	[[ "$output" == *'"detail": "trusted verifier reported FAILED verification"'* ]]
}
