#!/usr/bin/env bats

load helpers

extract_quickstart_policy() {
	local marker="$1"
	sed -n "/<!-- ${marker} -->/,/<!-- \/${marker} -->/p" README.md |
		sed -n "/^   \`\`\`json$/,/^   \`\`\`$/p" |
		sed '1d;$d' |
		sed 's/^   //'
}

@test "quickstart verification without VSA succeeds" {
	skip_if_network_unavailable
	skip_if_image_unavailable "$QUICKSTART_IMAGE"
	mkdir -p "$TEST_DIR/policies"
	extract_quickstart_policy "quickstart-policy-basic" \
		>"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" --verify-image "$QUICKSTART_IMAGE"
	[[ "$status" -eq 0 ]]
	[[ "$output" == *'"allowed": true'* ]]
	[[ "$output" == *'"type": "slsa"'* ]]
	[[ "$output" == *'"passed": true'* ]]
	[[ "$output" == *'"detail": "SLSA provenance verified"'* ]]
	[[ "$output" == *'"type": "vex"'* ]]
	[[ "$output" == *'"detail": "VEX verification passed"'* ]]
}

@test "quickstart verification with VSA succeeds" {
	skip_if_network_unavailable
	skip_if_image_unavailable "$QUICKSTART_IMAGE"
	mkdir -p "$TEST_DIR/policies"
	extract_quickstart_policy "quickstart-policy-vsa" \
		>"$TEST_DIR/policies/default.json"
	cat >"$TEST_DIR/config.toml" <<EOF
verification = "enforce"
policy_dir = "$TEST_DIR/policies"
EOF
	run_binary --config "$TEST_DIR/config.toml" --verify-image "$QUICKSTART_IMAGE"
	[[ "$status" -eq 0 ]]
	[[ "$output" == *'"allowed": true'* ]]
	[[ "$output" == *'"type": "vsa"'* ]]
	[[ "$output" == *'"passed": true'* ]]
	[[ "$output" == *'"detail": "VSA verification passed"'* ]]
	[[ "$output" == *'"reason": "VSA verification passed, skipping direct verification"'* ]]
	[[ "$output" != *'"type": "slsa"'* ]]
}
