#!/usr/bin/env bash

BINARY="${BINARY:-build/nri-supply-chain}"
QUICKSTART_IMAGE=$(grep -o -- '--verify-image [^ ]*' README.md | head -1 | awk '{print $2}')
export QUICKSTART_IMAGE

setup() {
	export TEST_DIR
	TEST_DIR=$(mktemp -d)
}

teardown() {
	rm -rf "$TEST_DIR"
}

run_binary() {
	run "$BINARY" "$@"
}

skip_if_network_unavailable() {
	if [[ -n "${SKIP_NETWORK_TESTS:-}" ]]; then
		skip "SKIP_NETWORK_TESTS is set"
	fi
}
