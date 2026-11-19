#!/usr/bin/env bash

BINARY="${BINARY:-build/nri-supply-chain}"
QUICKSTART_IMAGE=$(grep -oE 'verify [^ ]+/[^ ]+:[^ ]+' README.md | head -1 | awk '{print $2}')
export QUICKSTART_IMAGE

setup() {
	export TEST_DIR
	TEST_DIR=$(mktemp -d)

	# Tests run in parallel, and sigstore-go caches the TUF metadata in
	# $HOME/.sigstore, where concurrent updates of the same file fail with
	# "failed to persist metadata". Give every test its own cache but keep
	# the registry credentials.
	export DOCKER_CONFIG="${DOCKER_CONFIG:-$HOME/.docker}"
	export HOME="$TEST_DIR"
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

skip_if_image_unavailable() {
	local image="$1"
	if ! docker manifest inspect "$image" &>/dev/null; then
		skip "image $image not available"
	fi
}
