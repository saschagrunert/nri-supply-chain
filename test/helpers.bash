#!/usr/bin/env bash

BINARY="${BINARY:-build/nri-supply-chain}"

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
