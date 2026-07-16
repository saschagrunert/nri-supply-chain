#!/usr/bin/env bats

load helpers

@test "version flag prints version" {
	run_binary --version
	[[ "$status" -eq 0 ]]
	[[ "$output" == *"nri-supply-chain v"* ]]
}

@test "help flag shows usage" {
	run_binary --help
	[[ "$status" -eq 0 ]]
	[[ "$output" == *"Usage"* ]]
}
