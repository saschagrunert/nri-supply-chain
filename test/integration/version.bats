#!/usr/bin/env bats

load helpers

@test "version subcommand prints version" {
	run_binary version
	[[ "$status" -eq 0 ]]
	[[ "$output" == *"nri-supply-chain "* ]]
}

@test "help flag shows usage" {
	run_binary --help
	[[ "$status" -eq 0 ]]
	[[ "$output" == *"Usage"* ]]
}
