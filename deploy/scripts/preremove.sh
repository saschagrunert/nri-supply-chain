#!/bin/sh
set -e
# Only stop and disable on full removal, not during upgrades.
# RPM passes $1=0 for removal, DEB passes $1=remove.
if [ "$1" = "0" ] || [ "$1" = "remove" ]; then
	# Without a running systemd (image builds, chroots) there is nothing to
	# stop, and "systemctl stop" fails.
	if [ -d /run/systemd/system ]; then
		systemctl stop nri-supply-chain
	fi
	systemctl disable nri-supply-chain
fi
