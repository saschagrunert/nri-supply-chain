#!/bin/sh
set -e
# Only stop and disable on full removal, not during upgrades.
# RPM passes $1=0 for removal, DEB passes $1=remove.
if [ "$1" = "0" ] || [ "$1" = "remove" ]; then
	systemctl stop nri-supply-chain
	systemctl disable nri-supply-chain
fi
