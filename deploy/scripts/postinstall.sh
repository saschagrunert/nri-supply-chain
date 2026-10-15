#!/bin/sh
set -e
# RPM passes $1=1 on install and $1=2 on upgrade. DEB passes "configure" and
# the previously configured version in $2, which is empty on a fresh install.
# Only a fresh install enables the service, so that an upgrade keeps a service
# the administrator disabled disabled.
fresh_install=false
if [ "$1" = "1" ]; then
	fresh_install=true
elif [ "$1" = "configure" ] && [ -z "$2" ]; then
	fresh_install=true
fi

# "systemctl enable" works without a running systemd (for example in image
# builds or chroots), "systemctl daemon-reload" and "try-restart" fail there.
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload
	if [ "$fresh_install" = false ]; then
		# Restart a running service with the upgraded binary. A failed
		# restart must not fail the package upgrade.
		systemctl try-restart nri-supply-chain ||
			echo "warning: failed to restart nri-supply-chain" >&2
	fi
fi

if [ "$fresh_install" = true ]; then
	systemctl enable nri-supply-chain
fi
