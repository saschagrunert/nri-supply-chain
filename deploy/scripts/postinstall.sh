#!/bin/sh
set -e
# "systemctl enable" works without a running systemd (for example in image
# builds or chroots), "systemctl daemon-reload" fails there.
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload
fi
systemctl enable nri-supply-chain
