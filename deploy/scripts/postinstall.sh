#!/bin/sh
set -e
systemctl daemon-reload
systemctl enable nri-supply-chain
