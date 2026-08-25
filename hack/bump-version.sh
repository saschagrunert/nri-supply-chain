#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <new-version>" >&2
	echo "Example: $0 X.Y.Z" >&2
	exit 1
fi

NEW_VERSION="$1"
NEW_VERSION="${NEW_VERSION#v}"

if [[ ! "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "Error: version must be in semver format (e.g. 0.5.0)" >&2
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Extract current version from dependencies.yaml.
OLD_VERSION=$(sed -n '/^  - name: nri-supply-chain$/{n;s/.*version: //p;}' \
	"$ROOT_DIR/dependencies.yaml" | tr -d '[:space:]')

if [[ -z "$OLD_VERSION" ]]; then
	echo "Error: could not determine current version from dependencies.yaml" >&2
	exit 1
fi

if [[ "$OLD_VERSION" == "$NEW_VERSION" ]]; then
	echo "Already at version $NEW_VERSION" >&2
	exit 0
fi

echo "Bumping version: $OLD_VERSION -> $NEW_VERSION"

OLD_ESCAPED="${OLD_VERSION//./\\.}"

# Go source (uses v prefix).
sed -i "s/var version = \"v${OLD_ESCAPED}\"/var version = \"v${NEW_VERSION}\"/" \
	"$ROOT_DIR/cmd/nri-supply-chain/main.go"

# dependencies.yaml (nri-supply-chain entry only).
sed -i "/^  - name: nri-supply-chain$/{n;s/version: ${OLD_ESCAPED}/version: ${NEW_VERSION}/;}" \
	"$ROOT_DIR/dependencies.yaml"

# Helm chart.
sed -i \
	-e "s/^version: ${OLD_ESCAPED}/version: ${NEW_VERSION}/" \
	-e "s/^appVersion: \"${OLD_ESCAPED}\"/appVersion: \"${NEW_VERSION}\"/" \
	"$ROOT_DIR/deploy/helm/nri-supply-chain/Chart.yaml"

# Kubernetes manifests.
sed -i "s|nri-supply-chain:${OLD_ESCAPED}|nri-supply-chain:${NEW_VERSION}|g" \
	"$ROOT_DIR/deploy/kubernetes/daemonset.yaml"

# README examples.
sed -i "s|nri-supply-chain:${OLD_ESCAPED}|nri-supply-chain:${NEW_VERSION}|g" \
	"$ROOT_DIR/README.md"

# Benchmark tests (uses v prefix).
sed -i "s|nri-supply-chain:v${OLD_ESCAPED}|nri-supply-chain:v${NEW_VERSION}|g" \
	"$ROOT_DIR/internal/registry/registry_bench_test.go"

echo "Done. Verify with: make verify-dependencies"
