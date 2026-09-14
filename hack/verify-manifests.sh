#!/usr/bin/env bash
# Validates the raw Kubernetes manifests and the rendered Helm chart:
#   - schema validation with kubeconform (including Prometheus Operator CRDs)
#   - the embedded config.toml and policies pass "nri-supply-chain validate"
#   - config.extraConfig top-level keys render before any TOML table
#   - the raw manifest and the Helm chart do not drift apart in the default
#     policy, shared config values, and security-relevant pod settings
set -euo pipefail

BINARY="${BINARY:-build/nri-supply-chain}"
HELM="${HELM:-build/helm}"
KUBECONFORM="${KUBECONFORM:-build/kubeconform}"
CHART="deploy/helm/nri-supply-chain"
RAW_MANIFESTS=(deploy/kubernetes/daemonset.yaml deploy/kubernetes/monitoring.yaml)
CRD_SCHEMA_LOCATION='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

render_chart() {
	local out="$1"
	shift
	"$HELM" template nri-supply-chain "$CHART" \
		--namespace nri-supply-chain \
		--set namespace.create=true \
		"$@" >"$out"
}

# split_documents writes each YAML document of $1 into directory $2.
split_documents() {
	mkdir -p "$2"
	awk -v dir="$2" '
		BEGIN { n = 0; file = dir "/doc-0.yaml" }
		/^---/ { n++; file = dir "/doc-" n ".yaml"; next }
		{ print > file }
	' "$1"
}

# configmap_document prints the path of the ConfigMap document named $2 in
# the split document directory $1.
configmap_document() {
	local doc
	for doc in "$1"/doc-*.yaml; do
		if grep -q '^kind: ConfigMap$' "$doc" && grep -q "^  name: $2\$" "$doc"; then
			echo "$doc"
			return 0
		fi
	done
	return 1
}

# extract_key prints the literal block scalar stored under data key $2 in the
# ConfigMap document $1.
extract_key() {
	awk -v key="$2" '
		$0 == "  " key ": |" || $0 == "  " key ": |-" { inblock = 1; next }
		inblock && /^    / { sub(/^    /, ""); print; next }
		inblock && /^[[:space:]]*$/ { print ""; next }
		inblock { exit }
	' "$1"
}

# extract_configmap writes config.toml and all *.json policies of the
# ConfigMap named $3 in manifest $1 into directory $2, pointing policy_dir at
# the extracted policies.
extract_configmap() {
	local manifest="$1" out="$2" name="$3" doc key
	split_documents "$manifest" "$out/docs"
	doc=$(configmap_document "$out/docs" "$name") ||
		fail "ConfigMap $name not found in $manifest"

	mkdir -p "$out/policies"
	extract_key "$doc" config.toml >"$out/config.toml"
	[[ -s "$out/config.toml" ]] || fail "config.toml missing in ConfigMap $name ($manifest)"

	while read -r key; do
		extract_key "$doc" "$key" >"$out/policies/$key"
	done < <(sed -n 's/^  \([A-Za-z0-9._-]*\.json\): |-\{0,1\}$/\1/p' "$doc")

	[[ -s "$out/policies/default.json" ]] || fail "default.json missing in ConfigMap $name ($manifest)"

	sed -i.bak "s|^policy_dir = .*|policy_dir = \"$out/policies\"|" "$out/config.toml"
	rm -f "$out/config.toml.bak"
}

validate_config() {
	local dir="$1" label="$2"
	echo "Validating $label config and policies"
	if ! "$BINARY" --config "$dir/config.toml" validate; then
		fail "$label config or policies failed validation"
	fi
}

echo "Rendering Helm chart"
render_chart "$TMP_DIR/helm.yaml" \
	--set monitoring.serviceMonitor.enabled=true \
	--set monitoring.prometheusRule.enabled=true \
	--set monitoring.grafana.enabled=true

render_chart "$TMP_DIR/helm-hostnetwork-off.yaml" \
	--set daemonSet.hostNetwork=false \
	--set daemonSet.dnsPolicy=ClusterFirst

render_chart "$TMP_DIR/helm-extra-config.yaml" \
	--set-string 'config.extraConfig=audit_log = "/var/log/nri-supply-chain/audit.json"'

render_chart "$TMP_DIR/helm-no-policies.yaml" \
	--set policies=null \
	--set config.policy.source=oci \
	--set config.policy.ociRef=registry.example/policies:v1

render_chart "$TMP_DIR/helm-restart-on-change.yaml" \
	--set daemonSet.restartOnConfigChange=true

TEST_DIGEST="sha256:$(printf '%064d' 0)"
render_chart "$TMP_DIR/helm-digest.yaml" --set "image.digest=$TEST_DIGEST"
grep -qF "image: \"ghcr.io/saschagrunert/nri-supply-chain@$TEST_DIGEST\"" "$TMP_DIR/helm-digest.yaml" ||
	fail "Helm chart does not pin the image by image.digest"

echo "Validating manifest schemas with kubeconform"
"$KUBECONFORM" -strict -summary \
	-schema-location default \
	-schema-location "$CRD_SCHEMA_LOCATION" \
	"${RAW_MANIFESTS[@]}" \
	"$TMP_DIR/helm.yaml" \
	"$TMP_DIR/helm-hostnetwork-off.yaml" \
	"$TMP_DIR/helm-extra-config.yaml" \
	"$TMP_DIR/helm-no-policies.yaml" \
	"$TMP_DIR/helm-restart-on-change.yaml"

# A ConfigMap volume without items projects every key (config.toml included)
# into the policy directory, so an empty policy set must not render one.
policies_volume=$(awk '
	/^        - name: policies$/ { invol = 1; print; next }
	invol && /^        - name: / { exit }
	invol { print }
' "$TMP_DIR/helm-no-policies.yaml")
grep -q 'emptyDir: {}' <<<"$policies_volume" ||
	fail "Helm chart without policies must mount an empty policy directory"
if grep -q 'configMap:' <<<"$policies_volume"; then
	fail "Helm chart without policies must not project the ConfigMap into the policy directory"
fi

if grep -qF 'checksum/config' "$TMP_DIR/helm.yaml"; then
	fail "Helm chart must not roll pods on config changes by default"
fi
grep -qF 'checksum/config' "$TMP_DIR/helm-restart-on-change.yaml" ||
	fail "daemonSet.restartOnConfigChange must add the checksum/config annotation"

grep -q '^kind: NetworkPolicy$' "$TMP_DIR/helm-hostnetwork-off.yaml" ||
	fail "Helm chart must render the NetworkPolicy when hostNetwork is disabled"
if grep -q '^kind: NetworkPolicy$' "$TMP_DIR/helm.yaml"; then
	fail "Helm chart must not render an ineffective NetworkPolicy for host network pods"
fi

extract_configmap "${RAW_MANIFESTS[0]}" "$TMP_DIR/raw" nri-supply-chain-config
extract_configmap "$TMP_DIR/helm.yaml" "$TMP_DIR/helm" nri-supply-chain
extract_configmap "$TMP_DIR/helm-extra-config.yaml" "$TMP_DIR/helm-extra" nri-supply-chain

validate_config "$TMP_DIR/raw" "raw manifest"
validate_config "$TMP_DIR/helm" "Helm chart"
validate_config "$TMP_DIR/helm-extra" "Helm chart with extraConfig"

first_table=$(grep -n '^\[' "$TMP_DIR/helm-extra/config.toml" | head -1 | cut -d: -f1)
audit_line=$(grep -n '^audit_log = ' "$TMP_DIR/helm-extra/config.toml" | head -1 | cut -d: -f1)
[[ -n "$audit_line" ]] || fail "extraConfig was not rendered into config.toml"
if [[ -n "$first_table" && "$audit_line" -gt "$first_table" ]]; then
	fail "extraConfig is rendered after a TOML table, top-level keys would be misplaced"
fi

echo "Checking raw manifest and Helm chart for drift"
for policy in "$TMP_DIR"/raw/policies/*.json; do
	name=$(basename "$policy")
	[[ -f "$TMP_DIR/helm/policies/$name" ]] || fail "policy $name exists only in the raw manifest"
	if ! diff <(jq -S . "$policy") <(jq -S . "$TMP_DIR/helm/policies/$name"); then
		fail "policy $name differs between the raw manifest and the Helm chart"
	fi
done

while IFS= read -r line; do
	key="${line%% =*}"
	[[ "$key" == "policy_dir" ]] && continue
	grep -qxF "$line" "$TMP_DIR/helm/config.toml" ||
		fail "config value differs between raw manifest and Helm chart: $line"
done < <(grep -E '^[a-z_]+ = ' "$TMP_DIR/raw/config.toml")

invariants=(
	'hostNetwork: true'
	'dnsPolicy: Default'
	'priorityClassName: system-node-critical'
	'terminationGracePeriodSeconds: 45'
	'sum by (le, instance)'
	'kubernetes.io/os: linux'
	'tolerate-missing-nri-plugins.noderesource.dev: "true"'
	'runAsUser: 0'
	'readOnlyRootFilesystem: true'
	'allowPrivilegeEscalation: false'
	'type: RuntimeDefault'
	'- ALL'
	'value: /var/cache/nri-supply-chain'
	'mountPath: /var/cache/nri-supply-chain'
	'mountPath: /tmp'
	'pod-security.kubernetes.io/enforce: privileged'
	'honorLabels: true'
	'alert: NRISupplyChainPluginDown'
	'alert: NRISupplyChainNRIDisconnected'
	'alert: NRISupplyChainHighAdmissionLatency'
)
for invariant in "${invariants[@]}"; do
	grep -qF -- "$invariant" "${RAW_MANIFESTS[@]}" ||
		fail "raw manifests are missing: $invariant"
	grep -qF -- "$invariant" "$TMP_DIR/helm.yaml" ||
		fail "rendered Helm chart is missing: $invariant"
done

for forbidden in 'kind: PodDisruptionBudget' 'runAsNonRoot: true' 'cpu: 200m'; do
	if grep -qF -- "$forbidden" "${RAW_MANIFESTS[@]}" "$TMP_DIR/helm.yaml"; then
		fail "manifests contain unexpected setting: $forbidden"
	fi
done

echo "Manifests are valid and in sync"
