// Copyright The nri-supply-chain Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verifier

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testPromotedImage  = "registry.k8s.io/security-profiles-operator/security-profiles-operator:v1.1.0"
	testPromoterIssuer = "https://accounts.google.com"
	testPromoterSigner = "krel-trust@k8s-releng-prod.iam.gserviceaccount.com"
)

// shippedDefaultPolicy loads the default.json policy of the raw DaemonSet
// manifest, which "make verify-manifests" keeps in sync with the Helm chart.
func shippedDefaultPolicy(t *testing.T) *policy.Policy {
	t.Helper()

	manifest, err := os.ReadFile("../../deploy/kubernetes/daemonset.yaml")
	testutil.AssertNoError(t, err)

	var (
		lines   []string
		inBlock bool
	)

	for line := range strings.SplitSeq(string(manifest), "\n") {
		if line == "  default.json: |" {
			inBlock = true

			continue
		}

		if !inBlock {
			continue
		}

		block, ok := strings.CutPrefix(line, "    ")
		if !ok && strings.TrimSpace(line) != "" {
			break
		}

		lines = append(lines, block)
	}

	if len(lines) == 0 {
		t.Fatal("default.json not found in the DaemonSet manifest")
	}

	path := filepath.Join(t.TempDir(), "default.json")
	testutil.AssertNoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600))

	pol, err := policy.Load(path)
	testutil.AssertNoError(t, err)

	return pol
}

func TestShippedDefaultPolicyExcludesOnlySystemImages(t *testing.T) {
	t.Parallel()

	pol := shippedDefaultPolicy(t)

	for _, imageRef := range []string{
		"registry.k8s.io/coredns/coredns:v1.12.1",
		"registry.k8s.io/etcd:3.6.4-0",
		"registry.k8s.io/kube-apiserver:v1.34.1",
		"registry.k8s.io/kube-controller-manager:v1.34.1",
		"registry.k8s.io/kube-proxy:v1.34.1",
		"registry.k8s.io/kube-proxy:v1.34.1@" + testPinnedDigest,
		"registry.k8s.io/kube-proxy@" + testPinnedDigest,
		"registry.k8s.io/kube-scheduler:v1.34.1",
		"registry.k8s.io/pause:3.10",
		"registry.k8s.io/sig-storage/csi-node-driver-registrar:v2.15.0",
		"registry.k8s.io/sig-storage/nfs-subdir-external-provisioner:v4.0.2",
		"registry.k8s.io/dns/k8s-dns-node-cache:1.26.4",
		"registry.k8s.io/kas-network-proxy/proxy-agent:v0.33.0",
		"registry.k8s.io/provider-aws/cloud-controller-manager:v1.34.0",
		"registry.k8s.io/provider-aws/aws-ebs-csi-driver:v1.50.0",
		"registry.k8s.io/provider-os/openstack-cloud-controller-manager:v1.34.0",
		"registry.k8s.io/provider-os/cinder-csi-plugin:v1.34.0",
		"registry.k8s.io/cloud-provider-gcp/cloud-controller-manager:v34.0.0",
		"registry.k8s.io/cloud-provider-gcp/gcp-compute-persistent-disk-csi-driver:v1.20.0",
	} {
		if !isExcluded(t.Context(), pol.Exclude, imageRef) {
			t.Errorf("expected %s to be excluded", imageRef)
		}
	}

	for _, imageRef := range []string{
		testPromotedImage,
		"registry.k8s.io/security-profiles-operator/security-profiles-operator@" + testPinnedDigest,
		"registry.k8s.io/ingress-nginx/controller:v1.13.3",
		"registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.17.0",
		"registry.k8s.io/provider-aws/aws-load-balancer-controller:v2.14.0",
	} {
		if isExcluded(t.Context(), pol.Exclude, imageRef) {
			t.Errorf("expected %s to be verified", imageRef)
		}
	}
}

func TestRegistryK8sIOExampleRequiresPromoterVSA(t *testing.T) {
	t.Parallel()

	pol, err := policy.Load("../../deploy/examples/policies/registry-k8s-io.json")
	testutil.AssertNoError(t, err)

	if shipped := shippedDefaultPolicy(t); !slices.Equal(pol.Exclude, shipped.Exclude) {
		t.Errorf("example excludes %v, the shipped default policy %v", pol.Exclude, shipped.Exclude)
	}

	for _, imageRef := range []string{
		testPromotedImage,
		"registry.k8s.io/security-profiles-operator/security-profiles-operator@" + testPinnedDigest,
	} {
		if isExcluded(t.Context(), pol.Exclude, imageRef) {
			t.Fatalf("expected %s to be verified", imageRef)
		}

		resolved, ruleIdx := ResolveImagePolicy(t.Context(), pol, imageRef)
		if ruleIdx != 0 {
			t.Fatalf("expected %s to match the promoter rule, got rule %d", imageRef, ruleIdx)
		}

		if got := resolved.VSAMissingPolicy(); got != types.ActionDeny {
			t.Errorf("expected a missing VSA to be denied for %s, got %q", imageRef, got)
		}

		if len(resolved.Trust.Verifiers) != 1 {
			t.Fatalf("expected one trusted verifier, got %d", len(resolved.Trust.Verifiers))
		}

		verifier := resolved.Trust.Verifiers[0]
		if verifier.ID != "https://k8s.io/promo-tools/verifier/v1" ||
			len(verifier.Keys) != 0 || len(verifier.Identities) != 1 ||
			verifier.Identities[0].Issuer != testPromoterIssuer ||
			verifier.Identities[0].SANPattern != testPromoterSigner {
			t.Errorf("expected the promoter verifier bound to %s, got %+v",
				testPromoterSigner, verifier)
		}

		if !slices.Equal(resolved.Trust.SANPatterns, []string{testPromoterSigner}) {
			t.Errorf("expected only the promoter signer to be trusted, got %v",
				resolved.Trust.SANPatterns)
		}
	}

	if _, ruleIdx := ResolveImagePolicy(t.Context(), pol, "ghcr.io/myorg/app:v1"); ruleIdx != -1 {
		t.Errorf("expected other images to use the base policy, got rule %d", ruleIdx)
	}
}
