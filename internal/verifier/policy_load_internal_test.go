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
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	ociTypes "github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func TestLoadAndHashPoliciesCommitsOCIRollbackGuard(t *testing.T) {
	t.Parallel()

	const created = "2026-09-01T00:00:00Z"

	annotations := map[string]string{"org.opencontainers.image.title": "default.json"}

	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: static.NewLayer(
			[]byte(`{"slsa": {"missingPolicy": "warn"}}`),
			ociTypes.MediaType(policy.PolicyMediaType),
		),
		Annotations: annotations,
	})
	testutil.AssertNoError(t, err)

	annotated, ok := mutate.Annotations(img, map[string]string{
		policy.CreatedAnnotation: created,
	}).(ociV1.Image)
	if !ok {
		t.Fatal("expected annotated image")
	}

	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)

	ociRef := strings.TrimPrefix(srv.URL, "http://") + "/org/policies:v1"

	ref, err := name.ParseReference(ociRef)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, remote.Write(ref, annotated))

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.Policy.Source = config.PolicySourceOCI
	cfg.Policy.OCIRef = ociRef

	loaded, err := loadAndHashPolicies(t.Context(), cfg, nil, time.Time{})
	testutil.AssertNoError(t, err)

	if loaded.policyFetcher == nil {
		t.Fatal("expected a policy fetcher")
	}

	want, err := time.Parse(time.RFC3339, created)
	testutil.AssertNoError(t, err)

	if got := loaded.policyFetcher.NewestCreated(); !got.Equal(want) {
		t.Errorf(
			"expected the accepted artifact to raise the rollback guard to %s, got %s",
			want,
			got,
		)
	}
}
