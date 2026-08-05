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

package policy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

var errSigVerificationFailed = errors.New("signature verification failed")

func TestFetchFromOCIWithSignatureVerificationSuccess(t *testing.T) {
	t.Parallel()

	img := buildPolicyImage(t, map[string]string{
		testDefaultJSON: testWarnPolicyJSON,
	})

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return img, nil
	}

	verifyOK := func(
		_ context.Context,
		_ name.Reference,
		_ ociV1.Image,
		_ []remote.Option,
	) error {
		return nil
	}

	fetcher := policy.NewOCIFetcherWithSignatureVerification(nil, verifyOK)
	fetcher.SetImageFetchFunc(fetchFunc)

	result, err := fetcher.FetchFromOCI(context.Background(), "example.com/test:v1")
	testutil.AssertNoError(t, err)

	if len(result.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(result.Policies))
	}

	if result.Digest == "" {
		t.Error("expected non-empty digest")
	}
}

func TestFetchFromOCIWithSignatureVerificationFailure(t *testing.T) {
	t.Parallel()

	img := buildPolicyImage(t, map[string]string{
		testDefaultJSON: testWarnPolicyJSON,
	})

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return img, nil
	}

	sigErr := errSigVerificationFailed
	verifyFail := func(
		_ context.Context,
		_ name.Reference,
		_ ociV1.Image,
		_ []remote.Option,
	) error {
		return sigErr
	}

	fetcher := policy.NewOCIFetcherWithSignatureVerification(nil, verifyFail)
	fetcher.SetImageFetchFunc(fetchFunc)

	_, err := fetcher.FetchFromOCI(context.Background(), "example.com/test:v1")
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "signature verification failed")
}

func TestFetchFromOCINilVerifySignatureSkipsVerification(t *testing.T) {
	t.Parallel()

	img := buildPolicyImage(t, map[string]string{
		testDefaultJSON: testWarnPolicyJSON,
	})

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return img, nil
	}

	// nil verifySignature means no verification (backward compat).
	fetcher := policy.NewOCIFetcherWithImageFunc(fetchFunc, nil)

	result, err := fetcher.FetchFromOCI(context.Background(), "example.com/test:v1")
	testutil.AssertNoError(t, err)

	if len(result.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(result.Policies))
	}
}

func TestFetchFromOCIWithSignatureBlocksPolicyExtraction(t *testing.T) {
	t.Parallel()

	// This test ensures that when signature verification fails, policy
	// extraction never happens (the error is returned before parsing).

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return buildPolicyImage(t, map[string]string{
			testDefaultJSON: testWarnPolicyJSON,
		}), nil
	}

	verifyFail := func(
		_ context.Context,
		_ name.Reference,
		_ ociV1.Image,
		_ []remote.Option,
	) error {
		return policy.ErrNoPolicySignature
	}

	fetcher := policy.NewOCIFetcherWithSignatureVerification(nil, verifyFail)
	fetcher.SetImageFetchFunc(fetchFunc)

	_, err := fetcher.FetchFromOCI(context.Background(), "example.com/test:v1")
	testutil.AssertError(t, err)

	if !errors.Is(err, policy.ErrNoPolicySignature) {
		t.Errorf("expected ErrNoPolicySignature, got %v", err)
	}
}

func TestNewSignatureVerifyFuncNilParameters(t *testing.T) {
	t.Parallel()

	dummyFetch := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return nil, nil
	}
	dummyReferrers := func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
		return nil, nil
	}
	validCfg := &policy.SignatureConfig{
		Issuers: []string{"https://example.com"},
	}

	t.Run("nil config", func(t *testing.T) {
		t.Parallel()

		_, err := policy.NewSignatureVerifyFunc(nil, nil, dummyFetch, dummyReferrers)
		testutil.AssertError(t, err)
	})

	t.Run("nil fetchImage", func(t *testing.T) {
		t.Parallel()

		_, err := policy.NewSignatureVerifyFunc(validCfg, nil, nil, dummyReferrers)
		testutil.AssertError(t, err)
	})

	t.Run("nil referrers", func(t *testing.T) {
		t.Parallel()

		_, err := policy.NewSignatureVerifyFunc(validCfg, nil, dummyFetch, nil)
		testutil.AssertError(t, err)
	})

	t.Run("no trust material", func(t *testing.T) {
		t.Parallel()

		emptyCfg := &policy.SignatureConfig{}

		_, err := policy.NewSignatureVerifyFunc(emptyCfg, nil, dummyFetch, dummyReferrers)
		testutil.AssertError(t, err)
	})

	t.Run("issuers and keys mutually exclusive", func(t *testing.T) {
		t.Parallel()

		bothCfg := &policy.SignatureConfig{
			Issuers: []string{"https://example.com"},
			Keys:    []string{"/etc/keys/test.pub"},
		}

		_, err := policy.NewSignatureVerifyFunc(bothCfg, nil, dummyFetch, dummyReferrers)
		testutil.AssertError(t, err)
		testutil.AssertContains(t, err.Error(), "mutually exclusive")
	})

	t.Run("nil fetchTrustedRoot with issuers", func(t *testing.T) {
		t.Parallel()

		_, err := policy.NewSignatureVerifyFunc(validCfg, nil, dummyFetch, dummyReferrers)
		testutil.AssertError(t, err)
		testutil.AssertContains(t, err.Error(), "fetchTrustedRoot")
	})
}
