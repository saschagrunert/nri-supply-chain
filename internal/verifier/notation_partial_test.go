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

package verifier_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

func untrustedNotationSignature(digest string) attestation.VerifiedAttestation {
	return attestation.VerifiedAttestation{
		PredicateType: attestation.NotationSignatureMediaType,
		SignatureType: attestation.SignatureTypeNotation,
		Payload:       []byte("untrusted-signature"),
		Digest:        digest,
		Signer: attestation.SignerIdentity{
			KeyPath: "", KeyPaths: nil, Issuer: "", SAN: "",
		},
	}
}

// notationPolicy returns a Notation-only policy trusting the root certificate
// in certPath, or a file that is no certificate when certPath is empty.
func notationPolicy(t *testing.T, missingPolicy types.Action, certPath string) string {
	t.Helper()

	if certPath == "" {
		certPath = filepath.Join(t.TempDir(), "ca.pem")

		err := os.WriteFile(certPath, []byte("not a certificate"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
	}

	return fmt.Sprintf(`{"notation":{
		"missingPolicy":%q,
		"revocationMode":"skip",
		"trustStores":[{"name":"store","type":"ca","certificates":[%q]}],
		"trustPolicy":[{"name":"rule","registryScopes":["*"],
			"trustStores":["ca:store"],"trustedIdentities":["*"]}]
	}}`, missingPolicy, certPath)
}

// TestVerifyTrustedNotationNextToUntrustedSigstoreAttestation checks that an
// image with a valid Notation signature and a Sigstore attestation from an
// untrusted signer (an upstream attestation, for example) is admitted by a
// Notation-only policy: the Notation check passes and the untrusted
// attestation is only reported.
func TestVerifyTrustedNotationNextToUntrustedSigstoreAttestation(t *testing.T) {
	t.Parallel()

	signer := newNotationSigner(t)

	fetcher := &legFetcher{
		attestations: map[string][]attestation.VerifiedAttestation{
			testFetchDigest: {signer.sign(t, testFetchDigest)},
		},
		errs: map[string]error{testFetchDigest: errUntrustedBundles()},
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce

	verif, _ := newHardeningVerifier(t, cfg, fetcher, map[string]string{
		testDefaultPolicy: notationPolicy(t, types.ActionDeny, signer.rootPath),
	})

	result, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, "", "default", ""))
	if err != nil {
		t.Fatalf("expected the trusted Notation signature to admit the image, got %v (%+v)",
			err, result)
	}

	check := findCheck(result, types.CheckTypeNotation)
	if check == nil || !check.Passed || check.Missing {
		t.Fatalf("expected a passing Notation check, got %+v", check)
	}

	if findCheck(result, types.CheckTypeAttestation) == nil {
		t.Errorf("expected the untrusted Sigstore attestation to be reported, got %+v", result)
	}
}

// TestVerifyNotationEvaluatedNextToFailedCosignReferrer checks that a cosign
// referrer that fails verification does not turn the Notation signatures of
// an image into missing ones: an untrusted signature still fails the Notation
// check even when missing signatures are allowed, and a signature is still
// evaluated when Notation is required.
func TestVerifyNotationEvaluatedNextToFailedCosignReferrer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		missingPolicy types.Action
		indexDigest   bool
	}{
		{"missing allowed", types.ActionAllow, false},
		{"missing denied", types.ActionDeny, false},
		{"missing allowed on index digest", types.ActionAllow, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fetcher := &legFetcher{
				attestations: map[string][]attestation.VerifiedAttestation{
					testFetchDigest: {untrustedNotationSignature(testFetchDigest)},
				},
				errs: map[string]error{testFetchDigest: errUntrustedBundles()},
			}

			indexDigest := ""
			if test.indexDigest {
				indexDigest = testIndexDigest
				fetcher.attestations = map[string][]attestation.VerifiedAttestation{
					testIndexDigest: {untrustedNotationSignature(testIndexDigest)},
				}
				fetcher.errs = map[string]error{testIndexDigest: errUntrustedBundles()}
			}

			cfg := config.DefaultConfig()
			cfg.Verification = config.ModeEnforce

			verif, _ := newHardeningVerifier(t, cfg, fetcher, map[string]string{
				testDefaultPolicy: notationPolicy(t, test.missingPolicy, ""),
			})

			result, err := verif.Verify(context.Background(),
				newRequest(testHardeningImage, testFetchDigest, indexDigest, "default", ""))
			if !errors.Is(err, verifier.ErrVerificationFailed) {
				t.Fatalf("expected the untrusted Notation signature to deny, got %v", err)
			}

			check := findCheck(result, types.CheckTypeNotation)
			if check == nil || check.Missing || check.Passed {
				t.Fatalf("expected an evaluated, failing Notation check, got %+v", check)
			}

			if findCheck(result, types.CheckTypeAttestation) == nil {
				t.Errorf("expected the failed cosign referrer to be reported, got %+v", result)
			}
		})
	}
}

// TestVerifyPlatformJunkDoesNotHideIncompleteIndexSet checks that cosign
// referrers failing verification on the platform digest do not make an
// incomplete index digest attestation set ignorable.
func TestVerifyPlatformJunkDoesNotHideIncompleteIndexSet(t *testing.T) {
	t.Parallel()

	fetcher := &legFetcher{
		attestations: nil,
		errs: map[string]error{
			testIndexDigest: fmt.Errorf("%w: %w: referrer limit exceeded",
				attestation.ErrVerificationFailed, attestation.ErrIncompleteAttestationSet),
			testFetchDigest: errUntrustedBundles(),
		},
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce

	verif, _ := newHardeningVerifier(t, cfg, fetcher, map[string]string{testDefaultPolicy: `{}`})

	_, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, testIndexDigest, "default", ""))
	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Fatalf("expected the incomplete index digest set to deny, got %v", err)
	}
}
