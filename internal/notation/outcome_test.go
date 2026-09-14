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

//nolint:testpackage // testing unexported functions
package notation

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	notationlib "github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var errLoggedValidation = errors.New("logged validation failure")

func outcomeWith(
	level *trustpolicy.VerificationLevel, results ...*notationlib.ValidationResult,
) *notationlib.VerificationOutcome {
	return &notationlib.VerificationOutcome{
		RawSignature:        nil,
		EnvelopeContent:     nil,
		VerificationLevel:   level,
		VerificationResults: results,
		Error:               nil,
	}
}

func loggedFailure(validationType trustpolicy.ValidationType) *notationlib.ValidationResult {
	return &notationlib.ValidationResult{
		Type:   validationType,
		Action: trustpolicy.ActionLog,
		Error:  errLoggedValidation,
	}
}

func TestResultFromOutcome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		outcome    *notationlib.VerificationOutcome
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "nil outcome fails",
			outcome:    nil,
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "clean strict outcome passes",
			outcome:    outcomeWith(trustpolicy.LevelStrict),
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "audit level logged authenticity failure fails",
			outcome: outcomeWith(
				trustpolicy.LevelAudit,
				loggedFailure(trustpolicy.TypeAuthenticity),
			),
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "logged integrity failure fails",
			outcome: outcomeWith(
				trustpolicy.LevelAudit,
				loggedFailure(trustpolicy.TypeIntegrity),
			),
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "permissive logged expiry passes with warning",
			outcome: outcomeWith(
				trustpolicy.LevelPermissive,
				loggedFailure(trustpolicy.TypeExpiry),
			),
			wantPassed: true,
			wantStatus: types.StatusWarn,
		},
		{
			name: "logged revocation passes with warning",
			outcome: outcomeWith(
				trustpolicy.LevelPermissive,
				loggedFailure(trustpolicy.TypeRevocation),
			),
			wantPassed: true,
			wantStatus: types.StatusWarn,
		},
		{
			name:       "skip level fails",
			outcome:    outcomeWith(trustpolicy.LevelSkip),
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := resultFromOutcome(context.Background(), tt.outcome, testImageRef)

			if result.Passed != tt.wantPassed {
				t.Errorf(
					"Passed = %v, want %v (detail %q)",
					result.Passed,
					tt.wantPassed,
					result.Detail,
				)
			}

			if result.Status != tt.wantStatus {
				t.Errorf("Status = %q, want %q", result.Status, tt.wantStatus)
			}
		})
	}
}

func TestVerifierForPolicyCachesAndDetectsCertChanges(t *testing.T) {
	t.Parallel()

	notationPolicy := validNotationPolicy(t)

	first, err := verifierForPolicy(notationPolicy)
	if err != nil {
		t.Fatalf("building verifier: %v", err)
	}

	second, err := verifierForPolicy(notationPolicy)
	if err != nil {
		t.Fatalf("building verifier: %v", err)
	}

	if first != second {
		t.Error("expected cached verifier to be reused for unchanged policy")
	}

	certPath := notationPolicy.TrustStores[0].Certificates[0]
	future := time.Now().Add(time.Hour)

	err = os.Chtimes(certPath, future, future)
	if err != nil {
		t.Fatalf("touching certificate: %v", err)
	}

	third, err := verifierForPolicy(notationPolicy)
	if err != nil {
		t.Fatalf("building verifier: %v", err)
	}

	if third == first {
		t.Error("expected a new verifier after the certificate file changed")
	}
}

func TestVerifierCacheKeyDiffersByPolicy(t *testing.T) {
	t.Parallel()

	notationPolicy := validNotationPolicy(t)
	key := verifierCacheKey(notationPolicy)

	changed := *notationPolicy
	changed.VerificationLevel = trustpolicy.LevelPermissive.Name

	if verifierCacheKey(&changed) == key {
		t.Error("expected different cache keys for different verification levels")
	}

	missing := *notationPolicy
	missing.TrustStores = append(missing.TrustStores[:0:0], notationPolicy.TrustStores...)
	missing.TrustStores[0].Certificates = []string{
		notationPolicy.TrustStores[0].Certificates[0] + "-missing",
	}

	if verifierCacheKey(&missing) == key {
		t.Error("expected different cache keys for different certificate files")
	}

	if verifierCacheKey(notationPolicy) != key {
		t.Error("expected a stable cache key for an unchanged policy")
	}
}
