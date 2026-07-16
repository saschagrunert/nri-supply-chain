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

package attestation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

const testDigest = "sha256:abc123"

var errFetchFailed = errors.New("fetch failed")

type mockFetcher struct {
	attestations []attestation.VerifiedAttestation
	err          error
}

//nolint:gocritic // hugeParam: signature must match Fetcher interface
func (m *mockFetcher) Fetch(
	_ context.Context, _, _ string, _ attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	return m.attestations, m.err
}

//nolint:funlen,varnamelen // table-driven test
func TestMockFetcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		attestations []attestation.VerifiedAttestation
		err          error
		wantCount    int
		wantErr      error
	}{
		{
			name: "returns attestations",
			attestations: []attestation.VerifiedAttestation{
				{
					PredicateType: attestation.PredicateSLSAProvenanceV1,
					Payload:       []byte(`{"test": true}`),
					Digest:        testDigest,
				},
			},
			err:       nil,
			wantCount: 1,
			wantErr:   nil,
		},
		{
			name:         "returns error",
			attestations: nil,
			err:          errFetchFailed,
			wantCount:    0,
			wantErr:      errFetchFailed,
		},
		{
			name:         "returns empty",
			attestations: nil,
			err:          nil,
			wantCount:    0,
			wantErr:      nil,
		},
		{
			name: "multiple attestations",
			attestations: []attestation.VerifiedAttestation{
				{
					PredicateType: attestation.PredicateSLSAProvenanceV1,
					Payload:       []byte(`{"slsa": true}`),
					Digest:        testDigest,
				},
				{
					PredicateType: attestation.PredicateVSA,
					Payload:       []byte(`{"vsa": true}`),
					Digest:        testDigest,
				},
				{
					PredicateType: attestation.PredicateOpenVEX,
					Payload:       []byte(`{"vex": true}`),
					Digest:        testDigest,
				},
			},
			err:       nil,
			wantCount: 3,
			wantErr:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fetcher := &mockFetcher{attestations: tt.attestations, err: tt.err}
			ctx := context.Background()
			opts := attestation.FetchOptions{
				Timeout: 30 * time.Second,
			}

			result, err := fetcher.Fetch(ctx, "nginx:latest", testDigest, opts)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected %v, got %v", tt.wantErr, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(result) != tt.wantCount {
				t.Errorf("expected %d attestations, got %d", tt.wantCount, len(result))
			}
		})
	}
}

func TestPredicateTypeConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "SLSA provenance v1",
			got:  attestation.PredicateSLSAProvenanceV1,
			want: "https://slsa.dev/provenance/v1",
		},
		{
			name: "SLSA provenance v0.2",
			got:  attestation.PredicateSLSAProvenanceV02,
			want: "https://slsa.dev/provenance/v0.2",
		},
		{
			name: "VSA",
			got:  attestation.PredicateVSA,
			want: "https://slsa.dev/verification_summary/v1",
		},
		{
			name: "OpenVEX",
			got:  attestation.PredicateOpenVEX,
			want: "https://openvex.dev/ns",
		},
		{
			name: "bundle media type",
			got:  attestation.BundleMediaType,
			want: "application/vnd.dev.sigstore.bundle.v0.3+json",
		},
		{
			name: "annotation predicate type",
			got:  attestation.AnnotationPredicateType,
			want: "dev.sigstore.bundle.predicateType",
		},
		{
			name: "DSSE payload type",
			got:  attestation.DSSEPayloadType,
			want: "application/vnd.in-toto+json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, tt.got)
			}
		})
	}
}
