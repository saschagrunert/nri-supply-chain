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

package bundle //nolint:testpackage // tests use internal test helpers

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestParseManifest(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)

	tests := []struct {
		name    string
		input   *Manifest
		wantErr error
	}{
		{ //nolint:exhaustruct_v5 // test data
			name: "valid manifest",
			input: &Manifest{ //nolint:exhaustruct_v5 // test data
				Version:   1,
				CreatedAt: now,
				Images: map[string]*ImageEntry{
					"sha256:abc123": {
						Refs: []string{"registry.example.com/app:v1.0"},
						Attestations: []AttestationEntry{{
							PredicateType: "https://slsa.dev/provenance/v1",
							BlobDigest:    "sha256:def456",
							Size:          1024,
							SignatureType: "sigstore",
						}},
						CreatedAt: now,
					},
				},
				TrustedRoot: &TrustedRootEntry{
					BlobDigest: "sha256:root789",
					Size:       2048,
				},
			},
		},
		{ //nolint:exhaustruct_v5 // test data
			name: "minimal manifest",
			input: &Manifest{ //nolint:exhaustruct_v5 // test data
				Version:   1,
				CreatedAt: now,
				Images:    map[string]*ImageEntry{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("marshaling test input: %v", err)
			}

			got, err := ParseManifest(data)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseManifest() error = %v, want %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("ParseManifest() unexpected error: %v", err)
			}

			if got.Version != tt.input.Version {
				t.Errorf("Version = %d, want %d", got.Version, tt.input.Version)
			}

			if !got.CreatedAt.Equal(tt.input.CreatedAt) {
				t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, tt.input.CreatedAt)
			}

			if len(got.Images) != len(tt.input.Images) {
				t.Errorf("Images count = %d, want %d", len(got.Images), len(tt.input.Images))
			}
		})
	}
}

func TestParseManifestErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{
			name:    "invalid JSON",
			input:   []byte(`{invalid`),
			wantErr: ErrManifestCorrupt,
		},
		{
			name:    "unsupported version too high",
			input:   []byte(`{"version": 999}`),
			wantErr: ErrManifestVersionUnsupported,
		},
		{
			name:    "unsupported version zero",
			input:   []byte(`{"version": 0}`),
			wantErr: ErrManifestVersionUnsupported,
		},
		{
			name:    "unsupported version negative",
			input:   []byte(`{"version": -1}`),
			wantErr: ErrManifestVersionUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseManifest(tt.input)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ParseManifest() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseManifestNilImages(t *testing.T) {
	t.Parallel()

	data := []byte(`{"version": 1}`)

	m, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.Images == nil {
		t.Fatal("Images should be initialized to empty map, got nil")
	}
}

func TestMarshalManifestForSigning(t *testing.T) {
	t.Parallel()

	m := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		Images:    map[string]*ImageEntry{},
		Signature: &ManifestSignature{
			Algorithm: "ecdsa-sha256",
			Value:     "abc123",
			KeyHint:   "hint",
		},
	}

	data, err := MarshalManifestForSigning(m)
	if err != nil {
		t.Fatalf("MarshalManifestForSigning() error: %v", err)
	}

	var parsed map[string]any

	unmarshalErr := json.Unmarshal(data, &parsed)
	if unmarshalErr != nil {
		t.Fatalf("unmarshaling signed bytes: %v", unmarshalErr)
	}

	if _, ok := parsed["signature"]; ok {
		t.Error("signature field should be absent in signing output")
	}

	if m.Signature == nil {
		t.Error("original manifest signature should not be modified")
	}
}

func FuzzParseManifest(f *testing.F) {
	f.Add([]byte(`{"version":1,"images":{}}`))
	f.Add([]byte(`{"version":0}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`invalid`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParseManifest(data)
	})
}
