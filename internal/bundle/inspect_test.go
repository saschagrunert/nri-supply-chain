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

package bundle //nolint:testpackage // tests use internal helpers

import (
	"errors"
	"testing"
	"time"
)

func TestInspectBasic(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"predicateType":"test","predicate":{}}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC().Add(-1 * time.Hour),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Refs: []string{"registry.example.com/app:v1"},
				Attestations: []AttestationEntry{{
					PredicateType: testSLSAPredicate,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
			},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{
		digest: payload,
	})

	result, err := Inspect(dir)
	if err != nil {
		t.Fatalf("Inspect() error: %v", err)
	}

	if result.Version != 1 {
		t.Errorf("Version = %d, want 1", result.Version)
	}

	if result.ImageCount != 1 {
		t.Errorf("ImageCount = %d, want 1", result.ImageCount)
	}

	if result.AttestationCount != 1 {
		t.Errorf(
			"AttestationCount = %d, want 1", result.AttestationCount,
		)
	}

	if result.TrustedRoot {
		t.Error("TrustedRoot should be false")
	}

	if result.Signed {
		t.Error("Signed should be false")
	}

	if result.Age <= 0 {
		t.Errorf("Age = %v, want > 0", result.Age)
	}

	if len(result.Images) != 1 {
		t.Fatalf("Images count = %d, want 1", len(result.Images))
	}

	img := result.Images[0]
	if img.Digest != testImageDigest {
		t.Errorf("Digest = %q, want %q", img.Digest, testImageDigest)
	}

	if img.AttestationCount != 1 {
		t.Errorf(
			"img.AttestationCount = %d, want 1",
			img.AttestationCount,
		)
	}
}

func TestInspectWithSignature(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images:    map[string]*ImageEntry{},
		Signature: &ManifestSignature{
			Algorithm: algorithmSHA256,
			Value:     "dGVzdA==",
			KeyHint:   "test-key-hint",
		},
	}

	dir := createTestStore(t, manifest, nil)

	result, err := Inspect(dir)
	if err != nil {
		t.Fatalf("Inspect() error: %v", err)
	}

	if !result.Signed {
		t.Error("Signed should be true")
	}

	if result.SignatureKeyHint != "test-key-hint" {
		t.Errorf(
			"SignatureKeyHint = %q, want %q",
			result.SignatureKeyHint, "test-key-hint",
		)
	}
}

func TestHumanDurationMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		duration time.Duration
		want     string
	}{
		{"one hour", time.Hour, `"1h0m0s"`},
		{"zero", 0, `"0s"`},
		{"sub-second rounds down", 500 * time.Millisecond, `"1s"`},
		{"negative", -30 * time.Minute, `"-30m0s"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := HumanDuration(tc.duration).MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON() error: %v", err)
			}

			if string(got) != tc.want {
				t.Errorf("MarshalJSON() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestHumanDurationDuration(t *testing.T) {
	t.Parallel()

	d := HumanDuration(42 * time.Second)
	if d.Duration() != 42*time.Second {
		t.Errorf("Duration() = %v, want %v", d.Duration(), 42*time.Second)
	}
}

func TestInspectNotFound(t *testing.T) {
	t.Parallel()

	_, err := Inspect("/nonexistent/path")
	if err == nil {
		t.Fatal("Inspect() should return error for nonexistent path")
	}

	if !errors.Is(err, ErrBundleNotFound) {
		t.Errorf("error = %v, want %v", err, ErrBundleNotFound)
	}
}
