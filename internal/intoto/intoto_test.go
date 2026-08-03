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

package intoto_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const (
	testDigest     = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testDigestHash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testDigestAlgo = "sha256"
)

func TestSubjectMatchesDigest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		subjects    []intoto.Subject
		imageDigest string
		want        bool
	}{
		{
			name: "match",
			subjects: []intoto.Subject{
				{Digest: map[string]string{testDigestAlgo: testDigestHash}},
			},
			imageDigest: testDigest,
			want:        true,
		},
		{
			name: "no match",
			subjects: []intoto.Subject{
				{Digest: map[string]string{
					testDigestAlgo: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				}},
			},
			imageDigest: testDigest,
			want:        false,
		},
		{
			name:        "empty subjects",
			subjects:    []intoto.Subject{},
			imageDigest: testDigest,
			want:        false,
		},
		{
			name: "multiple subjects one matches",
			subjects: []intoto.Subject{
				{Digest: map[string]string{
					testDigestAlgo: "0000000000000000000000000000000000000000000000000000000000000000",
				}},
				{Digest: map[string]string{testDigestAlgo: testDigestHash}},
				{Digest: map[string]string{
					testDigestAlgo: "1111111111111111111111111111111111111111111111111111111111111111",
				}},
			},
			imageDigest: testDigest,
			want:        true,
		},
		{
			name: "nil digest map in subject",
			subjects: []intoto.Subject{
				{Digest: nil},
			},
			imageDigest: testDigest,
			want:        false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := intoto.SubjectMatchesDigest(test.subjects, test.imageDigest)
			testutil.AssertEqual(t, test.want, got)
		})
	}
}

func TestVerifySubjectAndExtractPredicate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		att         func(t *testing.T) []byte
		imageDigest string
		wantErr     error
		checkResult func(t *testing.T, result json.RawMessage)
	}{
		{
			name: "valid statement with matching digest extracts predicate",
			att: func(t *testing.T) []byte {
				t.Helper()

				predicate := map[string]string{"builder": "test-builder"}

				return testutil.MustMarshal(t, intoto.Statement{
					Subject: []intoto.Subject{
						{Digest: map[string]string{testDigestAlgo: testDigestHash}},
					},
					Predicate: testutil.MustMarshal(t, predicate),
				})
			},
			imageDigest: testDigest,
			wantErr:     nil,
			checkResult: func(t *testing.T, result json.RawMessage) {
				t.Helper()

				var predicate map[string]string

				err := json.Unmarshal(result, &predicate)
				testutil.AssertNoError(t, err)
				testutil.AssertEqual(t, "test-builder", predicate["builder"])
			},
		},
		{
			name: "invalid JSON returns ErrInvalidStatement",
			att: func(_ *testing.T) []byte {
				return []byte("not valid json")
			},
			imageDigest: testDigest,
			wantErr:     intoto.ErrInvalidStatement,
			checkResult: nil,
		},
		{
			name: "empty subjects returns ErrEmptySubjects",
			att: func(t *testing.T) []byte {
				t.Helper()

				return testutil.MustMarshal(t, intoto.Statement{
					Subject:   []intoto.Subject{},
					Predicate: json.RawMessage(`{"key":"value"}`),
				})
			},
			imageDigest: testDigest,
			wantErr:     intoto.ErrEmptySubjects,
			checkResult: nil,
		},
		{
			name: "digest mismatch returns ErrSubjectMismatch",
			att: func(t *testing.T) []byte {
				t.Helper()

				return testutil.MustMarshal(t, intoto.Statement{
					Subject: []intoto.Subject{
						{Digest: map[string]string{
							testDigestAlgo: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
						}},
					},
					Predicate: json.RawMessage(`{"key":"value"}`),
				})
			},
			imageDigest: testDigest,
			wantErr:     intoto.ErrSubjectMismatch,
			checkResult: nil,
		},
		{
			name: "subjects present but no digest for binding returns ErrNoDigestBinding",
			att: func(t *testing.T) []byte {
				t.Helper()

				return testutil.MustMarshal(t, intoto.Statement{
					Subject: []intoto.Subject{
						{Digest: map[string]string{}},
					},
					Predicate: json.RawMessage(`{"key":"value"}`),
				})
			},
			imageDigest: "",
			wantErr:     intoto.ErrNoDigestBinding,
			checkResult: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, err := intoto.VerifySubjectAndExtractPredicate(test.att(t), test.imageDigest)

			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("expected error wrapping %v, got %v", test.wantErr, err)
				}

				return
			}

			testutil.AssertNoError(t, err)

			if test.checkResult != nil {
				test.checkResult(t, result)
			}
		})
	}
}
