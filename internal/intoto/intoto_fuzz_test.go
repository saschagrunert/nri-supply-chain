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
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
)

const fuzzDigest = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

func FuzzVerifySubjectAndExtractPredicate(f *testing.F) {
	validStmt, err := json.Marshal(intoto.Statement{
		Subject: []intoto.Subject{
			{Digest: map[string]string{"sha256": fuzzDigest}},
		},
		Predicate: json.RawMessage(`{"builder":"test"}`),
	})
	if err != nil {
		f.Fatalf("marshaling seed statement: %v", err)
	}

	f.Add(validStmt, "sha256:"+fuzzDigest)
	f.Add([]byte(`{}`), "sha256:abc123")
	f.Add([]byte(`not valid json`), "sha256:abc123")
	f.Add([]byte(`{"subject":[]}`), "sha256:abc123")
	f.Add([]byte(`{"subject":[{"digest":{}}]}`), "")
	f.Add(
		[]byte(`{"subject":[{"digest":{"sha256":"ffff"}}]}`),
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
	)

	f.Fuzz(func(t *testing.T, att []byte, imageDigest string) {
		predicate, err := intoto.VerifySubjectAndExtractPredicate(att, imageDigest)
		if err == nil && predicate == nil {
			t.Error("VerifySubjectAndExtractPredicate returned nil predicate and nil error")
		}
	})
}

func FuzzSubjectMatchesDigest(f *testing.F) {
	f.Add("sha256:" + fuzzDigest)
	f.Add("")
	f.Add("sha256:")
	f.Add("invalid")
	f.Add("sha512:abc123")

	f.Fuzz(func(_ *testing.T, imageDigest string) {
		subjects := []intoto.Subject{
			{Digest: map[string]string{"sha256": fuzzDigest}},
		}
		intoto.SubjectMatchesDigest(subjects, imageDigest)
	})
}
