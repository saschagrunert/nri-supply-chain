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

// Package intoto provides shared in-toto statement types and subject matching.
package intoto

import (
	"encoding/json"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// Statement is a minimal in-toto statement containing subjects and a raw
// predicate payload.
type Statement struct {
	Subject   []Subject       `json:"subject"`
	Predicate json.RawMessage `json:"predicate"`
}

// Subject holds the digest map for an in-toto statement subject.
type Subject struct {
	Digest map[string]string `json:"digest"`
}

// SubjectMatchesDigest returns true if any subject's digest matches the given
// image digest string.
func SubjectMatchesDigest(subjects []Subject, imageDigest string) bool {
	for _, subject := range subjects {
		if types.MatchDigestInMap(imageDigest, subject.Digest) {
			return true
		}
	}

	return false
}
