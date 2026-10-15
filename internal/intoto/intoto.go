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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var (
	// ErrInvalidStatement indicates the in-toto statement could not be parsed.
	ErrInvalidStatement = errors.New("invalid in-toto statement")

	// ErrEmptySubjects indicates a statement has no subjects when a digest
	// is available for binding.
	ErrEmptySubjects = errors.New("statement has no subjects for digest binding")

	// ErrSubjectMismatch indicates the in-toto subject does not match the image.
	ErrSubjectMismatch = errors.New("subject digest mismatch")

	// ErrNoDigestBinding indicates subjects exist but no digest was provided
	// for binding.
	ErrNoDigestBinding = errors.New("statement has subjects but no digest for binding")

	// ErrMissingPredicate indicates a statement without a predicate.
	ErrMissingPredicate = fmt.Errorf("%w: statement has no predicate", ErrInvalidStatement)
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

// VerifySubjectAndExtractPredicate unmarshals an in-toto statement, verifies
// subject digest binding, and returns the raw predicate payload.
func VerifySubjectAndExtractPredicate(att []byte, imageDigest string) (json.RawMessage, error) {
	var stmt Statement

	err := json.Unmarshal(att, &stmt)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}

	err = checkSubjectBinding(stmt.Subject, imageDigest)
	if err != nil {
		return nil, err
	}

	// A null predicate is a missing one: encoding/json hands json.RawMessage
	// the literal null.
	predicate := bytes.TrimSpace(stmt.Predicate)
	if len(predicate) > 0 && !bytes.Equal(predicate, []byte("null")) {
		return stmt.Predicate, nil
	}

	// A statement without a predicate must not be evaluated as an empty
	// document, which would pass deny lists trivially. Only a bare document
	// (no subjects, verified without a digest) is returned as is.
	if len(stmt.Subject) > 0 {
		return nil, ErrMissingPredicate
	}

	return att, nil
}

// checkSubjectBinding checks that the subjects of a statement bind it to
// imageDigest: with a digest some subject must match it, without one the
// statement must have no subjects.
func checkSubjectBinding(subjects []Subject, imageDigest string) error {
	switch {
	case imageDigest != "" && len(subjects) == 0:
		return fmt.Errorf(
			"%w: digest %q available but statement has no subjects",
			ErrEmptySubjects, imageDigest,
		)
	case imageDigest != "" && !SubjectMatchesDigest(subjects, imageDigest):
		return fmt.Errorf(
			"%w: none of the subjects match %q",
			ErrSubjectMismatch, imageDigest,
		)
	case imageDigest == "" && len(subjects) > 0:
		return fmt.Errorf(
			"%w: statement has %d subjects but no digest for binding",
			ErrNoDigestBinding, len(subjects),
		)
	default:
		return nil
	}
}
