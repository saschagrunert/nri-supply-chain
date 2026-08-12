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

package types_test

import (
	"errors"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var (
	errFuture          = errors.New("future timestamp")
	errUnreasonablyOld = errors.New("unreasonably old")
	errStale           = errors.New("stale")
)

func TestVerifyFreshness(t *testing.T) {
	t.Parallel()

	oneHour := 1 * time.Hour
	zeroDur := time.Duration(0)

	tests := []struct {
		name    string
		ts      time.Time
		maxAge  *time.Duration
		wantErr error
	}{
		{
			name:    "recent timestamp, no max age",
			ts:      time.Now().Add(-10 * time.Second),
			maxAge:  nil,
			wantErr: nil,
		},
		{
			name:    "recent timestamp, within max age",
			ts:      time.Now().Add(-5 * time.Minute),
			maxAge:  &oneHour,
			wantErr: nil,
		},
		{
			name:    "recent timestamp, exceeds max age",
			ts:      time.Now().Add(-2 * time.Hour),
			maxAge:  &oneHour,
			wantErr: errStale,
		},
		{
			name:    "future timestamp beyond clock skew",
			ts:      time.Now().Add(5 * time.Minute),
			maxAge:  nil,
			wantErr: errFuture,
		},
		{
			name:    "future timestamp within clock skew",
			ts:      time.Now().Add(30 * time.Second),
			maxAge:  nil,
			wantErr: nil,
		},
		{
			name:    "unreasonably old timestamp",
			ts:      time.Date(1800, 1, 1, 0, 0, 0, 0, time.UTC),
			maxAge:  nil,
			wantErr: errUnreasonablyOld,
		},
		{
			name:    "zero max age rejects any positive age",
			ts:      time.Now().Add(-1 * time.Second),
			maxAge:  &zeroDur,
			wantErr: errStale,
		},
		{
			name:    "nil max age skips staleness check",
			ts:      time.Now().Add(-24 * time.Hour),
			maxAge:  nil,
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := types.VerifyFreshness(
				test.ts, test.maxAge, "created",
				errFuture, errUnreasonablyOld, errStale,
			)

			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}

				return
			}

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, test.wantErr) {
				t.Fatalf("expected error wrapping %v, got %v", test.wantErr, err)
			}
		})
	}
}
