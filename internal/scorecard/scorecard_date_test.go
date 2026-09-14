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

package scorecard_test

import (
	"context"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/scorecard"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func TestVerifyDateOnlyTimezoneTolerance(t *testing.T) {
	t.Parallel()

	const dateOnly = "2006-01-02"

	tests := []struct {
		name       string
		date       string
		wantPassed bool
	}{
		{
			// A scanner in a timezone ahead of UTC writes its local date,
			// which can be the next UTC day.
			name:       "next day local date",
			date:       time.Now().UTC().Add(24 * time.Hour).Format(dateOnly),
			wantPassed: true,
		},
		{
			name:       "date two days ahead",
			date:       time.Now().UTC().Add(72 * time.Hour).Format(dateOnly),
			wantPassed: false,
		},
		{
			name:       "rfc3339 an hour ahead is still rejected",
			date:       time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
			wantPassed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc := validDoc()
			doc.Date = tc.date

			result, err := scorecard.Verify(
				context.Background(), wrapInToto(t, doc, testDigest), &policy.Policy{}, testDigest,
			)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, tc.wantPassed, result.Passed)
		})
	}
}
