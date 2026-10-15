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

package openvex_test

import (
	"testing"
	"time"

	openvexlib "github.com/openvex/go-vex/pkg/vex"

	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/openvex"
)

func TestParseRejectsFutureTimestamps(t *testing.T) {
	t.Parallel()

	future := time.Now().Add(time.Hour)
	nearFuture := time.Now().Add(10 * time.Second)

	tests := []struct {
		name    string
		modify  func(doc *openvexlib.VEX)
		wantErr bool
	}{
		{
			name:    "document timestamp",
			modify:  func(doc *openvexlib.VEX) { doc.Timestamp = &future },
			wantErr: true,
		},
		{
			name:    "document last_updated",
			modify:  func(doc *openvexlib.VEX) { doc.LastUpdated = &future },
			wantErr: true,
		},
		{
			name:    "statement timestamp",
			modify:  func(doc *openvexlib.VEX) { doc.Statements[0].Timestamp = &future },
			wantErr: true,
		},
		{
			name:    "statement last_updated",
			modify:  func(doc *openvexlib.VEX) { doc.Statements[0].LastUpdated = &future },
			wantErr: true,
		},
		{
			name:    "within clock skew tolerance",
			modify:  func(doc *openvexlib.VEX) { doc.Statements[0].Timestamp = &nearFuture },
			wantErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			doc := validDoc(openvexlib.StatusNotAffected)
			test.modify(&doc)

			_, err := openvex.Parse(testutil.MustMarshal(t, doc))
			if test.wantErr {
				testutil.AssertErrorIs(t, err, openvex.ErrFutureTimestamp)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}
