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

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const testFieldName = "missingPolicy"

func TestValidateAction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   types.Action
		wantErr bool
	}{
		{name: "allow is valid", value: "allow", wantErr: false},
		{name: "warn is valid", value: "warn", wantErr: false},
		{name: "deny is valid", value: "deny", wantErr: false},
		{name: "empty string is invalid", value: "", wantErr: true},
		{name: "uppercase WARN is invalid", value: "WARN", wantErr: true},
		{name: "arbitrary string is invalid", value: "invalid", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := types.ValidateAction(testFieldName, test.value)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if !errors.Is(err, types.ErrInvalidAction) {
					t.Errorf("expected ErrInvalidAction, got %v", err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
