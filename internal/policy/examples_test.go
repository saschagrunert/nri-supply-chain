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

package policy_test

import (
	"path/filepath"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

func TestExamplePolicies(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob("../../examples/policies/*.json")
	if err != nil {
		t.Fatalf("globbing: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("no example policies found")
	}

	for _, policyFile := range files {
		t.Run(filepath.Base(policyFile), func(t *testing.T) {
			t.Parallel()

			_, err := policy.Load(policyFile)
			if err != nil {
				t.Fatalf("loading %s: %v", policyFile, err)
			}
		})
	}
}
