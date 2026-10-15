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

package scai_test

import (
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/checker/checkertest"
	"github.com/saschagrunert/nri-supply-chain/internal/scai"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func TestContract(t *testing.T) {
	t.Parallel()

	checkertest.RunContract(t, &checkertest.Contract{
		Verify:        scai.VerifyMultiple,
		CheckType:     types.CheckTypeSCAI,
		PredicateType: testPredicateType,
		Digest:        testDigest,
		ErrInvalid:    scai.ErrInvalidSCAI,
		Valid:         validReport(),
		OptionalMeta:  nil,
	})
}
