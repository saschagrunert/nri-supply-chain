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

package cel_test

import (
	"testing"

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func FuzzCompileAndEvaluate(f *testing.F) {
	f.Add("image.registry == 'ghcr.io'", "slsa.verified == true")
	f.Add("true", "true")
	f.Add("", "vex.verified")
	f.Add("", "image.ref.startsWith('ghcr')")
	f.Add("", "invalid +++")

	f.Fuzz(func(_ *testing.T, match, require string) {
		if len(require) > celengine.MaxExpressionSize || len(match) > celengine.MaxExpressionSize {
			return
		}

		rules := []celengine.Rule{
			{Match: match, Require: require},
		}

		compiled, err := celengine.Compile(rules)
		if err != nil {
			return
		}

		vars := celengine.BuildVars(
			testImageRef, testRegistry, testRepository, testDigest, testNamespace,
			types.PassResult(types.CheckTypeSLSA, "ok"),
			types.PassResult(types.CheckTypeVEX, "ok"),
			nil,
			types.PassResult(types.CheckTypeSBOM, "ok"),
			nil,
			nil,
		)

		celengine.Evaluate(compiled, vars)
	})
}
