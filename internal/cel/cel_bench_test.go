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

func BenchmarkCompile(b *testing.B) {
	rules := []celengine.Rule{
		{
			Match:   exprMatchGHCR,
			Require: exprSLSAVerified,
			Message: msgGHCRSLSA,
		},
		{
			Require: exprVEXVerified,
			Message: msgVEXMustBeVerified,
		},
	}

	// Reset the environment on each iteration to benchmark full compilation.
	b.ResetTimer()

	for range b.N {
		celengine.ResetEnvironmentForTest()

		_, _ = celengine.Compile(rules)
	}
}

func BenchmarkEvaluate(b *testing.B) {
	rules := []celengine.Rule{
		{
			Match:   exprMatchGHCR,
			Require: exprSLSAVerified,
			Message: msgGHCRSLSA,
		},
		{
			Require: exprVEXVerified,
			Message: msgVEXMustBeVerified,
		},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		b.Fatalf("compile error: %v", err)
	}

	vars := celengine.BuildVars(
		testImageRef, testRegistry, testRepository, testDigest, testNamespace,
		types.PassResult(types.CheckTypeSLSA, "ok"),
		types.PassResult(types.CheckTypeVEX, "ok"),
		nil,
		types.PassResult(types.CheckTypeSBOM, "ok"),
		nil,
		nil,
		nil, nil, nil, nil,
		nil,
	)

	b.ResetTimer()

	for range b.N {
		celengine.Evaluate(compiled, vars)
	}
}

func BenchmarkEvaluateWithMatch(b *testing.B) {
	rules := []celengine.Rule{
		{
			Match:   "image.registry == 'docker.io'",
			Require: exprFalse,
		},
		{
			Match:   exprMatchGHCR,
			Require: exprSLSAVerified + " && " + exprVEXVerified,
		},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		b.Fatalf("compile error: %v", err)
	}

	vars := celengine.BuildVars(
		testImageRef, testRegistry, testRepository, testDigest, testNamespace,
		types.PassResult(types.CheckTypeSLSA, "ok"),
		types.PassResult(types.CheckTypeVEX, "ok"),
		nil,
		types.PassResult(types.CheckTypeSBOM, "ok"),
		nil,
		nil,
		nil, nil, nil, nil,
		nil,
	)

	b.ResetTimer()

	for range b.N {
		celengine.Evaluate(compiled, vars)
	}
}
