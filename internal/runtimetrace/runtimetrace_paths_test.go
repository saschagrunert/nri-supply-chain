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

package runtimetrace_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/runtimetrace"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const (
	testShadowPath = "/etc/shadow"
	testEtcGlob    = "/etc/**"
)

func TestVerifyForbiddenFileEncodings(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"file localhost host":     `{"uri":"file://localhost/etc/shadow"}`,
		"file without slashes":    `{"uri":"file:/etc/shadow"}`,
		"percent encoded path":    `{"uri":"file:///etc/sh%61dow"}`,
		"double slashes":          `{"uri":"file:////etc//shadow"}`,
		"dot segment in name":     `{"name":"/./etc/shadow"}`,
		"parent segment in uri":   `{"uri":"/tmp/../etc/shadow"}`,
		"uppercase scheme":        `{"uri":"FILE:///etc/shadow"}`,
		"download location":       `{"name":"shadow","downloadLocation":"file:///etc/shadow"}`,
		"percent encoded raw uri": `{"uri":"/etc/sh%61dow"}`,
	}

	for name, file := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			predicate := `{"monitor":{"type":"` + testMonitorType + `"},` +
				`"monitorLog":{"fileAccess":[` + file + `]}}`
			att := testutil.WrapInToto(t, json.RawMessage(predicate), testDigest, testPredicateType)

			result, err := runtimetrace.Verify(context.Background(), att, &policy.Policy{
				RuntimeTrace: &policy.RuntimeTracePolicy{
					ForbiddenFilePatterns: []string{testShadowPath},
				},
			}, testDigest)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, false, result.Passed)
			testutil.AssertContains(t, result.Detail, testShadowPath)
		})
	}
}

func TestVerifyForbiddenFileUnparsableURLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		file    string
		pattern string
	}{
		{"invalid escape in name", `{"uri":"file:///etc/ssl/private/100%.key"}`, testEtcGlob},
		{"invalid escape in directory", `{"uri":"file:///etc/%zz/shadow"}`, testEtcGlob},
		{"trailing percent", `{"uri":"file:///etc/shadow%"}`, testEtcGlob},
		{"control character", `{"uri":"file:///etc/shadow\u0001junk"}`, testEtcGlob},
		{
			"invalid escape with dot segments",
			`{"uri":"file://host/tmp/%zz/../../etc/shadow"}`,
			testShadowPath,
		},
		{"nul byte truncates the path", `{"uri":"file:///etc/shadow%00.txt"}`, testShadowPath},
		{
			"raw nul byte truncates the path",
			`{"uri":"file:///etc/shadow\u0000.txt"}`,
			testShadowPath,
		},
		{"plain path with invalid escape", `{"name":"/etc/%zz/../shadow"}`, testShadowPath},
		{"file URL without a path", `{"uri":"file://"}`, testShadowPath},
		{"query after the path", `{"uri":"file:///etc/shadow?x"}`, testShadowPath},
		{"fragment after the path", `{"uri":"file:///etc/shadow#x"}`, testShadowPath},
		{"query with invalid escape", `{"uri":"file:///etc/shadow?%zz"}`, testShadowPath},
		{"query without slashes", `{"uri":"file:/etc/shadow?x"}`, testShadowPath},
		{"file URL with only a query", `{"uri":"file:?x"}`, testShadowPath},
		{"file URL with host and only a query", `{"uri":"file://host?x"}`, testShadowPath},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			predicate := `{"monitor":{"type":"` + testMonitorType + `"},` +
				`"monitorLog":{"fileAccess":[` + test.file + `]}}`
			att := testutil.WrapInToto(t, json.RawMessage(predicate), testDigest, testPredicateType)

			result, err := runtimetrace.Verify(context.Background(), att, &policy.Policy{
				RuntimeTrace: &policy.RuntimeTracePolicy{
					ForbiddenFilePatterns: []string{test.pattern},
				},
			}, testDigest)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, false, result.Passed)
		})
	}
}

func TestVerifyAllowedFileEncodings(t *testing.T) {
	t.Parallel()

	predicate := `{"monitor":{"type":"` + testMonitorType + `"},` +
		`"monitorLog":{"fileAccess":[{"uri":"file:///etc/shadow.d/notes"},` +
		`{"name":"/usr/bin/gcc","downloadLocation":"https://example.com/gcc"}]}}`
	att := testutil.WrapInToto(t, json.RawMessage(predicate), testDigest, testPredicateType)

	result, err := runtimetrace.Verify(context.Background(), att, &policy.Policy{
		RuntimeTrace: &policy.RuntimeTracePolicy{
			ForbiddenFilePatterns: []string{testShadowPath},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)
}
