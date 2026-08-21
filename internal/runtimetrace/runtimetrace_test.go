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
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/runtimetrace"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testDigest           = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testDigestAlgo       = "sha256"
	testInTotoType       = "https://in-toto.io/Statement/v1"
	testSubjectName      = "test-image"
	testPredicateType    = "https://in-toto.io/attestation/runtime-trace/v0.1"
	testMonitorType      = "https://example.com/monitors/ebpf"
	testTrustedPattern   = "https://example.com/monitors/*"
	testForbiddenTmpGlob = "/tmp/**"
)

type inTotoWrapper struct {
	Type          string          `json:"_type"` //nolint:tagliatelle // In-toto spec field name.
	Subject       []inTotoSubj    `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

type inTotoSubj struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type tracePredicate struct {
	Monitor    traceMonitor    `json:"monitor"`
	MonitorLog traceMonitorLog `json:"monitorLog"`
	Metadata   *traceMetadata  `json:"metadata,omitempty"`
}

type traceMonitor struct {
	Type string `json:"type"`
}

type traceMonitorLog struct {
	Process    []json.RawMessage `json:"process,omitempty"`
	Network    []json.RawMessage `json:"network,omitempty"`
	FileAccess []traceFileAccess `json:"fileAccess,omitempty"`
}

type traceFileAccess struct {
	Name   string            `json:"name,omitempty"`
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

type traceMetadata struct {
	BuildStartedOn  *time.Time `json:"buildStartedOn,omitempty"`
	BuildFinishedOn *time.Time `json:"buildFinishedOn,omitempty"`
}

func validPredicate() tracePredicate {
	return tracePredicate{
		Monitor: traceMonitor{Type: testMonitorType},
		MonitorLog: traceMonitorLog{
			Process: []json.RawMessage{
				json.RawMessage(`{"pid": 1, "cmd": "make"}`),
			},
			Network: []json.RawMessage{
				json.RawMessage(`{"dst": "registry.example.com:443"}`),
			},
			FileAccess: []traceFileAccess{
				{Name: "/usr/bin/gcc", URI: "", Digest: nil},
				{Name: "/tmp/build/output.o", URI: "", Digest: nil},
			},
		},
		Metadata: nil,
	}
}

func wrapInToto(t *testing.T, doc any, digest string) []byte {
	t.Helper()

	predBytes := testutil.MustMarshal(t, doc)

	wrapper := inTotoWrapper{
		Type: testInTotoType,
		Subject: []inTotoSubj{
			{
				Name:   testSubjectName,
				Digest: map[string]string{testDigestAlgo: digest[len(testDigestAlgo)+1:]},
			},
		},
		PredicateType: testPredicateType,
		Predicate:     predBytes,
	}

	return testutil.MustMarshal(t, wrapper)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		doc        tracePredicate
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "valid trace with no policy passes",
			doc:        validPredicate(),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "trusted monitor passes",
			doc:  validPredicate(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					RuntimeTrace: &policy.RuntimeTracePolicy{
						TrustedMonitors: []string{testTrustedPattern},
					},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "untrusted monitor fails",
			doc:  validPredicate(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					RuntimeTrace: &policy.RuntimeTracePolicy{
						TrustedMonitors: []string{"https://other.com/monitors/*"},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "forbidden file access pattern fails",
			doc:  validPredicate(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					RuntimeTrace: &policy.RuntimeTracePolicy{
						ForbiddenFilePatterns: []string{testForbiddenTmpGlob},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "allowed file access passes",
			doc:  validPredicate(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					RuntimeTrace: &policy.RuntimeTracePolicy{
						ForbiddenFilePatterns: []string{"/etc/shadow"},
					},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := wrapInToto(t, test.doc, testDigest)

			result, err := runtimetrace.Verify(context.Background(), att, test.pol, testDigest)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)
			testutil.AssertEqual(t, test.wantStatus, result.Status)
		})
	}
}

func TestVerifyCheckType(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validPredicate(), testDigest)

	result, err := runtimetrace.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	testutil.AssertEqual(t, types.CheckType("runtimetrace"), result.Type)
}

func TestVerifyMetadata(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validPredicate(), testDigest)

	result, err := runtimetrace.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Metadata == nil {
		t.Fatal("expected metadata on runtime trace result")
	}

	monitorType, ok := result.Metadata["monitorType"].(string)
	if !ok || monitorType != testMonitorType {
		t.Errorf("monitorType = %v, want %s", result.Metadata["monitorType"], testMonitorType)
	}

	processCount, ok := result.Metadata["processCount"].(int64)
	if !ok || processCount != 1 {
		t.Errorf("processCount = %v, want 1", result.Metadata["processCount"])
	}

	networkCount, ok := result.Metadata["networkCount"].(int64)
	if !ok || networkCount != 1 {
		t.Errorf("networkCount = %v, want 1", result.Metadata["networkCount"])
	}

	fileAccessCount, ok := result.Metadata["fileAccessCount"].(int64)
	if !ok || fileAccessCount != 2 {
		t.Errorf("fileAccessCount = %v, want 2", result.Metadata["fileAccessCount"])
	}

	fileNames, ok := result.Metadata["fileNames"].(string)
	if !ok {
		t.Fatal("expected fileNames to be a string")
	}

	if !strings.Contains(fileNames, "/usr/bin/gcc") {
		t.Errorf("fileNames = %q, want to contain /usr/bin/gcc", fileNames)
	}

	if !strings.Contains(fileNames, "/tmp/build/output.o") {
		t.Errorf("fileNames = %q, want to contain /tmp/build/output.o", fileNames)
	}
}

func TestVerifyMalformedPayloads(t *testing.T) {
	t.Parallel()

	t.Run("empty payload", func(t *testing.T) {
		t.Parallel()

		_, err := runtimetrace.Verify(context.Background(), []byte{}, &policy.Policy{}, testDigest)
		if !errors.Is(err, runtimetrace.ErrInvalidRuntimeTrace) {
			t.Errorf("expected ErrInvalidRuntimeTrace, got %v", err)
		}
	})

	t.Run("nil payload", func(t *testing.T) {
		t.Parallel()

		_, err := runtimetrace.Verify(context.Background(), nil, &policy.Policy{}, testDigest)
		if !errors.Is(err, runtimetrace.ErrInvalidRuntimeTrace) {
			t.Errorf("expected ErrInvalidRuntimeTrace, got %v", err)
		}
	})

	t.Run("truncated JSON", func(t *testing.T) {
		t.Parallel()

		_, err := runtimetrace.Verify(
			context.Background(), []byte(`{"subject":[`), &policy.Policy{}, testDigest,
		)
		if !errors.Is(err, runtimetrace.ErrInvalidRuntimeTrace) {
			t.Errorf("expected ErrInvalidRuntimeTrace, got %v", err)
		}
	})
}

func TestVerifySubjectEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("subject with mismatched digest", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validPredicate(), testDigest)

		_, err := runtimetrace.Verify(context.Background(),
			att, &policy.Policy{},
			"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		)
		if !errors.Is(err, intoto.ErrSubjectMismatch) {
			t.Errorf("expected ErrSubjectMismatch, got %v", err)
		}
	})

	t.Run("empty digest with subjects rejects for binding", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validPredicate(), testDigest)

		_, err := runtimetrace.Verify(context.Background(), att, &policy.Policy{}, "")
		if !errors.Is(err, intoto.ErrNoDigestBinding) {
			t.Errorf("expected ErrNoDigestBinding, got %v", err)
		}
	})
}

func TestVerifyMultiple(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		docs       []tracePredicate
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "single valid passes",
			docs:       []tracePredicate{validPredicate()},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "all must pass - forbidden file fails all",
			docs: []tracePredicate{validPredicate()},
			pol: &policy.Policy{
				Sections: policy.Sections{
					RuntimeTrace: &policy.RuntimeTracePolicy{
						ForbiddenFilePatterns: []string{testForbiddenTmpGlob},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "empty attestation list passes",
			docs:       []tracePredicate{},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			attestations := make([][]byte, len(test.docs))
			for idx := range test.docs {
				attestations[idx] = wrapInToto(t, test.docs[idx], testDigest)
			}

			result, err := runtimetrace.VerifyMultiple(
				context.Background(),
				attestations,
				test.pol,
				testDigest,
			)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)
			testutil.AssertEqual(t, test.wantStatus, result.Status)
		})
	}
}

func TestVerifyMultipleMergesMetadata(t *testing.T) {
	t.Parallel()

	doc1 := tracePredicate{
		Monitor: traceMonitor{Type: testMonitorType},
		MonitorLog: traceMonitorLog{
			Process: nil,
			Network: nil,
			FileAccess: []traceFileAccess{
				{Name: "/usr/bin/gcc", URI: "", Digest: nil},
			},
		},
		Metadata: nil,
	}
	doc2 := tracePredicate{
		Monitor: traceMonitor{Type: testMonitorType},
		MonitorLog: traceMonitorLog{
			Process: []json.RawMessage{
				json.RawMessage(`{"pid": 1}`),
				json.RawMessage(`{"pid": 2}`),
			},
			Network: nil,
			FileAccess: []traceFileAccess{
				{Name: "/usr/bin/ld", URI: "", Digest: nil},
			},
		},
		Metadata: nil,
	}

	attestations := [][]byte{
		wrapInToto(t, doc1, testDigest),
		wrapInToto(t, doc2, testDigest),
	}

	result, err := runtimetrace.VerifyMultiple(
		context.Background(), attestations, &policy.Policy{}, testDigest,
	)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Detail)
	}

	if result.Metadata == nil {
		t.Fatal("expected metadata on merged result")
	}

	fileAccessCount, ok := result.Metadata["fileAccessCount"].(int64)
	if !ok || fileAccessCount != 2 {
		t.Errorf("fileAccessCount = %v, want 2", result.Metadata["fileAccessCount"])
	}

	processCount, ok := result.Metadata["processCount"].(int64)
	if !ok || processCount != 2 {
		t.Errorf("processCount = %v, want 2", result.Metadata["processCount"])
	}

	fileNames, ok := result.Metadata["fileNames"].(string)
	if !ok {
		t.Fatal("expected fileNames to be a string")
	}

	if !strings.Contains(fileNames, "/usr/bin/gcc") {
		t.Errorf("fileNames = %q, want to contain /usr/bin/gcc", fileNames)
	}

	if !strings.Contains(fileNames, "/usr/bin/ld") {
		t.Errorf("fileNames = %q, want to contain /usr/bin/ld", fileNames)
	}
}

func TestVerifyMultipleEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("nil attestation slice", func(t *testing.T) {
		t.Parallel()

		result, err := runtimetrace.VerifyMultiple(
			context.Background(),
			nil,
			&policy.Policy{},
			testDigest,
		)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass for nil attestation slice, got: %s", result.Detail)
		}
	})

	t.Run("all invalid returns fail with parse errors", func(t *testing.T) {
		t.Parallel()

		attestations := [][]byte{
			[]byte("bad json 1"),
			[]byte("bad json 2"),
		}

		result, err := runtimetrace.VerifyMultiple(
			context.Background(),
			attestations,
			&policy.Policy{},
			testDigest,
		)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail when all documents are invalid")
		}

		testutil.AssertEqual(t, types.StatusFail, result.Status)
	})

	t.Run("mix of valid and invalid with valid passing", func(t *testing.T) {
		t.Parallel()

		attestations := [][]byte{
			[]byte("invalid json"),
			wrapInToto(t, validPredicate(), testDigest),
		}

		result, err := runtimetrace.VerifyMultiple(
			context.Background(),
			attestations,
			&policy.Policy{},
			testDigest,
		)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass with valid doc, got: %s", result.Detail)
		}
	})
}

func TestVerifyFreshness(t *testing.T) {
	t.Parallel()

	staleTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	freshTime := time.Now().Add(-10 * time.Minute).UTC()

	tests := []struct {
		name       string
		doc        tracePredicate
		pol        *policy.Policy
		wantPassed bool
		wantSubstr string
	}{
		{
			name: "stale trace fails",
			doc: tracePredicate{
				Monitor:    traceMonitor{Type: testMonitorType},
				MonitorLog: traceMonitorLog{}, //nolint:exhaustruct_v5 // test omits log entries
				Metadata: &traceMetadata{
					BuildStartedOn:  nil,
					BuildFinishedOn: &staleTime,
				},
			},
			pol: &policy.Policy{
				Sections: policy.Sections{
					RuntimeTrace: &policy.RuntimeTracePolicy{
						MaxAge:         "1h",
						MaxAgeDuration: time.Hour,
					},
				},
			},
			wantPassed: false,
			wantSubstr: "stale",
		},
		{
			name: "fresh trace passes",
			doc: tracePredicate{
				Monitor:    traceMonitor{Type: testMonitorType},
				MonitorLog: traceMonitorLog{}, //nolint:exhaustruct_v5 // test omits log entries
				Metadata: &traceMetadata{
					BuildStartedOn:  nil,
					BuildFinishedOn: &freshTime,
				},
			},
			pol: &policy.Policy{
				Sections: policy.Sections{
					RuntimeTrace: &policy.RuntimeTracePolicy{
						MaxAge:         "1h",
						MaxAgeDuration: time.Hour,
					},
				},
			},
			wantPassed: true,
			wantSubstr: "",
		},
		{
			name: "no timestamp with maxAge fails",
			doc: tracePredicate{
				Monitor:    traceMonitor{Type: testMonitorType},
				MonitorLog: traceMonitorLog{Process: nil, Network: nil, FileAccess: nil},
				Metadata:   nil,
			},
			pol: &policy.Policy{
				Sections: policy.Sections{
					RuntimeTrace: &policy.RuntimeTracePolicy{
						MaxAge:         "1h",
						MaxAgeDuration: time.Hour,
					},
				},
			},
			wantPassed: false,
			wantSubstr: "no build finished timestamp",
		},
		{
			name: "no timestamp without maxAge passes",
			doc: tracePredicate{
				Monitor:    traceMonitor{Type: testMonitorType},
				MonitorLog: traceMonitorLog{Process: nil, Network: nil, FileAccess: nil},
				Metadata:   nil,
			},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantSubstr: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := wrapInToto(t, test.doc, testDigest)

			result, err := runtimetrace.Verify(context.Background(), att, test.pol, testDigest)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)

			if test.wantSubstr != "" && !strings.Contains(result.Detail, test.wantSubstr) {
				t.Errorf("expected detail to contain %q, got %q", test.wantSubstr, result.Detail)
			}
		})
	}
}

func TestVerifyUntrustedMonitorDetailMessage(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validPredicate(), testDigest)

	result, err := runtimetrace.Verify(context.Background(), att, &policy.Policy{
		Sections: policy.Sections{
			RuntimeTrace: &policy.RuntimeTracePolicy{
				TrustedMonitors: []string{"https://other.com/*"},
			},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Fatal("expected fail")
	}

	if !strings.Contains(result.Detail, "not trusted") {
		t.Errorf("expected detail to mention not trusted, got %q", result.Detail)
	}

	if !strings.Contains(result.Detail, testMonitorType) {
		t.Errorf("expected detail to contain monitor type, got %q", result.Detail)
	}
}

func TestVerifyForbiddenFileDetailMessage(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validPredicate(), testDigest)

	result, err := runtimetrace.Verify(context.Background(), att, &policy.Policy{
		Sections: policy.Sections{
			RuntimeTrace: &policy.RuntimeTracePolicy{
				ForbiddenFilePatterns: []string{testForbiddenTmpGlob},
			},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Fatal("expected fail")
	}

	if !strings.Contains(result.Detail, "forbidden") {
		t.Errorf("expected detail to mention forbidden, got %q", result.Detail)
	}

	if !strings.Contains(result.Detail, "/tmp/build/output.o") {
		t.Errorf("expected detail to contain file name, got %q", result.Detail)
	}
}

func TestVerifyFileAccessURI(t *testing.T) {
	t.Parallel()

	doc := tracePredicate{
		Monitor: traceMonitor{Type: testMonitorType},
		MonitorLog: traceMonitorLog{
			Process: nil,
			Network: nil,
			FileAccess: []traceFileAccess{
				{Name: "", URI: "file:///etc/passwd", Digest: nil},
			},
		},
		Metadata: nil,
	}
	att := wrapInToto(t, doc, testDigest)

	result, err := runtimetrace.Verify(context.Background(), att, &policy.Policy{
		Sections: policy.Sections{
			RuntimeTrace: &policy.RuntimeTracePolicy{
				ForbiddenFilePatterns: []string{"file:///etc/*"},
			},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Fatal("expected fail for forbidden URI-based file access")
	}

	fileNames, ok := result.Metadata["fileNames"].(string)
	if !ok || !strings.Contains(fileNames, "file:///etc/passwd") {
		t.Errorf("fileNames = %v, want to contain file:///etc/passwd", result.Metadata["fileNames"])
	}
}

func TestVerifyCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := runtimetrace.Verify(ctx, nil, nil, "")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
