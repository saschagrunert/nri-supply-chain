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

// Package runtimetrace provides runtime trace attestation verification for supply chain checks.
package runtimetrace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const checkType = types.CheckTypeRuntimeTrace

var (
	// ErrInvalidRuntimeTrace indicates the runtime trace attestation could not be parsed.
	ErrInvalidRuntimeTrace = errors.New("invalid runtime trace attestation")

	// ErrUntrustedMonitor indicates the monitor type is not trusted.
	ErrUntrustedMonitor = errors.New("monitor type not trusted")

	// ErrForbiddenFileAccess indicates a forbidden file access was detected.
	ErrForbiddenFileAccess = errors.New("forbidden file access detected")

	// ErrStaleRuntimeTrace indicates the runtime trace attestation is older
	// than the maximum allowed age.
	ErrStaleRuntimeTrace = errors.New("runtime trace attestation is stale")

	// ErrFutureTimestamp indicates the runtime trace timestamp is in the future.
	ErrFutureTimestamp = errors.New("runtime trace timestamp is in the future")
)

type runtimeTracePredicate struct {
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

// Verify checks a single runtime trace attestation against the given policy.
func Verify( //nolint:revive // ctx reserved for future context-aware logging
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	predicate, err := intoto.VerifySubjectAndExtractPredicate(att, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRuntimeTrace, err)
	}

	return verifyRuntimeTracePredicate(predicate, pol)
}

// VerifyMultiple checks multiple runtime trace attestations. Any policy
// violation in any document causes failure.
func VerifyMultiple( //nolint:cyclop // metadata accumulation adds branches
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	var (
		failDetails  []string
		verifyErrors []string
		anyValid     bool
		mergedMeta   map[string]any
	)

	for _, att := range attestations {
		result, err := Verify(ctx, att, pol, imageDigest)
		if err != nil {
			verifyErrors = append(verifyErrors, err.Error())

			continue
		}

		anyValid = true

		if !result.Passed && result.Status == types.StatusFail {
			failDetails = append(failDetails, result.Detail)
		}

		if result.Passed && result.Metadata != nil {
			if mergedMeta == nil {
				mergedMeta = make(map[string]any)
			}

			mergeTraceMeta(mergedMeta, result.Metadata)
		}
	}

	if len(failDetails) > 0 {
		return failResult(strings.Join(failDetails, "; ")), nil
	}

	if len(attestations) > 0 && !anyValid {
		return failResult(
			"all runtime trace documents failed verification: " + strings.Join(
				verifyErrors,
				"; ",
			),
		), nil
	}

	result := passResult()
	result.Metadata = mergedMeta

	return result, nil
}

func verifyRuntimeTracePredicate(
	predicate []byte, pol *policy.Policy,
) (*types.CheckResult, error) {
	var pred runtimeTracePredicate

	err := json.Unmarshal(predicate, &pred)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRuntimeTrace, err)
	}

	fileNames := collectFileNames(pred.MonitorLog.FileAccess)

	meta := map[string]any{
		"monitorType":     pred.Monitor.Type,
		"processCount":    int64(len(pred.MonitorLog.Process)),
		"networkCount":    int64(len(pred.MonitorLog.Network)),
		"fileAccessCount": int64(len(pred.MonitorLog.FileAccess)),
		"fileNames":       strings.Join(fileNames, ","),
	}

	if pol.RuntimeTrace == nil {
		result := passResult()
		result.Metadata = meta

		return result, nil
	}

	if len(pol.RuntimeTrace.TrustedMonitors) > 0 {
		err = verifyMonitorType(pred.Monitor.Type, pol.RuntimeTrace.TrustedMonitors)
		if err != nil {
			result := failResult(err.Error())
			result.Metadata = meta

			return result, nil
		}
	}

	if len(pol.RuntimeTrace.ForbiddenFilePatterns) > 0 {
		err = checkForbiddenFiles(
			pred.MonitorLog.FileAccess, pol.RuntimeTrace.ForbiddenFilePatterns,
		)
		if err != nil {
			result := failResult(err.Error())
			result.Metadata = meta

			return result, nil
		}
	}

	err = verifyFreshness(pred.Metadata, pol)
	if err != nil {
		result := failResult(err.Error())
		result.Metadata = meta

		return result, nil
	}

	result := passResult()
	result.Metadata = meta

	return result, nil
}

func collectFileNames(files []traceFileAccess) []string {
	names := make([]string, 0, len(files))

	for idx := range files {
		name := files[idx].Name
		if name == "" {
			name = files[idx].URI
		}

		if name != "" {
			names = append(names, name)
		}
	}

	return names
}

func verifyMonitorType(monitorType string, trusted []string) error {
	if monitorType == "" {
		return fmt.Errorf("%w: monitor type not specified in attestation", ErrUntrustedMonitor)
	}

	for _, pattern := range trusted {
		matched, err := glob.Match(pattern, monitorType)
		if err != nil {
			return fmt.Errorf("invalid monitor pattern %q: %w", pattern, err)
		}

		if matched {
			return nil
		}
	}

	return fmt.Errorf("%w: %q", ErrUntrustedMonitor, monitorType)
}

func checkForbiddenFiles(files []traceFileAccess, patterns []string) error {
	for idx := range files {
		name := files[idx].Name
		if name == "" {
			name = files[idx].URI
		}

		if name == "" {
			continue
		}

		for _, pattern := range patterns {
			matched, err := glob.Match(pattern, name)
			if err != nil {
				return fmt.Errorf("invalid file pattern %q: %w", pattern, err)
			}

			if matched {
				return fmt.Errorf("%w: %q matches %q", ErrForbiddenFileAccess, name, pattern)
			}
		}
	}

	return nil
}

func verifyFreshness(metadata *traceMetadata, pol *policy.Policy) error {
	maxAgeConfigured := pol.RuntimeTrace != nil && pol.RuntimeTrace.MaxAge != ""

	if metadata == nil || metadata.BuildFinishedOn == nil {
		if maxAgeConfigured {
			return fmt.Errorf(
				"%w: no build finished timestamp in attestation",
				ErrStaleRuntimeTrace,
			)
		}

		return nil
	}

	if !maxAgeConfigured {
		return nil
	}

	maxAge := &pol.RuntimeTrace.MaxAgeDuration

	//nolint:wrapcheck // VerifyFreshness wraps the caller's sentinel errors
	return types.VerifyFreshness(
		*metadata.BuildFinishedOn,
		maxAge,
		"finished",
		ErrFutureTimestamp,
		ErrStaleRuntimeTrace,
		ErrStaleRuntimeTrace,
	)
}

func mergeTraceMeta(dst, src map[string]any) {
	for key, val := range src {
		existing, hasPrev := dst[key]
		if !hasPrev {
			dst[key] = val

			continue
		}

		switch key {
		case "processCount", "networkCount", "fileAccessCount":
			if dstCount, ok := existing.(int64); ok {
				if srcCount, ok := val.(int64); ok {
					dst[key] = dstCount + srcCount
				}
			}
		case "monitorType", "fileNames":
			if dstStr, ok := existing.(string); ok {
				if srcStr, ok := val.(string); ok {
					dst[key] = types.MergeCommaSeparated(dstStr, srcStr)
				}
			}
		default:
		}
	}
}

func passResult() *types.CheckResult {
	return types.PassResult(checkType, "runtime trace verification passed")
}

func failResult(detail string) *types.CheckResult {
	return types.FailResult(checkType, detail, nil)
}
