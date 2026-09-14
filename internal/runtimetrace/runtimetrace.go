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
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/checker"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

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

	errMissingMonitorType = errors.New("monitor.type is required")
	errMissingMonitorLog  = errors.New("monitorLog is required")
)

const fileScheme = "file"

type runtimeTracePredicate struct {
	Monitor    traceMonitor     `json:"monitor"`
	MonitorLog *traceMonitorLog `json:"monitorLog"`
	Metadata   *traceMetadata   `json:"metadata,omitempty"`
}

type traceMonitor struct {
	Type string `json:"type"`
}

type traceMonitorLog struct {
	Process    []json.RawMessage `json:"process,omitempty"`
	Network    []json.RawMessage `json:"network,omitempty"`
	FileAccess []traceFileAccess `json:"fileAccess,omitempty"`
}

// traceFileAccess is the ResourceDescriptor subset used for file access
// checks.
type traceFileAccess struct {
	Name             string            `json:"name,omitempty"`
	URI              string            `json:"uri,omitempty"`
	DownloadLocation string            `json:"downloadLocation,omitempty"`
	Digest           map[string]string `json:"digest,omitempty"`
}

type traceMetadata struct {
	BuildStartedOn  *time.Time `json:"buildStartedOn,omitempty"`
	BuildFinishedOn *time.Time `json:"buildFinishedOn,omitempty"`
}

//nolint:gochecknoglobals // immutable check declaration
var spec = &checker.Spec[runtimeTracePredicate]{
	Info: checker.Info{
		Type:  types.CheckTypeRuntimeTrace,
		Label: "runtime trace",
	},
	Aggregation: checker.AllMustPass,
	ErrInvalid:  ErrInvalidRuntimeTrace,
	Validate:    validatePredicate,
	Meta:        predicateMeta,
	Freshness: &checker.Freshness[runtimeTracePredicate]{
		Timestamp: func(pred *runtimeTracePredicate) *time.Time {
			if pred.Metadata == nil {
				return nil
			}

			return pred.Metadata.BuildFinishedOn
		},
		MaxAge: func(pol *policy.Policy) *time.Duration {
			if pol.RuntimeTrace == nil || pol.RuntimeTrace.MaxAge == "" {
				return nil
			}

			return &pol.RuntimeTrace.MaxAgeDuration
		},
		Label:     "build finished",
		ErrStale:  ErrStaleRuntimeTrace,
		ErrFuture: ErrFutureTimestamp,
	},
	Rules: []checker.Rule[runtimeTracePredicate]{
		checkMonitorType,
		checkForbiddenFiles,
	},
	Merge: map[string]checker.MergeFunc{
		"processCount":    checker.Sum(),
		"networkCount":    checker.Sum(),
		"fileAccessCount": checker.Sum(),
		"monitorType":     checker.CSV(),
		"fileNames":       checker.CSV(),
	},
}

// Info returns the check type and label of the runtime trace check.
func Info() checker.Info {
	return spec.Info
}

// Verify checks a single runtime trace attestation against the given policy.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.Verify(ctx, att, pol, imageDigest)
}

// VerifyMultiple checks multiple runtime trace attestations. Any policy
// violation or invalid document causes failure.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.VerifyMultiple(ctx, attestations, pol, imageDigest)
}

func validatePredicate(pred *runtimeTracePredicate) error {
	if strings.TrimSpace(pred.Monitor.Type) == "" {
		return errMissingMonitorType
	}

	if pred.MonitorLog == nil {
		return errMissingMonitorLog
	}

	return nil
}

func predicateMeta(pred *runtimeTracePredicate) map[string]any {
	return map[string]any{
		"monitorType":     pred.Monitor.Type,
		"processCount":    int64(len(pred.MonitorLog.Process)),
		"networkCount":    int64(len(pred.MonitorLog.Network)),
		"fileAccessCount": int64(len(pred.MonitorLog.FileAccess)),
		"fileNames":       strings.Join(collectFileNames(pred.MonitorLog.FileAccess), ","),
	}
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

func checkMonitorType(pred *runtimeTracePredicate, pol *policy.Policy) string {
	if pol.RuntimeTrace == nil || len(pol.RuntimeTrace.TrustedMonitors) == 0 {
		return ""
	}

	for _, pattern := range pol.RuntimeTrace.TrustedMonitors {
		matched, err := glob.Match(pattern, pred.Monitor.Type)
		if err != nil {
			return fmt.Sprintf("invalid monitor pattern %q: %s", pattern, err)
		}

		if matched {
			return ""
		}
	}

	return fmt.Sprintf("%s: %q", ErrUntrustedMonitor, pred.Monitor.Type)
}

// checkForbiddenFiles matches the name, URI, and download location of every
// file access against the forbidden patterns, so a benign name cannot hide a
// forbidden URI. File URIs are also matched as their decoded, cleaned path so
// that encodings such as file://localhost/, percent escapes (valid or not),
// NUL bytes, or dot segments cannot evade a pattern. A file URL without a
// derivable path fails the check.
func checkForbiddenFiles(pred *runtimeTracePredicate, pol *policy.Policy) string {
	if pol.RuntimeTrace == nil || len(pol.RuntimeTrace.ForbiddenFilePatterns) == 0 {
		return ""
	}

	for idx := range pred.MonitorLog.FileAccess {
		candidates, unresolved := fileCandidates(&pred.MonitorLog.FileAccess[idx])
		if unresolved != "" {
			return fmt.Sprintf(
				"%s: cannot determine the path of %q",
				ErrForbiddenFileAccess,
				unresolved,
			)
		}

		for _, candidate := range candidates {
			violation := matchForbidden(candidate, pol.RuntimeTrace.ForbiddenFilePatterns)
			if violation != "" {
				return violation
			}
		}
	}

	return ""
}

// fileCandidates returns every spelling of a file access that forbidden
// patterns are matched against. unresolved is the first file URL for which
// no path could be derived.
func fileCandidates(file *traceFileAccess) (candidates []string, unresolved string) {
	add := func(value string) {
		if value != "" && !slices.Contains(candidates, value) {
			candidates = append(candidates, value)
		}
	}

	for _, raw := range []string{file.Name, file.URI, file.DownloadLocation} {
		if raw == "" {
			continue
		}

		add(raw)

		decoded, derived := decodedPaths(raw)
		if !derived && unresolved == "" {
			unresolved = raw
		}

		for _, value := range decoded {
			add(value)
		}
	}

	return candidates, unresolved
}

// decodedPaths returns the cleaned filesystem paths a file reference may
// denote: the path of a file URL (any host, with or without slashes after
// the scheme), and for plain paths the cleaned and percent-decoded forms.
// File URLs that url.Parse rejects (invalid percent escapes, control
// characters) are split by hand. derived is false for a file URL without a
// path.
func decodedPaths(raw string) (paths []string, derived bool) {
	add := func(value string) {
		paths = append(paths, cleanedPathForms(value)...)
	}

	if scheme, rest, found := strings.Cut(
		raw,
		":",
	); found &&
		strings.EqualFold(scheme, fileScheme) {
		parsed, err := url.Parse(fileScheme + ":" + rest)
		if err == nil {
			filePath := parsed.Path
			if filePath == "" && parsed.Opaque != "" {
				filePath = lenientUnescape(parsed.Opaque)
			}

			add(filePath)
		}

		manual := fileURLPath(rest)
		add(manual)
		add(lenientUnescape(manual))

		return paths, len(paths) > 0
	}

	add(raw)
	add(lenientUnescape(raw))

	return paths, true
}

// fileURLPath returns the path of a file URL without its "file:" scheme,
// removing a query or fragment and an optional "//authority" part.
func fileURLPath(rest string) string {
	if end := strings.IndexAny(rest, "?#"); end >= 0 {
		rest = rest[:end]
	}

	authorityAndPath, hasAuthority := strings.CutPrefix(rest, "//")
	if !hasAuthority {
		return rest
	}

	slash := strings.IndexByte(authorityAndPath, '/')
	if slash < 0 {
		return ""
	}

	return authorityAndPath[slash:]
}

// cleanedPathForms returns the cleaned path and, when the path contains a
// NUL byte, the cleaned path up to that byte, which is what the kernel
// would open.
func cleanedPathForms(value string) []string {
	var forms []string

	if value != "" {
		forms = append(forms, path.Clean(value))
	}

	if before, _, hasNUL := strings.Cut(value, "\x00"); hasNUL && before != "" {
		forms = append(forms, path.Clean(before))
	}

	return forms
}

// lenientUnescape decodes valid %XX escapes and keeps invalid ones verbatim.
func lenientUnescape(value string) string {
	if !strings.Contains(value, "%") {
		return value
	}

	var builder strings.Builder

	builder.Grow(len(value))

	for idx := 0; idx < len(value); idx++ {
		if value[idx] == '%' && idx+2 < len(value) {
			decoded, err := strconv.ParseUint(value[idx+1:idx+3], 16, 8)
			if err == nil {
				builder.WriteByte(byte(decoded))

				idx += 2

				continue
			}
		}

		builder.WriteByte(value[idx])
	}

	return builder.String()
}

func matchForbidden(candidate string, patterns []string) string {
	for _, pattern := range patterns {
		matched, err := glob.Match(pattern, candidate)
		if err != nil {
			return fmt.Sprintf("invalid file pattern %q: %s", pattern, err)
		}

		if matched {
			return fmt.Sprintf("%s: %q matches %q", ErrForbiddenFileAccess, candidate, pattern)
		}
	}

	return ""
}
