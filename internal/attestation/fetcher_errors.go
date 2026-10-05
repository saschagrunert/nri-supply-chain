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

package attestation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"

	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// referrerOutcome classifies what happened to a single referrer candidate.
type referrerOutcome int

const (
	// outcomeVerified means the referrer produced a verified attestation.
	outcomeVerified referrerOutcome = iota
	// outcomeUnverified means the referrer was collected for a check that
	// verifies it later (Notation signatures). It does not count as verified.
	outcomeUnverified
	// outcomeSkipped means the referrer is not relevant (for example gone).
	outcomeSkipped
	// outcomeVerifyFailed means signed material or referrer content was found
	// but did not verify or could not be parsed.
	outcomeVerifyFailed
	// outcomeFetchFailed means the registry could not serve the referrer or
	// the trust material to verify it was unavailable.
	outcomeFetchFailed
	// outcomeLimitExceeded means the referrer was dropped because a size or
	// count limit was exceeded, so the attestation set is incomplete.
	outcomeLimitExceeded
)

// collectStats aggregates referrer outcomes of one collection pass.
type collectStats struct {
	mu             sync.Mutex
	verifyFailures int
	fetchErr       error
	limitErr       error
}

func (s *collectStats) record(outcome referrerOutcome, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch outcome {
	case outcomeVerifyFailed:
		s.verifyFailures++
	case outcomeFetchFailed:
		if s.fetchErr == nil {
			s.fetchErr = err
		}
	case outcomeLimitExceeded:
		if s.limitErr == nil {
			s.limitErr = err
		}
	case outcomeVerified, outcomeUnverified, outcomeSkipped:
	}
}

func (s *collectStats) merge(other *collectStats) {
	s.verifyFailures += other.verifyFailures

	if s.fetchErr == nil {
		s.fetchErr = other.fetchErr
	}

	if s.limitErr == nil {
		s.limitErr = other.limitErr
	}
}

func isContentError(err error) bool {
	return errors.Is(err, errEmptyAttestation) || errors.Is(err, errInvalidReferrer)
}

// isTransportFailure reports whether err means that the registry could not
// be reached or refused to serve a request, as opposed to serving content
// that is malformed. Only transport failures may be handled with the fetch
// failure policy. Everything else counts as a verification failure, so junk
// pushed to a registry (an index where an attestation manifest is expected,
// undecodable layers, broken manifests) can never turn a deny into a lenient
// fetch failure.
func isTransportFailure(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}

	if transportErr, ok := errors.AsType[*transport.Error](err); ok {
		switch transportErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden,
			http.StatusRequestTimeout, http.StatusTooManyRequests:
			return true
		default:
			return transportErr.StatusCode >= http.StatusInternalServerError
		}
	}

	if _, ok := errors.AsType[net.Error](err); ok {
		return true
	}

	// Only a body that ended early while it was downloaded (see readBounded)
	// is a truncated response. The same io.ErrUnexpectedEOF also comes from
	// decoding a truncated manifest or layer, which is malformed content.
	return errors.Is(err, errTruncatedResponse)
}

// isReferrerTransportFailure reports whether an error fetching a listed
// referrer (its manifest or blob) is a transport failure. It is stricter than
// isTransportFailure for authorization errors: the referrers listing already
// succeeded with the same credentials, so a 401 or 403 for one referrer is a
// per-artifact decision of the registry (for example a policy engine blocking
// a freshly pushed artifact). Treating it as a transport failure would let
// anyone who can push such an artifact turn a deny into the fetch failure
// policy, so it counts as a verification failure instead.
func isReferrerTransportFailure(err error) bool {
	if transportErr, ok := errors.AsType[*transport.Error](err); ok {
		switch transportErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return false
		default:
		}
	}

	return isTransportFailure(err)
}

// classifyReferrerError maps an error from fetching a referrer manifest or
// reading its layer to an outcome. A referrer that no longer exists is
// skipped. A manifest or layer exceeding a size limit, or the download
// budget, makes the attestation set incomplete, so it must not be evaluated.
// A transport failure makes the attestation set incomplete as well (the fetch
// failure policy applies), and any other error means the registry served
// content that is not a valid attestation.
func classifyReferrerError(
	ctx context.Context, what string, desc *ociV1.Descriptor, err error,
) referrerOutcome {
	switch {
	case isRegistryNotFound(err):
		slog.WarnContext(ctx, "Referrer listed but not found, skipping",
			"kind", what,
			"digest", desc.Digest.String(),
		)

		return outcomeSkipped
	case errors.Is(err, errAttestationTooLarge), errors.Is(err, errDownloadLimitExceeded):
		slog.WarnContext(ctx, "Referrer exceeds the attestation size limit",
			"kind", what,
			"digest", desc.Digest.String(),
			"error", err,
		)

		return outcomeLimitExceeded
	case !isContentError(err) && isReferrerTransportFailure(err):
		slog.WarnContext(ctx, "Failed to fetch referrer",
			"kind", what,
			"digest", desc.Digest.String(),
			"error", err,
		)

		return outcomeFetchFailed
	default:
		slog.WarnContext(ctx, "Invalid referrer content",
			"kind", what,
			"digest", desc.Digest.String(),
			"error", err,
		)

		return outcomeVerifyFailed
	}
}

func isRegistryNotFound(err error) bool {
	var transportErr *transport.Error

	return errors.As(err, &transportErr) &&
		transportErr.StatusCode == http.StatusNotFound
}

// classifyCosignLayerError maps an error from reading a cosign attestation
// layer to an outcome.
// Content errors are checked first: decoding a truncated layer fails with the
// same io.ErrUnexpectedEOF that a dropped connection produces.
func classifyCosignLayerError(err error) (referrerOutcome, error) {
	switch {
	case errors.Is(err, errAttestationTooLarge), errors.Is(err, errDownloadLimitExceeded):
		return outcomeLimitExceeded, err
	case isContentError(err):
		return outcomeVerifyFailed, nil
	case isReferrerTransportFailure(err):
		return outcomeFetchFailed, err
	default:
		return outcomeVerifyFailed, nil
	}
}

// tagContentError keeps transport failures as plain fetch errors and marks
// every other error on the cosign attestation tag as a verification failure.
func tagContentError(err error) error {
	if !isContentError(err) && isTransportFailure(err) {
		return err
	}

	return fmt.Errorf("%w: %w: %w", ErrVerificationFailed, errInvalidReferrer, err)
}
