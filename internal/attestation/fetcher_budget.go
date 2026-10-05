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
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
)

// maxRegistryResponseSize bounds the bytes read from one manifest or referrers
// listing response. go-containerregistry reads up to 100 MiB per manifest,
// and the size declared by a referrers listing is chosen by whoever pushed the
// referrer, so the bound is enforced on the bytes actually read.
const maxRegistryResponseSize = maxReferrerManifestSize

// downloadBudget counts the bytes downloaded during one fetch pass, so junk
// referrers cannot make the plugin download without bound.
type downloadBudget struct {
	used  atomic.Int64
	limit int64
}

type downloadBudgetKey struct{}

func withDownloadBudget(ctx context.Context, limit int64) context.Context {
	return context.WithValue(
		ctx,
		downloadBudgetKey{},
		&downloadBudget{used: atomic.Int64{}, limit: limit},
	)
}

func budgetFrom(ctx context.Context) *downloadBudget {
	budget, _ := ctx.Value(downloadBudgetKey{}).(*downloadBudget)

	return budget
}

// reserveDownload checks that size more bytes fit the download budget of the
// fetch in ctx before they are downloaded.
func reserveDownload(ctx context.Context, size int64) error {
	budget := budgetFrom(ctx)
	if budget == nil {
		return nil
	}

	if used := budget.used.Load(); used+size > budget.limit {
		return fmt.Errorf(
			"%w: %d bytes already downloaded, %d more exceed %d",
			errDownloadLimitExceeded, used, size, budget.limit,
		)
	}

	return nil
}

// chargeDownload records size downloaded bytes against the download budget of
// the fetch in ctx.
func chargeDownload(ctx context.Context, size int64) error {
	return budgetFrom(ctx).charge(size)
}

// charge records size downloaded bytes. A nil budget accepts everything.
func (b *downloadBudget) charge(size int64) error {
	if b == nil {
		return nil
	}

	if used := b.used.Add(size); used > b.limit {
		return fmt.Errorf(
			"%w: %d bytes downloaded, limit %d", errDownloadLimitExceeded, used, b.limit,
		)
	}

	return nil
}

// budgetTransport bounds the manifest and referrers listing responses of a
// fetch pass. Every byte read from such a response is charged to the download
// budget in the request context, and a response larger than
// maxRegistryResponseSize fails while it is read. Blob downloads are bounded
// by readLayer.
type budgetTransport struct {
	base http.RoundTripper
}

func newBudgetTransport(base http.RoundTripper) http.RoundTripper {
	return &budgetTransport{base: base}
}

func (t *budgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err //nolint:wrapcheck // transparent transport wrapper
	}

	if resp.Body != nil && isManifestPath(req.URL.Path) {
		resp.Body = &budgetedBody{
			ReadCloser: resp.Body,
			budget:     budgetFrom(req.Context()),
			remaining:  maxRegistryResponseSize,
		}
	}

	return resp, nil
}

// isManifestPath reports whether a registry API path serves a manifest
// (/v2/<name>/manifests/<reference>) or a referrers listing
// (/v2/<name>/referrers/<digest>). Only the segment right before the final
// reference counts, since repository names may contain "manifests" or
// "referrers" as well (/v2/org/referrers/app/blobs/<digest> is a blob).
func isManifestPath(path string) bool {
	rest, ok := strings.CutPrefix(path, "/v2/")
	if !ok {
		return false
	}

	segments := strings.Split(rest, "/")

	// At least one repository name segment, the endpoint and the reference.
	const minSegments = 3
	if len(segments) < minSegments || segments[len(segments)-1] == "" {
		return false
	}

	switch segments[len(segments)-2] {
	case "manifests", "referrers":
		return !slices.Contains(segments[:len(segments)-2], "")
	default:
		return false
	}
}

// budgetedBody charges the bytes read from a response body and fails once the
// body exceeds its size limit or the download budget.
type budgetedBody struct {
	io.ReadCloser

	budget    *downloadBudget
	remaining int64
}

func (b *budgetedBody) Read(buf []byte) (int, error) {
	// Read one byte more than allowed to detect an oversized body.
	if int64(len(buf)) > b.remaining+1 {
		buf = buf[:b.remaining+1]
	}

	count, err := b.ReadCloser.Read(buf)

	if int64(count) > b.remaining {
		return 0, fmt.Errorf(
			"%w: registry response exceeds %d bytes",
			errDownloadLimitExceeded,
			maxRegistryResponseSize,
		)
	}

	b.remaining -= int64(count)

	chargeErr := b.budget.charge(int64(count))
	if chargeErr != nil {
		return 0, chargeErr
	}

	return count, err //nolint:wrapcheck // io.EOF must be returned unwrapped
}
