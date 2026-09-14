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

package attestation_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func TestLegacyLayerWithoutVerificationMaterial(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	layerData, annotations := testutil.LegacyCosignLayer(
		t,
		signer.SignBundle(t, signerStatement(t)),
	)

	converted, err := attestation.ExportLegacyLayerToBundles(layerData, annotations, nil)
	testutil.AssertErrorIs(t, err, attestation.ErrNoLegacyVerificationMaterial)
	testutil.AssertEqual(t, 0, len(converted))
}

//nolint:paralleltest // mutates slog.SetDefault
func TestCosignTagWithoutVerificationMaterialLogsReason(t *testing.T) {
	var buf bytes.Buffer

	prev := slog.Default()

	slog.SetDefault(
		slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})),
	)
	t.Cleanup(func() { slog.SetDefault(prev) })

	signer := testutil.NewKeySigner(t)
	ref, err := name.NewDigest(signerLegacyTagRef + "@" + signerTestDigest)
	testutil.AssertNoError(t, err)

	img := legacyCosignImage(t, signer.SignBundle(t, signerStatement(t)))
	fetcher := signedFetcher(map[string]ociV1.Image{
		strings.Replace(signerTestDigest, ":", "-", 1) + ".att": img,
	}, nil)

	_, err = fetcher.CosignTagFallback(
		t.Context(),
		ref,
		signerTestDigest,
		nil,
		&attestation.FetchOptions{Digest: signerTestDigest},
	)
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)

	output := buf.String()

	if strings.Contains(output, "error=<nil>") {
		t.Errorf("expected every verification failure log to carry an error, got: %s", output)
	}

	if !strings.Contains(output, "no certificate annotation and no trusted keys") {
		t.Errorf("expected the missing verification material to be logged, got: %s", output)
	}
}
