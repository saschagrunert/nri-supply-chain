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

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testDigestBBB = "sha256:bbb"
	testImgV3     = "img:v3"
	testCheckSLSA = "slsa"
)

func TestLoadImagesFromArgs(t *testing.T) {
	t.Parallel()

	images, err := loadImages([]string{testImgV1, testImgV2}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(images) != 2 {
		t.Fatalf("expected 2 images, got %d", len(images))
	}

	if images[0] != testImgV1 {
		t.Errorf("images[0] = %q, want %q", images[0], testImgV1)
	}

	if images[1] != testImgV2 {
		t.Errorf("images[1] = %q, want %q", images[1], testImgV2)
	}
}

func TestLoadImagesFromFile(t *testing.T) {
	t.Parallel()

	imagesFile := filepath.Join(t.TempDir(), "images.txt")

	err := os.WriteFile(imagesFile, []byte(
		"docker.io/library/nginx:latest\n"+
			"# this is a comment\n"+
			"  \n"+
			"ghcr.io/owner/repo:v1\n",
	), 0o600)
	if err != nil {
		t.Fatalf("writing images file: %v", err)
	}

	images, err := loadImages(nil, imagesFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(images) != 2 {
		t.Fatalf("expected 2 images, got %d", len(images))
	}

	if images[0] != "docker.io/library/nginx:latest" {
		t.Errorf("images[0] = %q, want docker.io/library/nginx:latest", images[0])
	}

	if images[1] != "ghcr.io/owner/repo:v1" {
		t.Errorf("images[1] = %q, want ghcr.io/owner/repo:v1", images[1])
	}
}

func TestLoadImagesCombined(t *testing.T) {
	t.Parallel()

	imagesFile := filepath.Join(t.TempDir(), "images.txt")

	err := os.WriteFile(imagesFile, []byte("file-img:v1\n"), 0o600)
	if err != nil {
		t.Fatalf("writing images file: %v", err)
	}

	images, err := loadImages([]string{"arg-img:v1"}, imagesFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(images) != 2 {
		t.Fatalf("expected 2 images, got %d", len(images))
	}

	if images[0] != "arg-img:v1" {
		t.Errorf("images[0] = %q, want arg-img:v1", images[0])
	}

	if images[1] != "file-img:v1" {
		t.Errorf("images[1] = %q, want file-img:v1", images[1])
	}
}

func TestLoadImagesFileMissing(t *testing.T) {
	t.Parallel()

	_, err := loadImages(nil, "/nonexistent/images.txt")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestAggregateResults(t *testing.T) {
	t.Parallel()

	results := []*verifyOutput{
		{
			Image:   testImgV1,
			Digest:  testDigestAAA,
			Allowed: true,
			CheckResults: []types.CheckResult{
				*types.PassResult(types.CheckTypeSLSA, "ok"),
				*types.PassResult(types.CheckTypeVEX, "ok"),
			},
		},
		{
			Image:   testImgV2,
			Digest:  testDigestBBB,
			Allowed: false,
			CheckResults: []types.CheckResult{
				*types.FailResult(types.CheckTypeSLSA, "missing", nil),
				*types.PassResult(types.CheckTypeVEX, "ok"),
			},
		},
		{
			Image:  testImgV3,
			Digest: "",
			Reason: "resolve error",
		},
	}

	summary := aggregateResults(results)

	if summary.Total != 3 {
		t.Errorf("Total = %d, want 3", summary.Total)
	}

	if summary.Allowed != 1 {
		t.Errorf("Allowed = %d, want 1", summary.Allowed)
	}

	if summary.Denied != 1 {
		t.Errorf("Denied = %d, want 1", summary.Denied)
	}

	if summary.Errors != 1 {
		t.Errorf("Errors = %d, want 1", summary.Errors)
	}

	slsaCheck := summary.Checks[testCheckSLSA]
	if slsaCheck.Pass != 1 || slsaCheck.Fail != 1 {
		t.Errorf("SLSA = %+v, want Pass=1 Fail=1", slsaCheck)
	}

	vexCheck := summary.Checks["vex"]
	if vexCheck.Pass != 2 {
		t.Errorf("VEX Pass = %d, want 2", vexCheck.Pass)
	}
}

func TestGenerateSuggestionsAllPass(t *testing.T) {
	t.Parallel()

	summary := previewSummary{
		Total:   2,
		Allowed: 2,
		Denied:  0,
		Errors:  0,
		Checks: map[string]checkSummary{
			testCheckSLSA: {Pass: 2, Warn: 0, Fail: 0},
		},
	}

	suggestions := generateSuggestions(summary)

	found := false
	safeFound := false

	for _, suggestion := range suggestions {
		if suggestion == "All 2 images pass SLSA; consider setting slsa.missingPolicy=deny" {
			found = true
		}

		if suggestion == "All images pass; this policy set is safe to promote to enforce mode" {
			safeFound = true
		}
	}

	if !found {
		t.Error("expected suggestion about SLSA missingPolicy=deny")
	}

	if !safeFound {
		t.Error("expected suggestion about promote to enforce mode")
	}
}

func TestGenerateSuggestionsWithFailures(t *testing.T) {
	t.Parallel()

	summary := previewSummary{
		Total:   3,
		Allowed: 2,
		Denied:  1,
		Errors:  0,
		Checks: map[string]checkSummary{
			testCheckSLSA: {Pass: 2, Warn: 0, Fail: 1},
		},
	}

	suggestions := generateSuggestions(summary)

	failFound := false
	reviewFound := false

	for _, suggestion := range suggestions {
		if suggestion == "1/3 images fail SLSA checks" {
			failFound = true
		}

		if suggestion == "1/3 images would be denied; review failing checks before enabling enforce mode" {
			reviewFound = true
		}
	}

	if !failFound {
		t.Error("expected suggestion about failing SLSA checks")
	}

	if !reviewFound {
		t.Error("expected suggestion about reviewing before enforce mode")
	}
}

func TestGenerateSuggestionsEmpty(t *testing.T) {
	t.Parallel()

	summary := previewSummary{
		Total:   0,
		Allowed: 0,
		Denied:  0,
		Errors:  0,
		Checks:  map[string]checkSummary{},
	}

	suggestions := generateSuggestions(summary)

	if suggestions != nil {
		t.Errorf("expected nil suggestions for empty input, got %v", suggestions)
	}
}

func TestRunPreviewDisabledVerification(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeDisabled

	var buf bytes.Buffer

	code := runPreview(&buf, []string{testImgV1}, "default", outputFormatTable, "", cfg)
	if code != exitError {
		t.Errorf("expected exit code %d, got %d", exitError, code)
	}
}

func TestRunPreviewJSONOutput(t *testing.T) {
	t.Parallel()

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{"slsa": {"missingPolicy": "warn"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	var buf bytes.Buffer

	code := runPreview(
		&buf, []string{"invalid-image-ref-for-test:latest"},
		"default", outputFormatJSON, "", cfg,
	)

	if code != exitSuccess {
		t.Fatalf("expected exit code %d, got %d", exitSuccess, code)
	}

	var out previewOutput

	err := json.Unmarshal(buf.Bytes(), &out)
	if err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
	}

	if out.Summary.Total != 1 {
		t.Errorf("Summary.Total = %d, want 1", out.Summary.Total)
	}
}

func TestNewPreviewCmdViaRoot(t *testing.T) {
	t.Parallel()

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{"slsa": {"missingPolicy": "warn"}}`)

	configPath := filepath.Join(t.TempDir(), "config.toml")
	writeTestConfig(t, configPath, policyDir, "warn")

	cmd := newRootCmd()
	cmd.SetArgs([]string{
		testFlagConfig, configPath,
		cmdPreview, "--output", outputFormatJSON,
		"test-image:latest",
	})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadImagesDeduplication(t *testing.T) {
	t.Parallel()

	imagesFile := filepath.Join(t.TempDir(), "images.txt")

	err := os.WriteFile(imagesFile, []byte(testImgV1+"\n"+testImgV2+"\n"), 0o600)
	if err != nil {
		t.Fatalf("writing images file: %v", err)
	}

	images, err := loadImages([]string{testImgV1, testImgV3}, imagesFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(images) != 3 {
		t.Fatalf("expected 3 unique images, got %d: %v", len(images), images)
	}

	if images[0] != testImgV1 || images[1] != testImgV3 || images[2] != testImgV2 {
		t.Errorf("unexpected dedup result: %v", images)
	}
}

func TestGenerateSuggestionsWithErrors(t *testing.T) {
	t.Parallel()

	summary := previewSummary{
		Total:   10,
		Allowed: 8,
		Denied:  0,
		Errors:  2,
		Checks: map[string]checkSummary{
			testCheckSLSA: {Pass: 8, Warn: 0, Fail: 0},
		},
	}

	suggestions := generateSuggestions(summary)

	slsaFound := false
	safeFound := false

	for _, suggestion := range suggestions {
		if strings.Contains(suggestion, "All 8 images pass SLSA") {
			slsaFound = true
		}

		if strings.Contains(suggestion, "safe to promote") {
			safeFound = true
		}
	}

	if !slsaFound {
		t.Errorf("expected suggestion about 8 images passing SLSA, got: %v", suggestions)
	}

	if safeFound {
		t.Errorf(
			"'safe to promote' should be suppressed when errors exist, got: %v",
			suggestions,
		)
	}
}

func TestBuildDiffOutput(t *testing.T) {
	t.Parallel()

	current := []*verifyOutput{
		{Image: testImgV1, Digest: testDigestAAA, Allowed: true},
		{Image: testImgV2, Digest: testDigestBBB, Allowed: true},
	}

	proposed := []*verifyOutput{
		{Image: testImgV1, Digest: testDigestAAA, Allowed: false},
		{Image: testImgV2, Digest: testDigestBBB, Allowed: true},
	}

	out := buildDiffOutput(current, proposed)

	if out.Summary.Total != 2 {
		t.Errorf("Total = %d, want 2", out.Summary.Total)
	}

	if out.Summary.Changed != 1 {
		t.Errorf("Changed = %d, want 1", out.Summary.Changed)
	}

	if out.Summary.Unchanged != 1 {
		t.Errorf("Unchanged = %d, want 1", out.Summary.Unchanged)
	}

	if out.Summary.NewDenied != 1 {
		t.Errorf("NewDenied = %d, want 1", out.Summary.NewDenied)
	}

	if out.Summary.NewAllow != 0 {
		t.Errorf("NewAllow = %d, want 0", out.Summary.NewAllow)
	}

	if !out.Images[0].Changed {
		t.Error("expected first image to be changed")
	}

	if out.Images[1].Changed {
		t.Error("expected second image to be unchanged")
	}
}

func TestBuildDiffOutputNewAllow(t *testing.T) {
	t.Parallel()

	current := []*verifyOutput{
		{Image: testImgV1, Digest: testDigestAAA, Allowed: false},
	}

	proposed := []*verifyOutput{
		{Image: testImgV1, Digest: testDigestAAA, Allowed: true},
	}

	out := buildDiffOutput(current, proposed)

	if out.Summary.NewAllow != 1 {
		t.Errorf("NewAllow = %d, want 1", out.Summary.NewAllow)
	}

	if out.Summary.NewDenied != 0 {
		t.Errorf("NewDenied = %d, want 0", out.Summary.NewDenied)
	}
}

func TestBuildDiffOutputCheckLevelChange(t *testing.T) {
	t.Parallel()

	current := []*verifyOutput{
		{
			Image:   testImgV1,
			Digest:  testDigestAAA,
			Allowed: true,
			CheckResults: []types.CheckResult{
				*types.PassResult(types.CheckTypeSLSA, "ok"),
			},
		},
	}

	proposed := []*verifyOutput{
		{
			Image:   testImgV1,
			Digest:  testDigestAAA,
			Allowed: true,
			CheckResults: []types.CheckResult{
				*types.FailResult(types.CheckTypeSLSA, "missing", nil),
			},
		},
	}

	out := buildDiffOutput(current, proposed)

	if out.Summary.Changed != 1 {
		t.Errorf("Changed = %d, want 1 (check status changed even though Allowed stayed the same)",
			out.Summary.Changed)
	}

	if out.Images[0].Changed != true {
		t.Error("expected image to be marked as changed due to check-level status change")
	}
}

func TestBuildDiffOutputMismatchedLengths(t *testing.T) {
	t.Parallel()

	current := []*verifyOutput{
		{Image: testImgV1, Digest: testDigestAAA, Allowed: true},
		{Image: testImgV2, Digest: testDigestBBB, Allowed: true},
	}

	proposed := []*verifyOutput{
		{Image: testImgV1, Digest: testDigestAAA, Allowed: false},
	}

	out := buildDiffOutput(current, proposed)

	if out.Summary.Total != 1 {
		t.Errorf("Total = %d, want 1 (min of current=%d, proposed=%d)",
			out.Summary.Total, len(current), len(proposed))
	}

	if len(out.Images) != 1 {
		t.Errorf("Images = %d, want 1", len(out.Images))
	}
}

func TestRunPreviewDiffViaRoot(t *testing.T) {
	t.Parallel()

	currentDir := t.TempDir()
	writeValidationPolicy(t, currentDir, "default.json",
		`{"slsa": {"missingPolicy": "warn"}}`)

	proposedDir := t.TempDir()
	writeValidationPolicy(t, proposedDir, "default.json",
		`{"slsa": {"missingPolicy": "deny"}}`)

	configPath := filepath.Join(t.TempDir(), "config.toml")
	writeTestConfig(t, configPath, currentDir, "warn")

	cmd := newRootCmd()
	cmd.SetArgs([]string{
		testFlagConfig, configPath,
		cmdPreview, "--output", outputFormatJSON,
		"--compare-policy", proposedDir,
		"test-image:latest",
	})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckStatusesChangedProposedDuplicates(t *testing.T) {
	t.Parallel()

	current := &verifyOutput{
		Image:         testImgV1,
		Digest:        testDigestAAA,
		Namespace:     "default",
		PolicyFile:    "",
		Mode:          "",
		PreviewPolicy: "",
		Allowed:       true,
		Reason:        "",
		CheckResults: []types.CheckResult{
			*types.PassResult(types.CheckTypeSLSA, "ok"),
			*types.PassResult(types.CheckTypeVEX, "ok"),
		},
	}

	proposed := &verifyOutput{
		Image:         testImgV1,
		Digest:        testDigestAAA,
		Namespace:     "default",
		PolicyFile:    "",
		Mode:          "",
		PreviewPolicy: "",
		Allowed:       true,
		Reason:        "",
		CheckResults: []types.CheckResult{
			*types.PassResult(types.CheckTypeSLSA, "ok"),
			*types.PassResult(types.CheckTypeSLSA, "ok"),
		},
	}

	if !checkStatusesChanged(current, proposed) {
		t.Error("expected changed=true when proposed has duplicate types masking a missing type")
	}
}

func TestOutputDiffTableNoChanges(t *testing.T) {
	t.Parallel()

	current := newVerifyOutput(testImgV1, "", "default", "")
	current.Allowed = true

	out := &previewDiffOutput{
		Images: []previewDiffImage{
			{
				Image:    testImgV1,
				Changed:  false,
				Current:  *current,
				Proposed: *current,
			},
		},
		Summary: previewDiffSummary{
			Total: 1, Changed: 0, Unchanged: 1,
			NewDenied: 0, NewAllow: 0,
		},
	}

	var buf bytes.Buffer

	err := outputDiffTable(&buf, out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "No policy impact") {
		t.Errorf("expected 'No policy impact' in output, got:\n%s", buf.String())
	}
}
