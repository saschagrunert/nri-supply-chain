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

// Package slsa provides SLSA provenance verification for supply chain attestations.
package slsa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	checkType = types.CheckTypeSLSA

	metaBuilderID    = "builderID"
	metaBuildType    = "buildType"
	metaSource       = "source"
	metaSourceRef    = "sourceRef"
	metaSourceDigest = "sourceDigest"
	metaTrustScoped  = "trustConfigured"

	paramWorkflow      = "workflow"
	paramSourceToBuild = "sourceToBuild"
	paramConfigSource  = "configSource"

	sha1HexLength   = 40
	sha256HexLength = 64

	emptyTrustDetail = "SLSA provenance verified, but no trusted builders, sources, " +
		"or build types are configured"
)

var (
	// ErrSubjectDigestMismatch indicates the provenance subject does not match the image digest.
	ErrSubjectDigestMismatch = errors.New("subject digest mismatch")

	// ErrUntrustedBuilder indicates the builder is not in the trusted builders list.
	ErrUntrustedBuilder = errors.New("untrusted builder")

	// ErrUntrustedBuildType indicates the build type is not in the allowed list.
	ErrUntrustedBuildType = errors.New("untrusted build type")

	// ErrUntrustedSource indicates the source repository is not in the allowed list.
	ErrUntrustedSource = errors.New("untrusted source repository")

	// ErrSourceMismatch indicates the provenance source is inconsistent with
	// its resolved dependencies.
	ErrSourceMismatch = errors.New("provenance source inconsistent with resolved dependencies")

	// ErrUnknownParameters indicates unrecognized external parameters were found.
	ErrUnknownParameters = errors.New("unrecognized external parameters")

	// ErrInvalidProvenance indicates the provenance attestation could not be parsed.
	ErrInvalidProvenance = errors.New("invalid provenance attestation")

	// ErrStaleProvenance indicates the provenance is older than the maximum allowed age.
	ErrStaleProvenance = errors.New("provenance is stale")

	// ErrFutureTimestamp indicates the provenance build timestamp is in the future.
	ErrFutureTimestamp = errors.New("provenance build timestamp is in the future")

	warnedMaxLevel   sync.Map //nolint:gochecknoglobals // dedup per builder ID
	warnedEmptyTrust sync.Map //nolint:gochecknoglobals // one-time empty trust warning
)

// Statement represents an in-toto statement wrapping a SLSA provenance predicate.
type Statement struct {
	Type          string              `json:"_type"` //nolint:tagliatelle // In-toto spec field name.
	Subject       []Subject           `json:"subject"`
	PredicateType string              `json:"predicateType"`
	Predicate     ProvenancePredicate `json:"predicate"`
}

// Subject represents an in-toto subject with name and digests.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// ProvenancePredicate represents the SLSA provenance v1 predicate.
type ProvenancePredicate struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// BuildDefinition describes what was built and how.
type BuildDefinition struct {
	BuildType          string         `json:"buildType"`
	ExternalParameters map[string]any `json:"externalParameters"`
	InternalParameters map[string]any `json:"internalParameters"`
}

// RunDetails describes the build execution.
type RunDetails struct {
	Builder  Builder  `json:"builder"`
	Metadata Metadata `json:"metadata"`
}

// Builder identifies the build system.
type Builder struct {
	ID string `json:"id"`
}

// Metadata holds build metadata.
type Metadata struct {
	InvocationID string     `json:"invocationId"` //nolint:tagliatelle // SLSA spec field name.
	StartedOn    *time.Time `json:"startedOn,omitempty"`
}

// VerifyOptions carries optional hooks for provenance verification.
type VerifyOptions struct {
	// BindBuilder is called after runDetails.builder.id (or builder.id for
	// v0.2) matched one or more trusted builders. The builder ID is only a
	// claim inside the signed payload, so the hook should confirm that the
	// attestation signer is authorized for one of the matched entries. A
	// returned error fails that attestation.
	BindBuilder func(att *attestation.VerifiedAttestation, matched []policy.TrustedBuilder) error
}

// resourceDescriptor is the SLSA v1 ResourceDescriptor subset used for
// resolved dependency checks.
type resourceDescriptor struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

// resolvedDependencies is decoded separately from Statement so that the
// exported provenance types stay unchanged.
type resolvedDependencies struct {
	Predicate struct {
		BuildDefinition struct {
			ResolvedDependencies []resourceDescriptor `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
	} `json:"predicate"`
}

// sourceInfo describes the source repository a build was started from.
type sourceInfo struct {
	// URI is the normalized repository URI without scheme prefix or ref.
	URI string
	// Ref is the git ref or commit SHA the build used, when known.
	Ref string
	// Digest is the source commit digest ("algorithm:value"), when known.
	Digest string
	// Config is the build configuration source when it differs from the
	// built source in repository or ref (Cloud Build configSource).
	Config *sourceInfo
}

// builderBinder binds a matched builder to the attestation being verified.
type builderBinder func(matched []policy.TrustedBuilder) error

// Verify checks a SLSA provenance attestation against the given policy.
func Verify(
	ctx context.Context, att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	return verify(ctx, att, pol, imageDigest, nil)
}

// VerifyMultiple checks multiple provenance attestations, accepting if any valid one passes.
func VerifyMultiple(
	ctx context.Context,
	attestations []attestation.VerifiedAttestation, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	return VerifyMultipleWithOptions(ctx, attestations, pol, imageDigest, nil)
}

// VerifyMultipleWithOptions checks multiple provenance attestations with
// optional verification hooks, accepting if any valid one passes.
func VerifyMultipleWithOptions(
	ctx context.Context,
	attestations []attestation.VerifiedAttestation, pol *policy.Policy, imageDigest string,
	opts *VerifyOptions,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // shared helper returns domain errors
	return types.VerifyMultipleFirstPassOf(
		ctx, checkType, "provenance", attestations,
		func(att *attestation.VerifiedAttestation) (*types.CheckResult, error) {
			var bind builderBinder

			if opts != nil && opts.BindBuilder != nil {
				bind = func(matched []policy.TrustedBuilder) error {
					return opts.BindBuilder(att, matched)
				}
			}

			return verify(ctx, att.Payload, pol, imageDigest, bind)
		},
	)
}

func verify(
	ctx context.Context, att []byte, pol *policy.Policy, imageDigest string, bind builderBinder,
) (*types.CheckResult, error) {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
	}

	var header struct {
		PredicateType string `json:"predicateType"`
	}

	err := json.Unmarshal(att, &header)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidProvenance, err)
	}

	if header.PredicateType == attestation.PredicateSLSAProvenanceV02 {
		return verifyV02(ctx, att, pol, imageDigest, bind)
	}

	return verifyV1(ctx, att, pol, imageDigest, bind)
}

func verifyV1(
	ctx context.Context, att []byte, pol *policy.Policy, imageDigest string, bind builderBinder,
) (*types.CheckResult, error) {
	var stmt Statement

	err := json.Unmarshal(att, &stmt)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidProvenance, err)
	}

	if stmt.PredicateType != attestation.PredicateSLSAProvenanceV1 {
		return nil, fmt.Errorf(
			"%w: unexpected predicate type %q", ErrInvalidProvenance, stmt.PredicateType,
		)
	}

	var deps resolvedDependencies

	err = json.Unmarshal(att, &deps)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidProvenance, err)
	}

	warnEmptyTrust(ctx, pol)

	buildDef := &stmt.Predicate.BuildDefinition
	source := extractSourceV1(buildDef.BuildType, buildDef.ExternalParameters)

	checks := []func() error{
		func() error { return verifySubjectDigest(stmt.Subject, imageDigest) },
		func() error { return verifyBuilder(ctx, stmt.Predicate.RunDetails.Builder, pol, bind) },
		func() error { return verifyBuildType(buildDef.BuildType, pol) },
		func() error { return verifySource(&source, pol) },
		func() error {
			return verifyResolvedSource(
				&source, deps.Predicate.BuildDefinition.ResolvedDependencies,
			)
		},
		func() error { return verifyParameters(buildDef.ExternalParameters, pol) },
		func() error { return verifyFreshness(stmt.Predicate.RunDetails.Metadata.StartedOn, pol) },
	}

	for _, check := range checks {
		err = check()
		if err != nil {
			return types.FailResult(checkType, err.Error(), nil), nil
		}
	}

	return passResult(pol, map[string]any{
		metaBuilderID:    stmt.Predicate.RunDetails.Builder.ID,
		metaBuildType:    buildDef.BuildType,
		metaSource:       source.URI,
		metaSourceRef:    source.Ref,
		metaSourceDigest: source.Digest,
	}), nil
}

// StatementV02 represents an in-toto v0.1 statement wrapping a SLSA provenance v0.2 predicate.
type StatementV02 struct {
	Type          string                 `json:"_type"` //nolint:tagliatelle // In-toto spec field name.
	Subject       []Subject              `json:"subject"`
	PredicateType string                 `json:"predicateType"`
	Predicate     ProvenancePredicateV02 `json:"predicate"`
}

// ProvenancePredicateV02 represents the SLSA provenance v0.2 predicate.
type ProvenancePredicateV02 struct {
	Builder    Builder       `json:"builder"`
	BuildType  string        `json:"buildType"`
	Invocation InvocationV02 `json:"invocation"`
	Materials  []MaterialV02 `json:"materials"`
	Metadata   MetadataV02   `json:"metadata"`
}

// MetadataV02 holds build metadata for v0.2 provenance.
type MetadataV02 struct {
	BuildStartedOn *time.Time `json:"buildStartedOn,omitempty"`
}

// InvocationV02 holds v0.2 invocation metadata.
type InvocationV02 struct {
	ConfigSource ConfigSourceV02 `json:"configSource"`
}

// ConfigSourceV02 identifies the source of a v0.2 build invocation.
type ConfigSourceV02 struct {
	URI string `json:"uri"`
}

// MaterialV02 represents a v0.2 build material.
type MaterialV02 struct {
	URI string `json:"uri"`
}

func verifyV02(
	ctx context.Context, att []byte, pol *policy.Policy, imageDigest string, bind builderBinder,
) (*types.CheckResult, error) {
	var stmt StatementV02

	err := json.Unmarshal(att, &stmt)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidProvenance, err)
	}

	warnEmptyTrust(ctx, pol)

	sourceURI, sourceRef := normalizeSourceURI(sourceV02(&stmt.Predicate))
	source := sourceInfo{URI: sourceURI, Ref: sourceRef, Digest: "", Config: nil}

	// v0.2 has no externalParameters, so rejectUnknownParameters does not
	// apply. Parameter validation is only meaningful for v1 provenance.
	checks := []func() error{
		func() error { return verifySubjectDigest(stmt.Subject, imageDigest) },
		func() error { return verifyBuilder(ctx, stmt.Predicate.Builder, pol, bind) },
		func() error { return verifyBuildType(stmt.Predicate.BuildType, pol) },
		func() error { return verifySource(&source, pol) },
		func() error { return verifyFreshness(stmt.Predicate.Metadata.BuildStartedOn, pol) },
	}

	for _, check := range checks {
		err = check()
		if err != nil {
			return types.FailResult(checkType, err.Error(), nil), nil
		}
	}

	return passResult(pol, map[string]any{
		metaBuilderID:    stmt.Predicate.Builder.ID,
		metaBuildType:    stmt.Predicate.BuildType,
		metaSource:       source.URI,
		metaSourceRef:    source.Ref,
		metaSourceDigest: "",
	}), nil
}

// passResult returns a passing result, or a warning when the policy has no
// builder, source, or build type constraints so that an unconstrained
// provenance check is visible in results and annotations.
func passResult(pol *policy.Policy, meta map[string]any) *types.CheckResult {
	constrained := trustConfigured(pol)
	meta[metaTrustScoped] = constrained

	result := check.Pass()
	if !constrained {
		result = types.WarnResult(checkType, emptyTrustDetail)
	}

	result.Metadata = meta

	return result
}

// sourceV02 returns the raw source URI from a v0.2 provenance predicate.
// Falls back to the first material URI; this relies on the SLSA GitHub
// generator always listing the source repo as the first material.
func sourceV02(pred *ProvenancePredicateV02) string {
	if pred.Invocation.ConfigSource.URI != "" {
		return pred.Invocation.ConfigSource.URI
	}

	if len(pred.Materials) > 0 {
		return pred.Materials[0].URI
	}

	return ""
}

// normalizeSourceURI converts git URIs like
// "git+https://github.com/org/repo@refs/heads/main" into
// "https://github.com/org/repo" and the ref "refs/heads/main" so they match
// the same trust policy source patterns used for source track attestations.
// An '@' in the authority (for example git+ssh://git@host/...) is kept.
func normalizeSourceURI(uri string) (normalized, ref string) {
	normalized, ref, _ = glob.SplitGitRef(uri)

	return normalized, ref
}

const (
	// BuildTypeGitHubActionsWorkflow is the buildType of GitHub artifact
	// attestations (actions/attest-build-provenance).
	BuildTypeGitHubActionsWorkflow = "https://actions.github.io/buildtypes/workflow/v1"

	// BuildTypeSLSAGitHubWorkflow is the buildType used by
	// slsa-github-generator for GitHub Actions workflows.
	BuildTypeSLSAGitHubWorkflow = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"

	// BuildTypeGCBTriggered is the buildType of Google Cloud Build triggered builds.
	BuildTypeGCBTriggered = "https://slsa-framework.github.io/gcb-buildtypes/triggered-build/v1"
)

// sourceExtractors maps known build types to the externalParameters layout
// that carries the source repository.
//
//nolint:gochecknoglobals // immutable lookup table
var sourceExtractors = map[string]func(params map[string]any) sourceInfo{
	BuildTypeGitHubActionsWorkflow: func(params map[string]any) sourceInfo {
		return nestedSource(params, paramWorkflow)
	},
	BuildTypeSLSAGitHubWorkflow: func(params map[string]any) sourceInfo {
		return nestedSource(params, paramWorkflow)
	},
	BuildTypeGCBTriggered: gcbSource,
}

// gcbSource returns the source of a Cloud Build triggered build. The
// specification omits sourceToBuild (or leaves only its dir) when the built
// source is the configSource repository and ref. When both are present and
// differ, the configSource is recorded as the build configuration source:
// the build configuration controls the build steps, so it is verified too.
func gcbSource(params map[string]any) sourceInfo {
	config := nestedSource(params, paramConfigSource)

	built := nestedSource(params, paramSourceToBuild)
	if built.URI == "" {
		return config
	}

	if config.URI == "" {
		return built
	}

	if !sameRepository(built.URI, config.URI) {
		built.Config = &config

		return built
	}

	if built.Ref == "" {
		built.Ref = config.Ref
	}

	if config.Ref != "" && built.Ref != config.Ref {
		built.Config = &config
	}

	return built
}

// extractSourceV1 returns the source repository of a v1 provenance. Known
// build types use their documented layout first. Otherwise, or when that
// layout is absent, a top-level "source" parameter (a URI string or a
// ResourceDescriptor-like object) is used, falling back to the GitHub
// workflow and Cloud Build layouts.
func extractSourceV1(buildType string, params map[string]any) sourceInfo {
	if extract, known := sourceExtractors[buildType]; known {
		if info := extract(params); info.URI != "" {
			return info
		}
	}

	if info := topLevelSource(params); info.URI != "" {
		return info
	}

	if info := nestedSource(params, paramWorkflow); info.URI != "" {
		return info
	}

	return gcbSource(params)
}

// topLevelSource reads externalParameters.source, either as a URI string or
// as an object with "uri" and "digest".
func topLevelSource(params map[string]any) sourceInfo {
	var (
		raw    string
		digest string
	)

	switch source := params[metaSource].(type) {
	case string:
		raw = source
	case map[string]any:
		raw, _ = source["uri"].(string)
		digest = firstDigest(stringMap(source["digest"]))
	default:
	}

	if raw == "" {
		return sourceInfo{URI: "", Ref: "", Digest: "", Config: nil}
	}

	normalized, ref := normalizeSourceURI(raw)
	if explicitRef, isString := params["ref"].(string); isString && explicitRef != "" {
		ref = explicitRef
	}

	return sourceInfo{URI: normalized, Ref: ref, Digest: digest, Config: nil}
}

func nestedSource(params map[string]any, container string) sourceInfo {
	nested, ok := params[container].(map[string]any)
	if !ok {
		return sourceInfo{URI: "", Ref: "", Digest: "", Config: nil}
	}

	uri, _ := nested["repository"].(string)
	normalized, ref := normalizeSourceURI(uri)

	if explicitRef, isString := nested["ref"].(string); isString && explicitRef != "" {
		ref = explicitRef
	}

	return sourceInfo{URI: normalized, Ref: ref, Digest: "", Config: nil}
}

// stringMap converts a decoded JSON object with string values.
func stringMap(value any) map[string]string {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}

	converted := make(map[string]string, len(object))

	for key, val := range object {
		if text, isString := val.(string); isString {
			converted[key] = text
		}
	}

	return converted
}

// verifyResolvedSource cross-checks the source repository against
// resolvedDependencies. Every dependency that refers to the same repository
// must carry a digest and, when both sides name a ref, the same ref. A ref
// that is a commit SHA is compared against the dependency's commit digest
// instead, as is a source digest. When a build configuration source is
// recorded, a dependency of its repository may match either source, so the
// configuration and the built source of one repository can use different
// refs. The digest of the first matching dependency is recorded on the
// source it matched.
func verifyResolvedSource(source *sourceInfo, deps []resourceDescriptor) error {
	if source.URI == "" {
		return nil
	}

	sources := []*sourceInfo{source}
	if source.Config != nil && source.Config.URI != "" {
		sources = append(sources, source.Config)
	}

	for idx := range deps {
		err := verifyDependencyAgainst(sources, &deps[idx])
		if err != nil {
			return err
		}
	}

	return nil
}

// verifyDependencyAgainst verifies a dependency against the first source of
// the same repository it is consistent with. Dependencies of other
// repositories are ignored.
func verifyDependencyAgainst(sources []*sourceInfo, dep *resourceDescriptor) error {
	depURI, depRef := normalizeSourceURI(dep.URI)

	var firstErr error

	for _, candidate := range sources {
		if !sameRepository(depURI, candidate.URI) {
			continue
		}

		err := verifyDependency(candidate, dep, depRef)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}

			continue
		}

		if candidate.Digest == "" {
			candidate.Digest = firstDigest(dep.Digest)
		}

		return nil
	}

	return firstErr
}

func verifyDependency(source *sourceInfo, dep *resourceDescriptor, depRef string) error {
	if firstDigest(dep.Digest) == "" {
		return fmt.Errorf("%w: dependency %q has no digest", ErrSourceMismatch, dep.URI)
	}

	err := verifyDependencyRef(source, dep, depRef)
	if err != nil {
		return err
	}

	return verifyDependencyDigest(source, dep)
}

// verifyDependencyRef compares the source ref with the dependency ref, or a
// commit SHA source ref with the dependency's commit digest.
func verifyDependencyRef(source *sourceInfo, dep *resourceDescriptor, depRef string) error {
	if isCommitSHA(source.Ref) {
		commit := commitDigest(dep.Digest, source.Ref)
		if commit != "" && !strings.EqualFold(commit, source.Ref) {
			return fmt.Errorf(
				"%w: dependency %q resolved commit %q, source ref is commit %q",
				ErrSourceMismatch, dep.URI, commit, source.Ref,
			)
		}

		return nil
	}

	if source.Ref == "" || depRef == "" || isCommitSHA(depRef) || sameRef(source.Ref, depRef) {
		return nil
	}

	return fmt.Errorf(
		"%w: dependency %q has ref %q, source ref is %q",
		ErrSourceMismatch, dep.URI, depRef, source.Ref,
	)
}

// verifyDependencyDigest compares a known source digest with the dependency
// digest of the same algorithm.
func verifyDependencyDigest(source *sourceInfo, dep *resourceDescriptor) error {
	algorithm, value, found := strings.Cut(source.Digest, ":")
	if !found {
		return nil
	}

	depValue, present := dep.Digest[algorithm]
	if !present || strings.EqualFold(depValue, value) {
		return nil
	}

	return fmt.Errorf(
		"%w: dependency %q has %s digest %q, source digest is %q",
		ErrSourceMismatch, dep.URI, algorithm, depValue, value,
	)
}

// isCommitSHA reports whether ref is a git commit SHA (SHA-1 or SHA-256,
// lowercase hex).
func isCommitSHA(ref string) bool {
	if len(ref) != sha1HexLength && len(ref) != sha256HexLength {
		return false
	}

	for _, char := range ref {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}

	return true
}

// commitDigest returns the git commit digest of a dependency that is
// comparable with the commit SHA ref: a 40 hex character ref is compared with
// a gitCommit or sha1 digest, a 64 hex character ref with a gitCommit or
// sha256 digest. It returns "" when the dependency has no digest of the
// ref's length.
func commitDigest(digests map[string]string, ref string) string {
	algorithm := "sha1"
	if len(ref) == sha256HexLength {
		algorithm = "sha256"
	}

	for _, candidate := range []string{"gitCommit", algorithm} {
		value := digests[candidate]
		if len(value) == len(ref) && isCommitSHA(strings.ToLower(value)) {
			return value
		}
	}

	return ""
}

func sameRepository(a, b string) bool {
	normalize := func(uri string) string {
		return strings.TrimSuffix(strings.TrimSuffix(uri, "/"), ".git")
	}

	return strings.EqualFold(normalize(a), normalize(b))
}

// sameRef compares git refs. Two fully qualified refs must be identical, so
// refs/tags/v1 and refs/heads/v1 differ. A short name matches a branch or
// tag of that name.
func sameRef(left, right string) bool {
	if left == right {
		return true
	}

	const qualifiedPrefix = "refs/"

	if strings.HasPrefix(left, qualifiedPrefix) && strings.HasPrefix(right, qualifiedPrefix) {
		return false
	}

	short := func(ref string) string {
		for _, prefix := range []string{"refs/heads/", "refs/tags/"} {
			if name, found := strings.CutPrefix(ref, prefix); found {
				return name
			}
		}

		return ref
	}

	return short(left) == short(right)
}

func firstDigest(digests map[string]string) string {
	algorithms := make([]string, 0, len(digests))

	for algorithm, value := range digests {
		if value != "" {
			algorithms = append(algorithms, algorithm)
		}
	}

	if len(algorithms) == 0 {
		return ""
	}

	slices.Sort(algorithms)

	return algorithms[0] + ":" + digests[algorithms[0]]
}

func verifySubjectDigest(subjects []Subject, imageDigest string) error {
	for _, subject := range subjects {
		if types.MatchDigestInMap(imageDigest, subject.Digest) {
			return nil
		}
	}

	return fmt.Errorf("%w: none of the subjects match %q", ErrSubjectDigestMismatch, imageDigest)
}

// verifyBuilder checks whether the builder is in the trusted builders list.
// When a matched builder has a MaxLevel configured, a warning is logged because
// SLSA provenance does not declare a build level, so MaxLevel can only be
// enforced via VSA verification (vsa.minimumLevel). When bind is set it is
// called with all matched builder entries.
func verifyBuilder(
	ctx context.Context, builder Builder, pol *policy.Policy, bind builderBinder,
) error {
	builders := pol.Builders()
	if len(builders) == 0 {
		return nil
	}

	var matched []policy.TrustedBuilder

	for _, trusted := range builders {
		if trusted.ID != builder.ID {
			continue
		}

		matched = append(matched, trusted)

		if trusted.MaxLevel > 0 {
			if _, loaded := warnedMaxLevel.LoadOrStore(builder.ID, struct{}{}); !loaded {
				slog.WarnContext(ctx,
					"Builder has maxLevel configured but SLSA provenance does not "+
						"declare build levels; use VSA verification to enforce levels",
					"builder", builder.ID,
					"maxLevel", trusted.MaxLevel,
				)
			}
		}
	}

	if len(matched) == 0 {
		return fmt.Errorf("%w: %q", ErrUntrustedBuilder, builder.ID)
	}

	if bind != nil {
		err := bind(matched)
		if err != nil {
			return fmt.Errorf("%w: %q: %w", ErrUntrustedBuilder, builder.ID, err)
		}
	}

	return nil
}

func verifyBuildType(buildType string, pol *policy.Policy) error {
	if pol.Trust == nil || len(pol.Trust.BuildTypes) == 0 {
		return nil
	}

	if slices.Contains(pol.Trust.BuildTypes, buildType) {
		return nil
	}

	return fmt.Errorf("%w: %q", ErrUntrustedBuildType, buildType)
}

// verifySource checks whether the provenance source matches any trusted
// source pattern. '*' matches non-'/' characters, '**' matches any
// characters including '/'. See glob.MatchSource for ref-pinned patterns.
// The resolved ref is the explicit ref parameter when the provenance
// carries one, so a ref embedded in a URI cannot satisfy a ref-pinned
// pattern, and ref text cannot satisfy a repository wildcard.
// A build configuration source (from a different repository, or from the
// same repository at another ref) must match a trusted source pattern as
// well.
func verifySource(source *sourceInfo, pol *policy.Policy) error {
	if pol.Trust == nil || len(pol.Trust.Sources) == 0 {
		return nil
	}

	if source.URI == "" {
		return fmt.Errorf("%w: source not found in provenance", ErrUntrustedSource)
	}

	err := verifySourcePatterns(source, pol.Trust.Sources)
	if err != nil {
		return err
	}

	if source.Config != nil && source.Config.URI != "" {
		err = verifySourcePatterns(source.Config, pol.Trust.Sources)
		if err != nil {
			return fmt.Errorf("build configuration source: %w", err)
		}
	}

	return nil
}

func verifySourcePatterns(source *sourceInfo, patterns []string) error {
	for _, pattern := range patterns {
		matched, err := glob.MatchSource(pattern, source.URI, source.Ref)
		if err != nil {
			return fmt.Errorf("invalid source pattern %q: %w", pattern, err)
		}

		if matched {
			return nil
		}
	}

	return fmt.Errorf("%w: %q", ErrUntrustedSource, source.URI)
}

// verifyParameters rejects provenance with unrecognized externalParameters
// when rejectUnknownParameters is enabled. Uses the policy's KnownParameters
// list if configured, otherwise falls back to the GitHub Actions parameter set.
func verifyParameters(params map[string]any, pol *policy.Policy) error {
	if pol.SLSA == nil || !pol.SLSA.RejectUnknownParameters {
		return nil
	}

	known := pol.SLSA.KnownParameters
	if len(known) == 0 {
		known = defaultKnownParameters()
	}

	for paramKey := range params {
		if !slices.Contains(known, paramKey) {
			return fmt.Errorf("%w: %q", ErrUnknownParameters, paramKey)
		}
	}

	return nil
}

func defaultKnownParameters() []string {
	return []string{metaSource, "repository", "ref", paramWorkflow, metaBuildType}
}

var check = types.Checker{ //nolint:gochecknoglobals // package-scoped helper
	Type:    checkType,
	PassMsg: "SLSA provenance verified",
}

// ResetWarnings clears the deduplication state so that maxLevel
// and empty-trust warnings are re-emitted on the next verification cycle.
// Call this after a config reload to ensure warnings reflect the new policy state.
func ResetWarnings() {
	warnedMaxLevel.Clear()
	warnedEmptyTrust.Clear()
}

func trustConfigured(pol *policy.Policy) bool {
	if len(pol.Builders()) > 0 {
		return true
	}

	return pol.Trust != nil && (len(pol.Trust.Sources) > 0 || len(pol.Trust.BuildTypes) > 0)
}

func warnEmptyTrust(ctx context.Context, pol *policy.Policy) {
	if trustConfigured(pol) {
		return
	}

	if _, loaded := warnedEmptyTrust.LoadOrStore("empty", struct{}{}); loaded {
		return
	}

	slog.WarnContext(ctx,
		"SLSA verification has no trusted builders, sources, or build types configured; "+
			"any provenance passes builder and source checks with a warning status")
}

func verifyFreshness(buildStarted *time.Time, pol *policy.Policy) error {
	maxAgeConfigured := pol.SLSA != nil && pol.SLSA.MaxAge != ""

	// A zero time (as emitted for an unset Go time.Time) carries no
	// information and is treated as absent.
	if buildStarted == nil || buildStarted.IsZero() {
		if maxAgeConfigured {
			return fmt.Errorf("%w: no build timestamp in provenance", ErrStaleProvenance)
		}

		return nil
	}

	var maxAge *time.Duration
	if maxAgeConfigured {
		maxAge = &pol.SLSA.MaxAgeDuration
	}

	//nolint:wrapcheck // VerifyFreshness wraps the caller's sentinel errors
	return types.VerifyFreshness(
		*buildStarted,
		maxAge,
		"built",
		ErrFutureTimestamp,
		ErrStaleProvenance,
		ErrStaleProvenance,
	)
}
