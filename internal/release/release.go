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

// Package release provides release attestation verification for supply chain checks.
package release

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/saschagrunert/nri-supply-chain/internal/checker"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/purl"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var (
	// ErrInvalidRelease indicates the release attestation could not be parsed.
	ErrInvalidRelease = errors.New("invalid release attestation")

	// ErrUntrustedRegistry indicates the release purl does not match trusted registries.
	ErrUntrustedRegistry = errors.New("release purl does not match trusted registries")

	// ErrMissingPackageID indicates the release attestation is missing the required packageId.
	ErrMissingPackageID = errors.New("release attestation missing required packageId")

	errMissingPURL = errors.New("purl is required")
)

// qualifierRepositoryURL is the purl qualifier naming the repository a
// package was published to.
const qualifierRepositoryURL = "repository_url"

type releasePredicate struct {
	PURL      string `json:"purl"`
	PackageID string `json:"packageId,omitempty"` //nolint:tagliatelle // matches in-toto release spec field name
}

//nolint:gochecknoglobals // immutable check declaration
var spec = &checker.Spec[releasePredicate]{
	Info: checker.Info{
		Type:  types.CheckTypeRelease,
		Label: "release",
	},
	Aggregation: checker.FirstPass,
	ErrInvalid:  ErrInvalidRelease,
	Validate:    validatePredicate,
	Meta: func(pred *releasePredicate) map[string]any {
		return map[string]any{
			"purl":      pred.PURL,
			"packageId": pred.PackageID,
		}
	},
	Freshness: nil,
	Rules: []checker.Rule[releasePredicate]{
		checkTrustedRegistry,
		checkPackageID,
	},
	Merge: nil,
}

// Info returns the check type and label of the release check.
func Info() checker.Info {
	return spec.Info
}

// Verify checks a single release attestation against the given policy.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.Verify(ctx, att, pol, imageDigest)
}

// VerifyMultiple checks multiple release attestations, accepting if any valid one passes.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.VerifyMultiple(ctx, attestations, pol, imageDigest)
}

func validatePredicate(pred *releasePredicate) error {
	if strings.TrimSpace(pred.PURL) == "" {
		return errMissingPURL
	}

	return nil
}

func checkTrustedRegistry(pred *releasePredicate, pol *policy.Policy) string {
	if pol.Release == nil || len(pol.Release.TrustedRegistries) == 0 {
		return ""
	}

	parsed, err := purl.Parse(pred.PURL)
	if err != nil {
		return fmt.Sprintf("%s: %q is not a valid package URL", ErrUntrustedRegistry, pred.PURL)
	}

	candidates := registryCandidates(&parsed)

	for _, pattern := range pol.Release.TrustedRegistries {
		for _, candidate := range candidates {
			matched, err := glob.Match(pattern, candidate)
			if err != nil {
				return fmt.Sprintf("invalid registry pattern %q: %s", pattern, err)
			}

			if matched {
				return ""
			}
		}
	}

	return fmt.Sprintf("%s: %q", ErrUntrustedRegistry, pred.PURL)
}

// registryCandidates returns the strings trustedRegistries patterns are
// matched against, all built from the parsed and percent-decoded purl so
// that encoding and qualifier order cannot change the result. For a purl
// with a repository_url qualifier (as the OCI purl specification requires)
// that is the location "pkg:type/<repository_url>" with the package name
// appended when the URL does not already end with it. The package identity
// "pkg:type/namespace/name" is only matched without repository_url, since it
// names the type's default registry, so a trusted identity cannot vouch for
// a package published to another registry. Both forms are also matched with
// "@version". Qualifiers other than repository_url and the subpath are never
// matched.
func registryCandidates(parsed *purl.PURL) []string {
	prefix := "pkg:" + parsed.Type + "/"

	path := repositoryLocation(parsed)
	if path == "" {
		path = packagePath(parsed)
	}

	candidates := []string{prefix + path}
	if parsed.Version != "" {
		candidates = append(candidates, prefix+path+"@"+parsed.Version)
	}

	return candidates
}

// packagePath returns "namespace/name", or the name without a namespace.
func packagePath(parsed *purl.PURL) string {
	if parsed.Namespace == "" {
		return parsed.Name
	}

	return parsed.Namespace + "/" + parsed.Name
}

// repositoryLocation returns the repository_url qualifier without URL scheme
// and trailing slashes, ending with the package namespace and name.
func repositoryLocation(parsed *purl.PURL) string {
	location := strings.TrimSpace(parsed.Qualifiers[qualifierRepositoryURL])
	if _, rest, found := strings.Cut(location, "://"); found {
		location = rest
	}

	location = strings.TrimRight(location, "/")
	if location == "" {
		return ""
	}

	pkgPath := packagePath(parsed)
	if location == pkgPath || strings.HasSuffix(location, "/"+pkgPath) {
		return location
	}

	return location + "/" + pkgPath
}

func checkPackageID(pred *releasePredicate, pol *policy.Policy) string {
	if pol.Release == nil || !pol.Release.RequirePackageID {
		return ""
	}

	if strings.TrimSpace(pred.PackageID) == "" {
		return ErrMissingPackageID.Error()
	}

	return ""
}
