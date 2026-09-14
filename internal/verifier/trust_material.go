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

package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"slices"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

// trustFingerprint identifies the content of every trust material file that
// verification results depend on. Policies only reference key and
// certificate files by path, so replacing a compromised key in place (and
// sending SIGHUP) does not change any policy hash; the fingerprint does, and
// invalidates cached results.
type trustFingerprint struct {
	// policy covers keys and certificates referenced by policies and the
	// policy and bundle signature keys of the operational config.
	policy string
	// sigstore covers the custom Sigstore TUF root files.
	sigstore string
}

func (f trustFingerprint) String() string {
	return f.policy + ":" + f.sigstore
}

func computeTrustFingerprint(
	cfg *config.Config, policies map[string]*policy.Policy,
) trustFingerprint {
	return trustFingerprint{
		policy:   hashFiles(policyTrustPaths(cfg, policies)),
		sigstore: hashFiles(sigstoreRootPaths(cfg)),
	}
}

func policyTrustPaths(cfg *config.Config, policies map[string]*policy.Policy) []string {
	paths := slices.Clone(cfg.Policy.Keys)

	if cfg.Offline.BundleSignatureKey != "" {
		paths = append(paths, cfg.Offline.BundleSignatureKey)
	}

	for _, pol := range policies {
		paths = appendSectionTrustPaths(paths, &pol.Sections)

		for idx := range pol.Rules {
			paths = appendSectionTrustPaths(paths, &pol.Rules[idx].Sections)
		}
	}

	return paths
}

func appendSectionTrustPaths(paths []string, sections *policy.Sections) []string {
	if sections.Trust != nil {
		for idx := range sections.Trust.Verifiers {
			paths = append(paths, sections.Trust.Verifiers[idx].Keys...)
		}

		for idx := range sections.Trust.Builders {
			paths = append(paths, sections.Trust.Builders[idx].Keys...)
		}
	}

	if sections.Notation != nil {
		for idx := range sections.Notation.TrustStores {
			paths = append(paths, sections.Notation.TrustStores[idx].Certificates...)
		}
	}

	return paths
}

func sigstoreRootPaths(cfg *config.Config) []string {
	var paths []string

	for _, root := range cfg.Sigstore.EffectiveRoots() {
		if root.TUFRoot != "" {
			paths = append(paths, root.TUFRoot)
		}
	}

	return paths
}

// hashFiles hashes the sorted, de-duplicated paths together with the SHA-256
// of each file's content. Unreadable files contribute their error so that a
// file appearing or disappearing also changes the fingerprint.
func hashFiles(paths []string) string {
	if len(paths) == 0 {
		return ""
	}

	cleaned := make([]string, 0, len(paths))
	for _, path := range paths {
		cleaned = append(cleaned, filepath.Clean(path))
	}

	slices.Sort(cleaned)
	cleaned = slices.Compact(cleaned)

	digest := sha256.New()

	for _, path := range cleaned {
		digest.Write([]byte(path))
		digest.Write([]byte{0})

		data, err := fileutil.ReadLimited(path, fileutil.MaxCredentialFileSize)
		if err != nil {
			digest.Write([]byte("unreadable:" + err.Error()))
		} else {
			sum := sha256.Sum256(data)
			digest.Write(sum[:])
		}

		digest.Write([]byte{0})
	}

	return hex.EncodeToString(digest.Sum(nil))
}
