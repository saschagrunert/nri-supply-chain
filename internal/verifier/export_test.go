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
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// ExportBuildDigestRef exposes buildDigestRef for external tests.
func ExportBuildDigestRef(imageRef, digest string) string {
	return buildDigestRef(imageRef, digest)
}

// ExportHandleMissingAttestation exposes handleMissingAttestation for external tests.
func ExportHandleMissingAttestation(pol, checkType, detail string) *types.CheckResult {
	return handleMissingAttestation(pol, checkType, detail)
}

// ExportWarnEnforceDefaults exposes warnEnforceDefaults for external tests.
func ExportWarnEnforceDefaults(cfg *config.Config, policies map[string]*policy.Policy) {
	warnEnforceDefaults(cfg, policies)
}

// ExportResultHasFailures exposes resultHasFailures for external tests.
func ExportResultHasFailures(result *types.Result) bool {
	return resultHasFailures(result)
}

// ExportCacheAffectingFieldsChanged exposes cacheAffectingFieldsChanged for external tests.
func ExportCacheAffectingFieldsChanged(prev, next *config.Config) bool {
	return cacheAffectingFieldsChanged(prev, next)
}
