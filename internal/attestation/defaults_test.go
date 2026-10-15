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
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
)

// TestDefaultMaxAttestationSizeMatchesConfig keeps the fetcher default in
// line with the config default, which attestation does not import.
func TestDefaultMaxAttestationSizeMatchesConfig(t *testing.T) {
	t.Parallel()

	if attestation.DefaultMaxAttestationSize != config.DefaultMaxAttestationSize {
		t.Errorf("attestation default %d, config default %d",
			attestation.DefaultMaxAttestationSize, config.DefaultMaxAttestationSize)
	}
}
