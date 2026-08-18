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

package registry

import (
	"io"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

//nolint:gochecknoglobals // singleton keychain avoids per-call allocations
var multiKeychain = authn.NewMultiKeychain(
	authn.DefaultKeychain,
	google.Keychain,
	authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard))),
	authn.NewKeychainFromHelper(newACRHelper()),
)

// AuthOption returns a remote.Option that authenticates using a multi-keychain
// chaining cloud provider credential helpers (GCR/Artifact Registry, AWS ECR,
// Azure ACR) with the default Docker keychain. Each cloud keychain is a no-op
// when its credentials are not present, so the chain safely falls through to
// the next provider.
func AuthOption() remote.Option {
	return remote.WithAuthFromKeychain(multiKeychain)
}
