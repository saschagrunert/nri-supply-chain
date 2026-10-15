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

package testutil

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
)

// errExternalNetwork is returned for DNS lookups in hermetic tests.
var errExternalNetwork = errors.New("tests must not resolve external hosts")

// RunHermetic runs the tests of a package without access to external hosts:
// DNS lookups fail, so the public Sigstore TUF repository, Docker Hub and
// other registries cannot be reached and tests cannot depend on them.
// Loopback addresses (httptest servers) and /etc/hosts entries such as
// localhost keep working. Call it from TestMain.
func RunHermetic(m *testing.M) {
	net.DefaultResolver = &net.Resolver{
		PreferGo:     true,
		StrictErrors: false,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errExternalNetwork
		},
	}

	os.Exit(m.Run())
}
