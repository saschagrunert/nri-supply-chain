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

package types

import "fmt"

// MaxComponentDepth bounds recursion into nested CycloneDX components. A
// document nesting components deeper is rejected rather than truncated, so
// deeply nested components can neither escape the SBOM checks nor the VEX
// component matching.
const MaxComponentDepth = 32

// ErrComponentsTooDeep indicates components nested deeper than
// MaxComponentDepth.
var ErrComponentsTooDeep = fmt.Errorf(
	"components nested deeper than %d levels", MaxComponentDepth,
)
