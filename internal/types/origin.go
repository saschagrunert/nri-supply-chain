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

import "context"

// VerifyOrigin tells why a verification runs. Background verifications of
// running containers are recorded apart from admission decisions.
type VerifyOrigin string

const (
	// OriginAdmission is a container admission (the default).
	OriginAdmission VerifyOrigin = ""
	// OriginPrewarm is cache pre-warming for running containers.
	OriginPrewarm VerifyOrigin = "prewarm"
	// OriginReverification is a re-verification of running containers by
	// the continuous verifier.
	OriginReverification VerifyOrigin = "reverification"
)

type verifyOriginKey struct{}

// WithVerifyOrigin returns a context whose verifications have origin.
func WithVerifyOrigin(ctx context.Context, origin VerifyOrigin) context.Context {
	return context.WithValue(ctx, verifyOriginKey{}, origin)
}

// VerifyOriginFrom returns the origin of the verifications of ctx.
func VerifyOriginFrom(ctx context.Context) VerifyOrigin {
	origin, ok := ctx.Value(verifyOriginKey{}).(VerifyOrigin)
	if !ok {
		return OriginAdmission
	}

	return origin
}
