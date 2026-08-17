// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugin

// KeySpec is type of the signing algorithm, including algorithm and size.
type KeySpec string

// KeySpec supported by notation.
//
// https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#algorithm-selection
const (
	KeySpecRSA2048 KeySpec = "RSA-2048"
	KeySpecRSA3072 KeySpec = "RSA-3072"
	KeySpecRSA4096 KeySpec = "RSA-4096"
	KeySpecEC256   KeySpec = "EC-256"
	KeySpecEC384   KeySpec = "EC-384"
	KeySpecEC521   KeySpec = "EC-521"
)

// HashAlgorithm supported by notation.
type HashAlgorithm string

// one of the following supported hash algorithm names.
//
// https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#algorithm-selection
const (
	HashAlgorithmSHA256 HashAlgorithm = "SHA-256"
	HashAlgorithmSHA384 HashAlgorithm = "SHA-384"
	HashAlgorithmSHA512 HashAlgorithm = "SHA-512"
)

// SignatureAlgorithm supported by notation
type SignatureAlgorithm string

// one of the following supported signing algorithm names.
//
// https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#algorithm-selection
const (
	SignatureAlgorithmECDSA_SHA256      SignatureAlgorithm = "ECDSA-SHA-256"
	SignatureAlgorithmECDSA_SHA384      SignatureAlgorithm = "ECDSA-SHA-384"
	SignatureAlgorithmECDSA_SHA512      SignatureAlgorithm = "ECDSA-SHA-512"
	SignatureAlgorithmRSASSA_PSS_SHA256 SignatureAlgorithm = "RSASSA-PSS-SHA-256"
	SignatureAlgorithmRSASSA_PSS_SHA384 SignatureAlgorithm = "RSASSA-PSS-SHA-384"
	SignatureAlgorithmRSASSA_PSS_SHA512 SignatureAlgorithm = "RSASSA-PSS-SHA-512"
)
