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

package config

import "errors"

var (
	// ErrInvalidVerificationMode indicates an unrecognized verification mode.
	ErrInvalidVerificationMode = errors.New("invalid verification mode")

	// ErrFetchTimeoutNotPositive indicates a non-positive fetch timeout.
	ErrFetchTimeoutNotPositive = errors.New("fetch_timeout must be positive")

	// ErrDigestResolveTimeoutNotPositive indicates a non-positive digest resolve timeout.
	ErrDigestResolveTimeoutNotPositive = errors.New("digest_resolve_timeout must be positive")

	// ErrDigestResolveTimeoutTooHigh indicates the digest resolve timeout exceeds the maximum.
	ErrDigestResolveTimeoutTooHigh = errors.New("digest_resolve_timeout exceeds maximum")

	// ErrCacheTTLNegative indicates a negative cache TTL.
	ErrCacheTTLNegative = errors.New("cache_ttl must be non-negative")

	// ErrPolicyDirEmpty indicates an empty policy directory when verification is enabled.
	ErrPolicyDirEmpty = errors.New("policy_dir must not be empty when verification is enabled")

	// ErrPolicyDirNotAbsolute indicates a relative policy directory path.
	ErrPolicyDirNotAbsolute = errors.New("policy_dir is not absolute")

	// ErrPolicyDirNotDirectory indicates the policy dir path is not a directory.
	ErrPolicyDirNotDirectory = errors.New("policy_dir is not a directory")

	// ErrCircuitBreakerThreshold indicates the circuit breaker threshold is invalid.
	ErrCircuitBreakerThreshold = errors.New("circuit_breaker_threshold must be positive")

	// ErrCircuitBreakerCooldown indicates the circuit breaker cooldown is invalid.
	ErrCircuitBreakerCooldown = errors.New("circuit_breaker_cooldown must be positive")

	// ErrFetchRateLimitNegative indicates a negative fetch rate limit.
	ErrFetchRateLimitNegative = errors.New("fetch_rate_limit must be non-negative")

	// ErrFetchRateLimitTooHigh indicates the fetch rate limit exceeds the maximum.
	ErrFetchRateLimitTooHigh = errors.New("fetch_rate_limit exceeds maximum")

	// ErrCacheFailureTTLNegative indicates a negative cache failure TTL.
	ErrCacheFailureTTLNegative = errors.New("cache_failure_ttl must be non-negative")

	// ErrInvalidMetricsAddr indicates the metrics address is not a valid host:port.
	ErrInvalidMetricsAddr = errors.New("invalid metrics_addr")

	// ErrInvalidLogLevel indicates an unrecognized log level value.
	ErrInvalidLogLevel = errors.New("invalid log_level")

	// ErrUnknownConfigKeys indicates the config file contains unrecognized keys.
	ErrUnknownConfigKeys = errors.New("unknown config keys")

	// ErrInvalidTUFMirror indicates the sigstore.tuf_mirror URL is not valid.
	ErrInvalidTUFMirror = errors.New("invalid sigstore.tuf_mirror URL")

	// ErrTUFRootNotAbsolute indicates the sigstore.tuf_root path is not absolute.
	ErrTUFRootNotAbsolute = errors.New("sigstore.tuf_root must be an absolute path")

	// ErrTUFRootNotFound indicates the sigstore.tuf_root file does not exist.
	ErrTUFRootNotFound = errors.New("sigstore.tuf_root file not found")

	// ErrTUFRootRequiresMirror indicates tuf_root is set without tuf_mirror.
	ErrTUFRootRequiresMirror = errors.New(
		"sigstore.tuf_root requires sigstore.tuf_mirror to be set",
	)

	// ErrTUFRootEmpty indicates the sigstore.tuf_root file is empty.
	ErrTUFRootEmpty = errors.New("sigstore.tuf_root file is empty")

	// ErrTUFRootNotRegularFile indicates the sigstore.tuf_root path is not a regular file.
	ErrTUFRootNotRegularFile = errors.New("sigstore.tuf_root is not a regular file")

	// ErrRegistryPrefixEmpty indicates a registry entry has an empty prefix.
	ErrRegistryPrefixEmpty = errors.New("registry prefix must not be empty")

	// ErrRegistryCACertNotAbsolute indicates a registry CA cert path is not absolute.
	ErrRegistryCACertNotAbsolute = errors.New("registry ca_cert path must be absolute")

	// ErrRegistryCACertNotFound indicates a registry CA cert file does not exist.
	ErrRegistryCACertNotFound = errors.New("registry ca_cert file not found")

	// ErrDuplicateRegistryPrefix indicates multiple registries share the same prefix.
	ErrDuplicateRegistryPrefix = errors.New("duplicate registry prefix")

	// ErrRegistryPrefixInvalid indicates a registry prefix is not a valid hostname.
	ErrRegistryPrefixInvalid = errors.New("registry prefix is not a valid hostname")

	// ErrRegistryMirrorInvalid indicates a registry mirror is not a valid hostname.
	ErrRegistryMirrorInvalid = errors.New("registry mirror is not a valid hostname")

	// ErrRegistryMirrorSameAsPrefix indicates the mirror equals the prefix.
	ErrRegistryMirrorSameAsPrefix = errors.New("registry mirror must differ from prefix")

	// ErrInvalidPolicySource indicates the policy source is not "local" or "oci".
	ErrInvalidPolicySource = errors.New("policy.source must be \"local\" or \"oci\"")

	// ErrPolicyOCIRefRequired indicates the OCI reference is missing when source is "oci".
	ErrPolicyOCIRefRequired = errors.New("policy.oci_ref is required when policy.source is \"oci\"")

	// ErrPolicyOCIRefInvalid indicates the OCI reference could not be parsed.
	ErrPolicyOCIRefInvalid = errors.New("policy.oci_ref is not a valid OCI reference")

	// ErrPollIntervalTooShort indicates the poll interval is below the minimum.
	ErrPollIntervalTooShort = errors.New("policy.poll_interval must be at least 30s")

	// ErrPolicyIssuersAndKeysMutuallyExclusive indicates both issuers and keys
	// are configured, which is not supported by sigstore-go.
	ErrPolicyIssuersAndKeysMutuallyExclusive = errors.New(
		"policy.issuers and policy.keys are mutually exclusive",
	)

	// ErrPolicySANPatternsWithoutIssuers indicates san_patterns is set
	// without issuers.
	ErrPolicySANPatternsWithoutIssuers = errors.New(
		"policy.san_patterns requires policy.issuers",
	)

	// ErrPolicyIssuerEmpty indicates an empty string in the issuers list.
	ErrPolicyIssuerEmpty = errors.New("policy.issuers entries must not be empty")

	// ErrPolicySANPatternEmpty indicates an empty string in the san_patterns list.
	ErrPolicySANPatternEmpty = errors.New("policy.san_patterns entries must not be empty")

	// ErrPolicySignatureKeyNotAbsolute indicates a policy key path is not absolute.
	ErrPolicySignatureKeyNotAbsolute = errors.New(
		"policy.keys path must be absolute",
	)

	// ErrPolicySignatureKeyDuplicate indicates the same key path appears
	// more than once.
	ErrPolicySignatureKeyDuplicate = errors.New(
		"duplicate policy.keys path",
	)

	// ErrPolicyKeyEmpty indicates an empty string in the keys list.
	ErrPolicyKeyEmpty = errors.New("policy.keys entries must not be empty")

	// ErrVerificationTimeoutNotPositive indicates a non-positive verification timeout.
	ErrVerificationTimeoutNotPositive = errors.New("verification_timeout must be positive")

	// ErrVerificationTimeoutTooHigh indicates the verification timeout exceeds the maximum.
	ErrVerificationTimeoutTooHigh = errors.New("verification_timeout exceeds maximum")

	// ErrInsecureRegistryInEnforceMode indicates that insecure TLS cannot be
	// used with enforce mode because it allows MITM on attestation transport.
	ErrInsecureRegistryInEnforceMode = errors.New(
		"insecure registry is not allowed in enforce mode; use ca_cert for custom CAs",
	)

	// ErrSymlinkNotAllowed indicates a path is a symbolic link.
	ErrSymlinkNotAllowed = errors.New("symbolic links are not allowed")

	// ErrPolicyKeyNotRegularFile indicates a policy key path is not a regular file.
	ErrPolicyKeyNotRegularFile = errors.New("policy.keys path is not a regular file")

	// ErrConfigFileTooLarge indicates the config file exceeds the size limit.
	ErrConfigFileTooLarge = errors.New("config file exceeds maximum size")

	// ErrSigstoreRootNameRequired indicates a sigstore.roots entry is missing its name.
	ErrSigstoreRootNameRequired = errors.New("sigstore.roots[].name must not be empty")

	// ErrSigstoreRootNameDuplicate indicates two sigstore.roots entries share the same name.
	ErrSigstoreRootNameDuplicate = errors.New("duplicate sigstore.roots[].name")

	// ErrSigstoreRootsMutualExclusion indicates both scalar tuf_mirror/tuf_root and
	// the new roots array are set, which is not allowed.
	ErrSigstoreRootsMutualExclusion = errors.New(
		"sigstore.tuf_mirror/tuf_root and sigstore.roots are mutually exclusive",
	)
)
