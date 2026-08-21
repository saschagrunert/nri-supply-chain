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

	// ErrFetchTimeoutTooHigh indicates the fetch timeout exceeds the maximum.
	ErrFetchTimeoutTooHigh = errors.New("fetch_timeout exceeds maximum")

	// ErrCacheTTLTooHigh indicates the cache TTL exceeds the maximum.
	ErrCacheTTLTooHigh = errors.New("cache_ttl exceeds maximum")

	// ErrCacheFailureTTLTooHigh indicates the cache failure TTL exceeds the maximum.
	ErrCacheFailureTTLTooHigh = errors.New("cache_failure_ttl exceeds maximum")

	// ErrCircuitBreakerCooldownTooHigh indicates the circuit breaker cooldown exceeds the maximum.
	ErrCircuitBreakerCooldownTooHigh = errors.New("circuit_breaker_cooldown exceeds maximum")

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

	// ErrCheckTimeoutNotPositive indicates a non-positive check timeout.
	ErrCheckTimeoutNotPositive = errors.New("check_timeout must be positive")

	// ErrCheckTimeoutExceedsVerification indicates check_timeout is larger than verification_timeout.
	ErrCheckTimeoutExceedsVerification = errors.New(
		"check_timeout must not exceed verification_timeout",
	)

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

	// ErrMaxAttestationSizeTooSmall indicates the max attestation size is below the minimum.
	ErrMaxAttestationSizeTooSmall = errors.New("max_attestation_size must be at least 1 MiB")

	// ErrMaxAttestationSizeTooLarge indicates the max attestation size exceeds the maximum.
	ErrMaxAttestationSizeTooLarge = errors.New("max_attestation_size must not exceed 100 MiB")

	// ErrCacheMaxEntriesTooSmall indicates the cache max entries is below the minimum.
	ErrCacheMaxEntriesTooSmall = errors.New("cache_max_entries must be at least 100")

	// ErrCacheMaxEntriesTooLarge indicates the cache max entries exceeds the maximum.
	ErrCacheMaxEntriesTooLarge = errors.New("cache_max_entries must not exceed 1000000")

	// ErrConfigVersionTooNew indicates the config_version is newer than the plugin supports.
	ErrConfigVersionTooNew = errors.New("config_version is newer than this plugin supports")

	// ErrInvalidConfigVersion indicates the config_version is not a valid positive integer.
	ErrInvalidConfigVersion = errors.New("config_version must be a positive integer")

	// ErrAllowlistDigestInvalid indicates an allowlist_digests entry is not a valid OCI digest.
	ErrAllowlistDigestInvalid = errors.New("invalid allowlist digest")

	// ErrIssuersWithoutSANPatternsInEnforce indicates that policy.issuers is
	// set without policy.san_patterns in enforce mode, which accepts any
	// certificate identity from the configured issuers.
	ErrIssuersWithoutSANPatternsInEnforce = errors.New(
		"policy.issuers requires policy.san_patterns in enforce mode",
	)

	// ErrAuditLogNotAbsolute indicates the audit_log path is not absolute.
	ErrAuditLogNotAbsolute = errors.New("audit_log must be an absolute path")

	// ErrGUACEndpointInvalid indicates the GUAC endpoint URL is not valid.
	ErrGUACEndpointInvalid = errors.New("invalid guac.endpoint URL")

	// ErrGUACTimeoutNotPositive indicates a non-positive GUAC timeout.
	ErrGUACTimeoutNotPositive = errors.New("guac.timeout must be positive")

	// ErrGUACTimeoutTooHigh indicates the GUAC timeout exceeds the maximum.
	ErrGUACTimeoutTooHigh = errors.New("guac.timeout exceeds maximum")

	// ErrGUACInvalidFallbackPolicy indicates an unrecognized GUAC fallback policy.
	ErrGUACInvalidFallbackPolicy = errors.New(
		`guac.fallback_policy must be "allow", "warn", or "deny"`,
	)

	// ErrGUACInvalidCheck indicates an unrecognized GUAC check name.
	ErrGUACInvalidCheck = errors.New("invalid guac.checks entry")

	// ErrGUACChecksEmpty indicates no GUAC checks are configured when endpoint is set.
	ErrGUACChecksEmpty = errors.New("guac.checks must not be empty when guac.endpoint is set")

	// ErrGUACMaxDepsRange indicates the max dependencies count is out of range.
	ErrGUACMaxDepsRange = errors.New("guac.max_dependencies must be between 1 and 20")

	// ErrGUACAuthTokenPathNotAbsolute indicates the auth token path is not absolute.
	ErrGUACAuthTokenPathNotAbsolute = errors.New("guac.auth_token_path must be an absolute path")

	// ErrGUACAuthTokenNotRegularFile indicates the auth token path is not a regular file.
	ErrGUACAuthTokenNotRegularFile = errors.New("guac.auth_token_path must be a regular file")

	// ErrGUACCACertPathNotAbsolute indicates the CA cert path is not absolute.
	ErrGUACCACertPathNotAbsolute = errors.New("guac.ca_cert path must be an absolute path")

	// ErrGUACCACertNotFound indicates the CA cert file does not exist.
	ErrGUACCACertNotFound = errors.New("guac.ca_cert file not found")

	// ErrGUACCACertNotRegularFile indicates the CA cert path is not a regular file.
	ErrGUACCACertNotRegularFile = errors.New("guac.ca_cert must be a regular file")

	// ErrInvalidOfflineMode indicates the offline.mode value is not recognized.
	ErrInvalidOfflineMode = errors.New(
		`offline.mode must be "disabled", "prefer-bundle", or "offline"`,
	)

	// ErrOfflineStoreNotAbsolute indicates the attestation_store path is not absolute.
	ErrOfflineStoreNotAbsolute = errors.New("offline.attestation_store must be an absolute path")

	// ErrOfflineStoreNotDirectory indicates the attestation_store path is not a directory.
	ErrOfflineStoreNotDirectory = errors.New("offline.attestation_store is not a directory")

	// ErrBundleMaxAgeNotPositive indicates bundle_max_age is not positive.
	ErrBundleMaxAgeNotPositive = errors.New("offline.bundle_max_age must be positive")

	// ErrInvalidBundleExpiryPolicy indicates the expiry policy is not recognized.
	ErrInvalidBundleExpiryPolicy = errors.New(
		`offline.bundle_expiry_policy must be "allow", "warn", or "deny"`,
	)

	// ErrBundleSignatureKeyRequired indicates a signature key is needed but missing.
	ErrBundleSignatureKeyRequired = errors.New(
		"offline.bundle_signature_key required when require_bundle_signature is true",
	)

	// ErrBundleSignatureKeyNotAbsolute indicates the signature key path is not absolute.
	ErrBundleSignatureKeyNotAbsolute = errors.New(
		"offline.bundle_signature_key must be an absolute path",
	)

	// ErrBundleSignatureKeyNotFound indicates the signature key file does not exist.
	ErrBundleSignatureKeyNotFound = errors.New("offline.bundle_signature_key file not found")

	// ErrRemediationModeInvalid indicates an unrecognized remediation mode.
	ErrRemediationModeInvalid = errors.New(
		`remediation.mode must be "warn", "throttle", or "evict"`,
	)

	// ErrRemediationEvictRequiresEnforce indicates mode=evict is incompatible
	// with verification=warn (would cause infinite evict-restart loops).
	ErrRemediationEvictRequiresEnforce = errors.New(
		"remediation.mode=evict requires verification=enforce",
	)

	// ErrRemediationIntervalTooShort indicates the re-verification interval
	// is below the minimum.
	ErrRemediationIntervalTooShort = errors.New("remediation.interval is too short")

	// ErrRemediationIntervalTooLong indicates the re-verification interval
	// exceeds the maximum.
	ErrRemediationIntervalTooLong = errors.New("remediation.interval is too long")

	// ErrRemediationBatchSizeInvalid indicates a non-positive batch size.
	ErrRemediationBatchSizeInvalid = errors.New(
		"remediation.batch_size must be positive",
	)

	// ErrRemediationBatchSizeTooLarge indicates the batch size exceeds the maximum.
	ErrRemediationBatchSizeTooLarge = errors.New(
		"remediation.batch_size exceeds maximum",
	)

	// ErrRemediationFeedDirNotAbsolute indicates the feed directory path is
	// not absolute.
	ErrRemediationFeedDirNotAbsolute = errors.New(
		"remediation.feed_dir must be an absolute path",
	)

	// ErrThrottlePercentOutOfRange indicates a throttle percentage is outside 1-100.
	ErrThrottlePercentOutOfRange = errors.New(
		"remediation.throttle percentage must be between 1 and 100",
	)

	// ErrRemediationFeedDirNotDirectory indicates the feed directory exists
	// but is not a directory.
	ErrRemediationFeedDirNotDirectory = errors.New(
		"remediation.feed_dir is not a directory",
	)

	// ErrRemediationCooldownTooShort indicates the cooldown is below the minimum.
	ErrRemediationCooldownTooShort = errors.New("remediation.cooldown is too short")

	// ErrRemediationCooldownTooLong indicates the cooldown exceeds the maximum.
	ErrRemediationCooldownTooLong = errors.New("remediation.cooldown is too long")
)
