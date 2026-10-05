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

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func (c *Config) validateOfflineConfig() error {
	switch c.Offline.Mode {
	case OfflineModeDisabled:
		return nil
	case OfflineModePreferBundle, OfflineModeOffline:
	default:
		return fmt.Errorf("%w: got %q", ErrInvalidOfflineMode, c.Offline.Mode)
	}

	var errs []error

	if c.Offline.AttestationStore == "" || !filepath.IsAbs(c.Offline.AttestationStore) {
		errs = append(errs, ErrOfflineStoreNotAbsolute)
	}

	if c.Offline.BundleMaxAge.Duration <= 0 {
		errs = append(errs, ErrBundleMaxAgeNotPositive)
	}

	errs = append(errs, c.validateOfflineBundlePolicy()...)

	return errors.Join(errs...)
}

func (c *Config) validateOfflineBundlePolicy() []error {
	var errs []error

	switch c.Offline.BundleExpiryPolicy {
	case BundleExpiryAllow, BundleExpiryWarn, BundleExpiryDeny:
	default:
		errs = append(errs, fmt.Errorf(
			"%w: got %q", ErrInvalidBundleExpiryPolicy, c.Offline.BundleExpiryPolicy,
		))
	}

	if c.Offline.RequireBundleSignature && c.Offline.BundleSignatureKey == "" {
		errs = append(errs, ErrBundleSignatureKeyRequired)
	}

	// The key verifies bundle signatures whenever it is set.
	if c.Offline.BundleSignatureKey != "" && !filepath.IsAbs(c.Offline.BundleSignatureKey) {
		errs = append(errs, ErrBundleSignatureKeyNotAbsolute)
	}

	return errs
}

func (c *Config) validateOfflineConfigRuntime() []error {
	if c.Offline.Mode == OfflineModeDisabled {
		return nil
	}

	var errs []error

	info, err := os.Lstat(c.Offline.AttestationStore)

	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf(
			"%w: %w", ErrOfflineStoreNotDirectory, err,
		))
	case info.Mode()&os.ModeSymlink != 0:
		errs = append(errs, fmt.Errorf(
			"%w: offline.attestation_store %q",
			ErrSymlinkNotAllowed, c.Offline.AttestationStore,
		))
	case !info.IsDir():
		errs = append(errs, fmt.Errorf(
			"%w: %q is not a directory", ErrOfflineStoreNotDirectory, c.Offline.AttestationStore,
		))
	}

	errs = append(errs, c.validateSignatureKeyFileRuntime()...)

	return errs
}

// validateSignatureKeyFileRuntime checks offline.bundle_signature_key whenever
// it is set: the key is used to verify bundle signatures even when
// require_bundle_signature is false.
func (c *Config) validateSignatureKeyFileRuntime() []error {
	if c.Offline.BundleSignatureKey == "" {
		return nil
	}

	_, err := checkContainedFile(&containedFile{
		label:         "offline.bundle_signature_key",
		path:          c.Offline.BundleSignatureKey,
		credential:    true,
		errNotFound:   ErrBundleSignatureKeyNotFound,
		errNotRegular: ErrBundleSignatureKeyNotFound,
	})
	if err != nil {
		return []error{err}
	}

	return nil
}
