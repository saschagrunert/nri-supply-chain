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
	"log/slog"
	"net"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
)

func (c *Config) validateRegistryCACertsRuntime() []error {
	var errs []error

	for idx := range c.Registries {
		reg := &c.Registries[idx]
		if reg.CACert == "" {
			continue
		}

		_, err := checkContainedFile(&containedFile{
			label:         fmt.Sprintf("registries[%d].ca_cert", idx),
			path:          reg.CACert,
			credential:    false,
			errNotFound:   ErrRegistryCACertNotFound,
			errNotRegular: ErrRegistryCACertNotRegularFile,
		})
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func (c *Config) validateTUFRootRuntime() []error {
	var errs []error

	if c.Sigstore.TUFRoot != "" {
		errs = append(errs, validateTUFRootFile(c.Sigstore.TUFRoot, "sigstore.tuf_root")...)
	}

	for idx := range c.Sigstore.Roots {
		if c.Sigstore.Roots[idx].TUFRoot != "" {
			label := fmt.Sprintf("sigstore.roots[%d].tuf_root", idx)
			errs = append(errs, validateTUFRootFile(c.Sigstore.Roots[idx].TUFRoot, label)...)
		}
	}

	if len(errs) == 0 {
		return nil
	}

	return errs
}

func validateTUFRootFile(path, label string) []error {
	rootInfo, err := checkContainedFile(&containedFile{
		label:         label,
		path:          path,
		credential:    false,
		errNotFound:   ErrTUFRootNotFound,
		errNotRegular: ErrTUFRootNotRegularFile,
	})
	if err != nil {
		return []error{err}
	}

	if rootInfo.Size() == 0 {
		return []error{fmt.Errorf(
			"%w: %q", ErrTUFRootEmpty, path,
		)}
	}

	return nil
}

func isValidRegistryHost(host string) bool {
	if host == "" || strings.ContainsAny(host, " \t\n/") {
		return false
	}

	if strings.Contains(host, "://") {
		return false
	}

	hostname := host

	h, _, err := net.SplitHostPort(host)
	if err == nil {
		hostname = h
	}

	return !slices.Contains(strings.Split(hostname, "."), "")
}

func (c *Config) validateRegistries() error {
	var errs []error //nolint:prealloc // conditional appends

	seen := make(map[string]int, len(c.Registries))

	for idx := range c.Registries {
		errs = append(errs, c.validateRegistry(&c.Registries[idx], idx, seen)...)
	}

	return errors.Join(errs...)
}

func (c *Config) validateRegistry(
	reg *Registry, idx int, seen map[string]int,
) []error {
	var errs []error

	errs = append(errs, validateRegistryPrefix(reg, idx, seen)...)
	errs = append(errs, validateRegistryMirror(reg, idx)...)

	if reg.CACert != "" && !filepath.IsAbs(reg.CACert) {
		errs = append(errs, fmt.Errorf(
			"%w: registries[%d] ca_cert %q",
			ErrRegistryCACertNotAbsolute, idx, reg.CACert,
		))
	}

	if reg.Insecure && c.Verification == ModeEnforce {
		errs = append(errs, fmt.Errorf(
			"%w: registries[%d] %q",
			ErrInsecureRegistryInEnforceMode, idx, reg.Prefix,
		))
	} else if reg.Insecure && c.Verification == ModeWarn {
		slog.Warn(
			"Insecure registry in warn mode allows MITM on attestation transport; "+
				"consider using ca_cert instead",
			"registry", reg.Prefix,
		)
	}

	return errs
}

func validateRegistryPrefix(
	reg *Registry, idx int, seen map[string]int,
) []error {
	var errs []error

	if reg.Prefix == "" {
		return append(errs, fmt.Errorf(
			"%w: registries[%d]", ErrRegistryPrefixEmpty, idx,
		))
	}

	if !isValidRegistryHost(reg.Prefix) {
		errs = append(errs, fmt.Errorf(
			"%w: registries[%d] %q",
			ErrRegistryPrefixInvalid, idx, reg.Prefix,
		))
	}

	normalized := normalizePrefix(reg.Prefix)

	if prevIdx, ok := seen[normalized]; ok {
		errs = append(errs, fmt.Errorf(
			"%w: %q at registries[%d] and registries[%d]",
			ErrDuplicateRegistryPrefix, reg.Prefix, prevIdx, idx,
		))
	} else {
		seen[normalized] = idx
	}

	return errs
}

func validateRegistryMirror(reg *Registry, idx int) []error {
	if reg.Mirror == "" {
		return nil
	}

	var errs []error

	if !isValidRegistryHost(reg.Mirror) {
		errs = append(errs, fmt.Errorf(
			"%w: registries[%d] %q",
			ErrRegistryMirrorInvalid, idx, reg.Mirror,
		))
	}

	if normalizePrefix(reg.Mirror) == normalizePrefix(reg.Prefix) {
		errs = append(errs, fmt.Errorf(
			"%w: registries[%d] %q",
			ErrRegistryMirrorSameAsPrefix, idx, reg.Prefix,
		))
	}

	return errs
}

func (c *Config) validateSigstoreConfig() error {
	var errs []error

	hasScalarFields := c.Sigstore.TUFMirror != "" || c.Sigstore.TUFRoot != ""
	hasRoots := len(c.Sigstore.Roots) > 0

	if hasScalarFields && hasRoots {
		errs = append(errs, ErrSigstoreRootsMutualExclusion)

		return errors.Join(errs...)
	}

	if c.Sigstore.TUFMirror != "" {
		err := validateTUFMirrorURL(c.Sigstore.TUFMirror)
		if err != nil {
			errs = append(errs, err)
		}
	}

	if c.Sigstore.TUFRoot != "" {
		if !filepath.IsAbs(c.Sigstore.TUFRoot) {
			errs = append(errs, fmt.Errorf("%w: %q", ErrTUFRootNotAbsolute, c.Sigstore.TUFRoot))
		}
	}

	errs = append(errs, validateSigstoreRoots(c.Sigstore.Roots)...)

	return errors.Join(errs...)
}

func validateSigstoreRoots(roots []SigstoreRootSource) []error {
	if len(roots) == 0 {
		return nil
	}

	var errs []error

	seen := make(map[string]int, len(roots))

	for idx := range roots {
		root := &roots[idx]

		if root.Name == "" {
			errs = append(errs, fmt.Errorf(
				"%w: roots[%d]", ErrSigstoreRootNameRequired, idx,
			))
		} else {
			if prevIdx, ok := seen[root.Name]; ok {
				errs = append(errs, fmt.Errorf(
					"%w: %q at roots[%d] and roots[%d]",
					ErrSigstoreRootNameDuplicate, root.Name, prevIdx, idx,
				))
			} else {
				seen[root.Name] = idx
			}
		}

		if root.TUFMirror != "" {
			err := validateTUFMirrorURL(root.TUFMirror)
			if err != nil {
				errs = append(errs, fmt.Errorf("roots[%d]: %w", idx, err))
			}
		}

		if root.TUFRoot != "" {
			if !filepath.IsAbs(root.TUFRoot) {
				errs = append(errs, fmt.Errorf(
					"%w: roots[%d] %q", ErrTUFRootNotAbsolute, idx, root.TUFRoot,
				))
			}

			if root.TUFMirror == "" {
				errs = append(errs, fmt.Errorf(
					"%w: roots[%d]", ErrTUFRootRequiresMirror, idx,
				))
			}
		}
	}

	return errs
}

func validateTUFMirrorURL(mirror string) error {
	parsed, err := url.Parse(mirror)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", ErrInvalidTUFMirror, mirror, err)
	}

	if parsed.Scheme != "https" {
		return fmt.Errorf(
			"%w: %q: scheme must be https", ErrInvalidTUFMirror, mirror,
		)
	}

	if parsed.Host == "" {
		return fmt.Errorf(
			"%w: %q: missing host", ErrInvalidTUFMirror, mirror,
		)
	}

	return nil
}
