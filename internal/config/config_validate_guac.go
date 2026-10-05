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
	"net/url"
	"path/filepath"
	"slices"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// errGUACAuthTokenUnavailable marks a GUAC auth token file that cannot be
// accessed, which is only logged.
var errGUACAuthTokenUnavailable = errors.New("guac.auth_token_path file not found")

func (c *Config) validateGUACConfig() error { //nolint:cyclop // sequential field checks
	guacCfg := &c.Guac

	if !guacCfg.Enabled() {
		return nil
	}

	var errs []error

	errs = append(errs, c.validateGUACEndpointScheme(guacCfg)...)

	if guacCfg.Timeout.Duration <= 0 {
		errs = append(errs, ErrGUACTimeoutNotPositive)
	} else if guacCfg.Timeout.Duration > maxGUACTimeout {
		errs = append(errs, fmt.Errorf("%w: %s (max %s)",
			ErrGUACTimeoutTooHigh, guacCfg.Timeout.Duration, maxGUACTimeout))
	}

	switch guacCfg.FallbackPolicy {
	case types.ActionAllow, types.ActionWarn, types.ActionDeny:
	case "":
	default:
		errs = append(errs, fmt.Errorf("%w: %q",
			ErrGUACInvalidFallbackPolicy, guacCfg.FallbackPolicy))
	}

	if len(guacCfg.Checks) == 0 {
		errs = append(errs, ErrGUACChecksEmpty)
	} else {
		for _, check := range guacCfg.Checks {
			if !slices.Contains(GUACValidChecks, check) {
				errs = append(errs, fmt.Errorf("%w: %q", ErrGUACInvalidCheck, check))
			}
		}
	}

	if guacCfg.MaxDependencies < 1 || guacCfg.MaxDependencies > maxGUACMaxDeps {
		errs = append(errs, fmt.Errorf("%w: got %d",
			ErrGUACMaxDepsRange, guacCfg.MaxDependencies))
	}

	if guacCfg.AuthTokenPath != "" && !filepath.IsAbs(guacCfg.AuthTokenPath) {
		errs = append(errs, ErrGUACAuthTokenPathNotAbsolute)
	}

	if guacCfg.CACertPath != "" && !filepath.IsAbs(guacCfg.CACertPath) {
		errs = append(errs, ErrGUACCACertPathNotAbsolute)
	}

	return errors.Join(errs...)
}

func (c *Config) validateGUACEndpointScheme(guacCfg *GUACConfig) []error {
	parsed, err := url.Parse(guacCfg.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return []error{fmt.Errorf("%w: %s", ErrGUACEndpointInvalid, guacCfg.Endpoint)}
	}

	if parsed.Scheme != "https" {
		if c.Verification == ModeEnforce {
			return []error{fmt.Errorf(
				"%w: %s", ErrGUACEndpointNotHTTPS, guacCfg.Endpoint,
			)}
		}

		slog.Warn(
			"GUAC endpoint does not use HTTPS, auth tokens will be sent in cleartext",
			"endpoint", guacCfg.Endpoint,
		)
	}

	return nil
}

func (c *Config) validateGUACConfigRuntime() []error {
	if !c.Guac.Enabled() {
		return nil
	}

	var errs []error

	errs = append(errs, validateGUACAuthTokenRuntime(c.Guac.AuthTokenPath)...)

	if c.Guac.CACertPath != "" {
		_, err := checkContainedFile(&containedFile{
			label:         "guac.ca_cert",
			path:          c.Guac.CACertPath,
			credential:    false,
			errNotFound:   ErrGUACCACertNotFound,
			errNotRegular: ErrGUACCACertNotRegularFile,
		})
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func validateGUACAuthTokenRuntime(tokenPath string) []error {
	if tokenPath == "" {
		return nil
	}

	_, err := checkContainedFile(&containedFile{
		label:         "guac.auth_token_path",
		path:          tokenPath,
		credential:    true,
		errNotFound:   errGUACAuthTokenUnavailable,
		errNotRegular: ErrGUACAuthTokenNotRegularFile,
	})
	if errors.Is(err, errGUACAuthTokenUnavailable) {
		// The token is optional at startup, for example while a Secret is
		// not yet mounted.
		slog.Warn("GUAC auth token file not found, token auth will be unavailable",
			"path", tokenPath, "error", err)

		return nil
	}

	if err != nil {
		return []error{err}
	}

	return nil
}
