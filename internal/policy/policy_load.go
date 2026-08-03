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

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Load loads and validates a policy file from disk.
func Load(policyPath string) (*Policy, error) {
	file, err := os.Open(filepath.Clean(policyPath))
	if err != nil {
		return nil, fmt.Errorf("reading policy file %q: %w", policyPath, err)
	}
	defer func() {
		closeErr := file.Close()
		if closeErr != nil {
			slog.Warn("Failed to close policy file",
				"path", policyPath,
				"error", closeErr,
			)
		}
	}()

	data, err := io.ReadAll(io.LimitReader(file, maxPolicyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading policy file %q: %w", policyPath, err)
	}

	if int64(len(data)) > maxPolicyFileSize {
		return nil, fmt.Errorf(
			"%w: %q exceeds %d bytes", ErrPolicyFileTooLarge, policyPath, maxPolicyFileSize,
		)
	}

	var pol Policy

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	err = dec.Decode(&pol)
	if err != nil {
		return nil, fmt.Errorf(
			"parsing policy file %q: %w", policyPath, err,
		)
	}

	err = dec.Decode(&struct{}{})
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%w: %q", ErrTrailingContent, policyPath)
		}

		return nil, fmt.Errorf(
			"parsing policy file %q: unexpected trailing content: %w",
			policyPath, err,
		)
	}

	err = pol.Validate()
	if err != nil {
		return nil, fmt.Errorf(
			"invalid policy file %q: %w", policyPath, err,
		)
	}

	return &pol, nil
}

// LoadAll loads all policy files from the given directory.
// Returns a map keyed by namespace (empty string for default.json).
func LoadAll(policyDir string) (map[string]*Policy, error) {
	policies, err := loadPolicyFiles(policyDir)
	if err != nil {
		return nil, err
	}

	err = applyInheritance(policies)
	if err != nil {
		return nil, err
	}

	return policies, nil
}

func loadPolicyFiles(policyDir string) (map[string]*Policy, error) {
	policies := make(map[string]*Policy)

	if policyDir == "" {
		return policies, nil
	}

	entries, err := readPolicyDir(policyDir)
	if err != nil {
		return nil, err
	}

	var errs []error

	for i, entry := range entries {
		if i >= maxPolicyFiles {
			errs = append(errs, fmt.Errorf(
				"%w: %q contains more than %d JSON files",
				ErrTooManyPolicyFiles, policyDir, maxPolicyFiles,
			))

			break
		}

		fullPath := filepath.Join(policyDir, entry.Name())

		pol, loadErr := Load(fullPath)
		if loadErr != nil {
			errs = append(errs, loadErr)

			continue
		}

		namespace := strings.TrimSuffix(entry.Name(), ".json")
		if namespace == "default" {
			namespace = ""
		}

		policies[namespace] = pol
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return policies, nil
}

func readPolicyDir(policyDir string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf(
			"reading policy directory %q: %w", policyDir, err,
		)
	}

	var jsonEntries []os.DirEntry

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		jsonEntries = append(jsonEntries, entry)
	}

	return jsonEntries, nil
}

func applyInheritance(policies map[string]*Policy) error {
	defaultPol := policies[""]

	if defaultPol != nil && defaultPol.Inherits != nil && *defaultPol.Inherits {
		return ErrDefaultCannotInherit
	}

	if defaultPol == nil {
		return nil
	}

	for ns, pol := range policies {
		if ns == "" || pol.Inherits == nil || !*pol.Inherits {
			continue
		}

		policies[ns] = MergeWithDefault(pol, defaultPol)
	}

	return nil
}
