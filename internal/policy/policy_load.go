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
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const (
	policyFileExtension   = ".json"
	defaultPolicyBaseName = "default"
	maxNamespaceLength    = 63
)

// namespacePattern matches a Kubernetes namespace name (RFC 1123 label).
var namespacePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

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

	return decodePolicy(data, fmt.Sprintf("policy file %q", policyPath))
}

// decodePolicy strictly decodes a single JSON policy document (unknown
// fields and trailing content are rejected), records which fields were set
// explicitly, and validates the result. source describes the document in
// error messages.
func decodePolicy(data []byte, source string) (*Policy, error) {
	var pol Policy

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	err := dec.Decode(&pol)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", source, err)
	}

	err = dec.Decode(&struct{}{})
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%w: %s", ErrTrailingContent, source)
		}

		return nil, fmt.Errorf(
			"parsing %s: unexpected trailing content: %w", source, err,
		)
	}

	err = checkCanonicalFields(data)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", source, err)
	}

	err = recordExplicitFields(&pol, data)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", source, err)
	}

	err = pol.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", source, err)
	}

	return &pol, nil
}

// NamespaceFromFilename maps a policy file name to the namespace it applies
// to. "default.json" maps to the default policy (empty namespace). Any other
// name must be "<namespace>.json" where namespace is a lowercase RFC 1123
// label, so typos like "Prod.json" or ".json" are rejected instead of
// silently creating a policy that never applies. Directory components (e.g.
// from OCI layer titles) are ignored.
func NamespaceFromFilename(filename string) (string, error) {
	base := path.Base(filepath.ToSlash(filename))

	namespace, isJSON := strings.CutSuffix(base, policyFileExtension)
	if !isJSON {
		return "", fmt.Errorf("%w: got %q", ErrInvalidPolicyFilename, filename)
	}

	if namespace == defaultPolicyBaseName {
		return "", nil
	}

	if len(namespace) > maxNamespaceLength || !namespacePattern.MatchString(namespace) {
		return "", fmt.Errorf("%w: got %q", ErrInvalidPolicyFilename, filename)
	}

	return namespace, nil
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

	for idx, entry := range entries {
		if idx >= maxPolicyFiles {
			errs = append(errs, fmt.Errorf(
				"%w: %q contains more than %d JSON files",
				ErrTooManyPolicyFiles, policyDir, maxPolicyFiles,
			))

			break
		}

		namespace, nameErr := NamespaceFromFilename(entry.name)
		if nameErr != nil {
			errs = append(errs, fmt.Errorf("policy file %q: %w", entry.path, nameErr))

			continue
		}

		pol, loadErr := Load(entry.path)
		if loadErr != nil {
			errs = append(errs, loadErr)

			continue
		}

		policies[namespace] = pol
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return policies, nil
}

type policyDirEntry struct {
	name string
	path string
}

// readPolicyDir lists the JSON policy files of a directory. Symlinked files
// are followed as long as they resolve to a regular file inside the policy
// directory, which is how Kubernetes projects ConfigMap keys (a symlink to
// "..data/<key>"). Hidden files are skipped. Symlinks escaping the
// directory and unreadable entries are errors rather than being skipped, so
// a policy is never dropped silently.
func readPolicyDir(policyDir string) ([]policyDirEntry, error) {
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf(
			"reading policy directory %q: %w", policyDir, err,
		)
	}

	resolvedDir, err := filepath.EvalSymlinks(policyDir)
	if err != nil {
		return nil, fmt.Errorf("resolving policy directory %q: %w", policyDir, err)
	}

	var (
		jsonEntries []policyDirEntry
		errs        []error
	)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), policyFileExtension) {
			continue
		}

		fullPath := filepath.Join(policyDir, entry.Name())

		// Hidden files are never policies: editor backups and lock files
		// (e.g. ".#default.json", often a dangling symlink) must not fail the
		// whole load, and ".json" must not become the default policy.
		if strings.HasPrefix(entry.Name(), ".") {
			slog.Warn("Skipping hidden file in policy directory", "path", fullPath)

			continue
		}

		resolveErr := checkPolicyFile(resolvedDir, fullPath)
		if resolveErr != nil {
			errs = append(errs, resolveErr)

			continue
		}

		jsonEntries = append(jsonEntries, policyDirEntry{name: entry.Name(), path: fullPath})
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return jsonEntries, nil
}

// checkPolicyFile verifies that a policy directory entry is a regular file,
// or a symlink resolving to a regular file inside the policy directory.
func checkPolicyFile(resolvedDir, fullPath string) error {
	info, err := os.Lstat(fullPath)
	if err != nil {
		return fmt.Errorf("policy file %q: %w", fullPath, err)
	}

	if info.Mode()&os.ModeSymlink == 0 {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("policy file %q: %w", fullPath, ErrNotRegularFile)
		}

		return nil
	}

	target, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		return fmt.Errorf("resolving policy file symlink %q: %w", fullPath, err)
	}

	rel, err := filepath.Rel(resolvedDir, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %q -> %q", ErrPolicySymlinkOutsideDir, fullPath, target)
	}

	targetInfo, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("policy file %q: %w", fullPath, err)
	}

	if !targetInfo.Mode().IsRegular() {
		return fmt.Errorf("policy file %q: %w", fullPath, ErrNotRegularFile)
	}

	return nil
}

// applyInheritance merges namespace policies that set inherits=true with the
// default policy. Independently of inherits, a namespace policy that does not
// set a mode uses the default policy's mode, so moving a setting into
// default.json never weakens the mode of other namespaces (the default mode
// is at least as strict as the global mode). Keyless verifiers of inheriting
// policies are validated here, on the merged policy, because they may rely on
// the default policy's trust.issuers.
func applyInheritance(policies map[string]*Policy) error {
	defaultPol := policies[""]

	if defaultPol != nil && defaultPol.Inherits != nil && *defaultPol.Inherits {
		return ErrDefaultCannotInherit
	}

	var errs []error

	for _, namespace := range slices.Sorted(maps.Keys(policies)) {
		pol := policies[namespace]
		if namespace == "" {
			continue
		}

		inherits := pol.Inherits != nil && *pol.Inherits

		if defaultPol != nil {
			pol = inheritFromDefault(pol, defaultPol)
			policies[namespace] = pol
		}

		if inherits {
			err := pol.validateKeylessVerifiers()
			if err != nil {
				errs = append(errs, fmt.Errorf(
					"invalid policy for namespace %q: %w", namespace, err,
				))
			}
		}
	}

	return errors.Join(errs...)
}

func inheritFromDefault(pol, defaultPol *Policy) *Policy {
	if pol.Inherits != nil && *pol.Inherits {
		return MergeWithDefault(pol, defaultPol)
	}

	if pol.Mode == "" {
		pol.Mode = defaultPol.Mode
	}

	return pol
}
