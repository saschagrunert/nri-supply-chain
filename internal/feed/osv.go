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

// Package feed parses OSV JSON vulnerability feeds and extracts affected PURLs
// for matching against container SBOM data.
package feed

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

const maxFeedFileSize = 50 << 20 // 50 MiB

var (
	// ErrFeedFileNotRegular indicates the path is not a regular file.
	ErrFeedFileNotRegular = errors.New("feed file is not a regular file")

	// ErrFeedFileTooLarge indicates the file exceeds the size limit.
	ErrFeedFileTooLarge = errors.New("feed file exceeds size limit")

	// ErrFeedUnexpectedToken indicates an unexpected JSON token type.
	ErrFeedUnexpectedToken = errors.New("expected JSON object or array")

	// ErrFeedUnexpectedDelimiter indicates an unexpected JSON delimiter.
	ErrFeedUnexpectedDelimiter = errors.New("unexpected JSON delimiter")
)

// OSVEntry represents a single OSV vulnerability entry. Only fields needed
// for PURL extraction are decoded.
type OSVEntry struct {
	ID       string        `json:"id"`
	Affected []OSVAffected `json:"affected"`
}

// OSVAffected represents an affected package entry in an OSV record.
type OSVAffected struct {
	Package OSVPackage `json:"package"`
}

// OSVPackage represents the package identifier within an OSV affected entry.
type OSVPackage struct {
	PURL string `json:"purl"`
}

// ParseFile reads a single OSV JSON file and returns the set of affected
// PURLs. The file may contain a single OSV entry or an array of entries.
func ParseFile(path string) ([]string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat feed file: %w", err)
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrFeedFileNotRegular, path)
	}

	if info.Size() > maxFeedFileSize {
		return nil, fmt.Errorf("%w: %s (%d bytes)", ErrFeedFileTooLarge, path, info.Size())
	}

	file, err := os.Open(path) //nolint:gosec // path is validated above via Lstat
	if err != nil {
		return nil, fmt.Errorf("open feed file: %w", err)
	}

	defer func() {
		closeErr := file.Close()
		if closeErr != nil {
			slog.Warn("Failed to close feed file", "file", path, "error", closeErr)
		}
	}()

	return parsePURLs(io.LimitReader(file, maxFeedFileSize))
}

func parsePURLs(reader io.Reader) ([]string, error) {
	dec := json.NewDecoder(reader)

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("reading JSON token: %w", err)
	}

	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return nil, fmt.Errorf("%w: got %T", ErrFeedUnexpectedToken, tok)
	}

	switch delim {
	case '{':
		var entry OSVEntry

		combined := io.MultiReader(
			strings.NewReader("{"), dec.Buffered(), reader,
		)

		decErr := json.NewDecoder(combined).Decode(&entry)
		if decErr != nil {
			return nil, fmt.Errorf("decoding OSV entry: %w", decErr)
		}

		return extractPURLs([]OSVEntry{entry}), nil

	case '[':
		var entries []OSVEntry

		combined := io.MultiReader(
			strings.NewReader("["), dec.Buffered(), reader,
		)

		decErr := json.NewDecoder(combined).Decode(&entries)
		if decErr != nil {
			return nil, fmt.Errorf("decoding OSV entries: %w", decErr)
		}

		return extractPURLs(entries), nil

	default:
		return nil, fmt.Errorf("%w: %c", ErrFeedUnexpectedDelimiter, delim)
	}
}

func extractPURLs(entries []OSVEntry) []string {
	seen := make(map[string]struct{})

	var purls []string

	for idx := range entries {
		entry := &entries[idx]

		for affIdx := range entry.Affected {
			purl := entry.Affected[affIdx].Package.PURL
			if purl == "" {
				continue
			}

			if _, exists := seen[purl]; exists {
				continue
			}

			seen[purl] = struct{}{}
			purls = append(purls, purl)
		}
	}

	return purls
}

// ParseDir reads all JSON files in a directory and returns the combined set
// of affected PURLs. Malformed files are logged as warnings and skipped.
func ParseDir(dir string) (purls []string, successCount, errorCount int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Warn("Failed to read feed directory", "dir", dir, "error", err)

		return nil, 0, 0
	}

	seen := make(map[string]struct{})

	var allPURLs []string

	for _, entry := range entries {
		if entry.IsDir() || !isJSONFile(entry.Name()) {
			continue
		}

		path := filepath.Join(dir, entry.Name())

		filePURLs, parseErr := ParseFile(path)
		if parseErr != nil {
			slog.Warn("Failed to parse feed file",
				"file", path, "error", parseErr)

			errorCount++

			continue
		}

		successCount++

		for _, purl := range filePURLs {
			if _, exists := seen[purl]; exists {
				continue
			}

			seen[purl] = struct{}{}
			allPURLs = append(allPURLs, purl)
		}
	}

	return allPURLs, successCount, errorCount
}

func isJSONFile(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".json")
}
