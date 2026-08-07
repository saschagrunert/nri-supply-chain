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

// ExportMigrationFromVersion returns the fromVersion of a migration at index i
// from the configMigrations list. Returns -1 if the index is out of range.
func ExportMigrationFromVersion(i int) int {
	migrations := configMigrations()
	if i < 0 || i >= len(migrations) {
		return -1
	}

	return migrations[i].fromVersion
}

// ExportMigrationCount returns the number of registered config migrations.
func ExportMigrationCount() int {
	return len(configMigrations())
}

// ExportApplyMigrations exposes applyMigrations for tests.
func ExportApplyMigrations(cfg *Config, steps []ExportMigration) error {
	internal := make([]migration, len(steps))
	for i, s := range steps {
		internal[i] = migration{
			fromVersion: s.FromVersion,
			description: s.Description,
			apply:       s.Apply,
		}
	}

	return applyMigrations(cfg, internal)
}

// ExportMigration is a test-visible representation of a migration step.
type ExportMigration struct {
	FromVersion int
	Description string
	Apply       func(*Config) error
}
