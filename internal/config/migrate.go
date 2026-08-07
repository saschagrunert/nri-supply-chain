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
	"fmt"
	"log/slog"
)

// migration describes a single schema migration step from one config version
// to the next. Each migration transforms the Config in place.
type migration struct {
	// fromVersion is the version this migration upgrades from.
	fromVersion int
	// description is a human-readable summary of what changes.
	description string
	// apply transforms the config from fromVersion to fromVersion+1.
	apply func(*Config) error
}

// configMigrations returns the ordered list of config migrations. Each entry
// upgrades the config from version N to N+1. The current schema is version 1,
// so this list is empty. When a future schema change is needed, add a
// migration here and bump LatestConfigVersion.
func configMigrations() []migration {
	return []migration{}
}

// Migrate applies sequential migrations to bring the config from its current
// version up to LatestConfigVersion. If the config is already at the latest
// version, this is a no-op. Version 0 is normalized to 1 for backward
// compatibility. Bounds validation is handled by Config.Validate.
func Migrate(cfg *Config) error {
	if cfg.ConfigVersion == 0 {
		cfg.ConfigVersion = 1
	}

	return applyMigrations(cfg, configMigrations())
}

func applyMigrations(cfg *Config, steps []migration) error {
	for _, step := range steps {
		if cfg.ConfigVersion > step.fromVersion {
			continue
		}

		if cfg.ConfigVersion != step.fromVersion {
			slog.Warn("migration list has a gap, stopping early",
				"configVersion", cfg.ConfigVersion,
				"nextMigration", step.fromVersion,
			)

			break
		}

		slog.Info("applying config migration",
			"from", step.fromVersion,
			"to", step.fromVersion+1,
			"description", step.description,
		)

		err := step.apply(cfg)
		if err != nil {
			return fmt.Errorf(
				"config migration from v%d to v%d failed: %w",
				step.fromVersion, step.fromVersion+1, err,
			)
		}

		cfg.ConfigVersion = step.fromVersion + 1
	}

	return nil
}
