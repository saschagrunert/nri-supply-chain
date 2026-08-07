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

package config_test

import (
	"errors"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

var errTestMigration = errors.New("migration failed")

func TestMigrateAlreadyAtLatest(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	testutil.AssertEqual(t, config.LatestConfigVersion, cfg.ConfigVersion)

	err := config.Migrate(cfg)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, config.LatestConfigVersion, cfg.ConfigVersion)
}

func TestMigrateZeroTreatedAsOne(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.ConfigVersion = 0

	err := config.Migrate(cfg)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, config.LatestConfigVersion, cfg.ConfigVersion)
}

func TestMigrationListOrdering(t *testing.T) {
	t.Parallel()

	count := config.ExportMigrationCount()

	for i := 1; i < count; i++ {
		prev := config.ExportMigrationFromVersion(i - 1)
		curr := config.ExportMigrationFromVersion(i)

		if curr != prev+1 {
			t.Errorf(
				"migration[%d] fromVersion %d is not contiguous with migration[%d] fromVersion %d",
				i, curr, i-1, prev,
			)
		}
	}
}

func TestLatestConfigVersionMatchesMigrationCount(t *testing.T) {
	t.Parallel()

	count := config.ExportMigrationCount()
	expected := count + 1

	testutil.AssertEqual(t, expected, config.LatestConfigVersion)
}

func TestApplyMigrationsSuccess(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.ConfigVersion = 1

	steps := []config.ExportMigration{
		{
			FromVersion: 1,
			Description: "test migration",
			Apply:       func(_ *config.Config) error { return nil },
		},
	}

	err := config.ExportApplyMigrations(cfg, steps)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 2, cfg.ConfigVersion)
}

func TestApplyMigrationsSkipsOlderVersions(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.ConfigVersion = 2

	applied := false
	steps := []config.ExportMigration{
		{
			FromVersion: 1,
			Description: "should be skipped",
			Apply: func(_ *config.Config) error {
				applied = true

				return nil
			},
		},
	}

	err := config.ExportApplyMigrations(cfg, steps)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, false, applied)
	testutil.AssertEqual(t, 2, cfg.ConfigVersion)
}

func TestApplyMigrationsBreaksOnGap(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.ConfigVersion = 1

	applied := false
	steps := []config.ExportMigration{
		{
			FromVersion: 3,
			Description: "future migration",
			Apply: func(_ *config.Config) error {
				applied = true

				return nil
			},
		},
	}

	err := config.ExportApplyMigrations(cfg, steps)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, false, applied)
}

func TestApplyMigrationsApplyError(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.ConfigVersion = 1

	steps := []config.ExportMigration{
		{
			FromVersion: 1,
			Description: "failing migration",
			Apply: func(_ *config.Config) error {
				return errTestMigration
			},
		},
	}

	err := config.ExportApplyMigrations(cfg, steps)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "migration failed")
}
