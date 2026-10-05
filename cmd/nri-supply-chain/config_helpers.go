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

package main

import (
	"fmt"
	"os"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/daemon"
)

func setupConfig(configPath string) (*config.Config, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}

	return validateRuntimeConfig(cfg)
}

// validateRuntimeConfig runs the runtime validation of an enabled config.
func validateRuntimeConfig(cfg *config.Config) (*config.Config, error) {
	if cfg.Enabled() {
		err := cfg.ValidateRuntime()
		if err != nil {
			return nil, fmt.Errorf("runtime validation: %w", err)
		}
	}

	return cfg, nil
}

// serveConfigPath returns the config file the plugin serves with. An empty
// result means the plugin has no config file: it starts from the built-in
// defaults and applies the configuration the runtime passes inline when it
// configures the plugin. That is the case for an explicit empty --config and
// when --config was not set and the default file does not exist.
func serveConfigPath(path string, explicit bool) string {
	if path == "" || (!explicit && !daemon.ShouldUseConfigFile(path)) {
		return ""
	}

	return path
}

// setupServeConfig loads the config for the plugin process. Without a config
// file the built-in defaults apply until the runtime passes a configuration.
// A config file the plugin serves with must exist: serveConfigPath only keeps
// the default path when it exists or was set explicitly, and an explicitly
// set file that is missing must not silently fall back to the defaults
// (verification disabled) while the configuration from the runtime is ignored.
func setupServeConfig(path string) (*config.Config, error) {
	if path == "" {
		return config.DefaultConfig(), nil
	}

	cfg, err := config.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading config file: %w", err)
	}

	return validateRuntimeConfig(cfg)
}

func loadConfig(path string) (*config.Config, error) {
	if path == defaultConfigPath {
		_, statErr := os.Stat(path)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				return config.DefaultConfig(), nil
			}

			return nil, fmt.Errorf("checking config file: %w", statErr)
		}
	}

	cfg, err := config.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading config file: %w", err)
	}

	return cfg, nil
}
