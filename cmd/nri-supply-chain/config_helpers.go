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
)

func setupConfig(configPath string) (*config.Config, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}

	if cfg.Enabled() {
		err = cfg.ValidateRuntime()
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
	if path == "" || (!explicit && !shouldUseConfigFile(path)) {
		return ""
	}

	return path
}

// setupServeConfig loads the config for the plugin process. Without a config
// file the built-in defaults apply until the runtime passes a configuration.
func setupServeConfig(path string) (*config.Config, error) {
	if path == "" {
		return config.DefaultConfig(), nil
	}

	return setupConfig(path)
}

func shouldUseConfigFile(path string) bool {
	if path == "" {
		return false
	}

	if path == defaultConfigPath {
		_, err := os.Stat(path)

		return !os.IsNotExist(err)
	}

	return true
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
