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

package daemon

import "log/slog"

// Log level names accepted by the log_level config field and the --log-level
// flag.
const (
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
)

// LogLevel is the level of the process logger. The CLI builds its logger on
// it, and the daemon changes it when a reloaded configuration sets log_level.
var LogLevel slog.LevelVar //nolint:gochecknoglobals // process-wide level shared by the logger and reloads

// ParseLogLevel returns the slog level for a log level name, or nil if the
// name is not recognized.
func ParseLogLevel(level string) *slog.Level {
	var parsed slog.Level

	switch level {
	case LogLevelDebug:
		parsed = slog.LevelDebug
	case LogLevelInfo:
		parsed = slog.LevelInfo
	case LogLevelWarn:
		parsed = slog.LevelWarn
	case LogLevelError:
		parsed = slog.LevelError
	default:
		return nil
	}

	return &parsed
}

// SetLogLevel sets LogLevel to level, or to info if level is not recognized.
func SetLogLevel(level string) {
	logLevel := slog.LevelInfo

	if parsed := ParseLogLevel(level); parsed != nil {
		logLevel = *parsed
	}

	LogLevel.Set(logLevel)
}

// applyLogLevel applies the log_level of a reloaded configuration. An empty
// or unrecognized level keeps the current one.
func applyLogLevel(level string) {
	if level == "" {
		return
	}

	parsed := ParseLogLevel(level)
	if parsed == nil {
		return
	}

	current := LogLevel.Level()
	if current != *parsed {
		LogLevel.Set(*parsed)
		slog.Info("Log level changed", "from", current, "to", *parsed)
	}
}
