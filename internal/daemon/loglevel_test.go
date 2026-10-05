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

package daemon_test

import (
	"log/slog"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/daemon"
)

//nolint:paralleltest // modifies the process log level
func TestSetLogLevel(t *testing.T) {
	tests := []struct {
		name  string
		level string
		want  slog.Level
	}{
		{name: daemon.LogLevelDebug, level: daemon.LogLevelDebug, want: slog.LevelDebug},
		{name: daemon.LogLevelInfo, level: daemon.LogLevelInfo, want: slog.LevelInfo},
		{name: daemon.LogLevelWarn, level: daemon.LogLevelWarn, want: slog.LevelWarn},
		{name: daemon.LogLevelError, level: daemon.LogLevelError, want: slog.LevelError},
		{name: "unrecognized defaults to info", level: "bogus", want: slog.LevelInfo},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			daemon.SetLogLevel(test.level)

			if daemon.LogLevel.Level() != test.want {
				t.Errorf("expected level %v, got %v", test.want, daemon.LogLevel.Level())
			}
		})
	}
}
