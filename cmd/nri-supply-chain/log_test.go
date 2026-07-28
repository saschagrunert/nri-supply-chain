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
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestCLIHandlerOutput(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	start := time.Now()
	handler := newCLIHandler(&buf, slog.LevelInfo)
	handler.start = start

	record := slog.NewRecord(start.Add(3*time.Second), slog.LevelError, "something failed", 0)
	record.AddAttrs(slog.String("key", "val"))

	err := handler.Handle(context.Background(), record)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}

	got := buf.String()

	if !strings.Contains(got, "[0003]") {
		t.Errorf("expected elapsed [0003], got: %s", got)
	}

	if !strings.Contains(got, "something failed") {
		t.Errorf("expected message in output, got: %s", got)
	}

	if !strings.Contains(got, "key=val") {
		t.Errorf("expected key=val attr, got: %s", got)
	}

	if !strings.HasSuffix(got, "\n") {
		t.Errorf("expected trailing newline, got: %q", got)
	}
}

func TestCLIHandlerEnabled(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	handler := newCLIHandler(&buf, slog.LevelWarn)

	if handler.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("info should be disabled at warn level")
	}

	if !handler.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("warn should be enabled at warn level")
	}

	if !handler.Enabled(context.Background(), slog.LevelError) {
		t.Error("error should be enabled at warn level")
	}
}

func TestCLIHandlerWithAttrsAndGroup(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	handler := newCLIHandler(&buf, slog.LevelInfo)

	if handler.WithAttrs(nil) != handler {
		t.Error("WithAttrs should return same handler")
	}

	if handler.WithGroup("g") != handler {
		t.Error("WithGroup should return same handler")
	}
}

func TestColorLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		level slog.Level
		want  string
	}{
		{slog.LevelError, "ERROR"},
		{slog.LevelWarn, "WARN"},
		{slog.LevelInfo, "INFO"},
		{slog.LevelDebug, "DEBUG"},
	}

	for _, test := range tests {
		t.Run(test.want, func(t *testing.T) {
			t.Parallel()

			got := colorLevel(test.level)
			if !strings.Contains(got, test.want) {
				t.Errorf(
					"colorLevel(%v) = %q, expected to contain %q",
					test.level, got, test.want,
				)
			}
		})
	}
}
