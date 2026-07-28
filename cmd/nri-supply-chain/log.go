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
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/fatih/color"
)

type cliHandler struct {
	level slog.Leveler
	out   io.Writer
	mu    *sync.Mutex
	start time.Time
}

func newCLIHandler(out io.Writer, level slog.Leveler) *cliHandler {
	return &cliHandler{
		level: level,
		out:   out,
		mu:    &sync.Mutex{},
		start: time.Now(),
	}
}

func (h *cliHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

//nolint:gocritic // slog.Handler interface requires slog.Record by value
func (h *cliHandler) Handle(
	_ context.Context, record slog.Record,
) error {
	elapsed := int(record.Time.Sub(h.start).Seconds())
	level := colorLevel(record.Level)
	msg := fmt.Sprintf("%s[%04d] %s", level, elapsed, record.Message)

	record.Attrs(func(attr slog.Attr) bool {
		msg += fmt.Sprintf(" %s=%s", attr.Key, attr.Value.String())

		return true
	})

	msg += "\n"

	h.mu.Lock()
	defer h.mu.Unlock()

	_, err := io.WriteString(h.out, msg)

	return err //nolint:wrapcheck // WriteString error is self-explanatory
}

func (h *cliHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return h
}

func (h *cliHandler) WithGroup(_ string) slog.Handler {
	return h
}

//nolint:gochecknoglobals // reusable color formatters for log levels
var (
	levelError = color.New(color.FgRed, color.Bold)
	levelWarn  = color.New(color.FgYellow, color.Bold)
	levelInfo  = color.New(color.FgGreen, color.Bold)
	levelDebug = color.New(color.FgCyan, color.Bold)
)

func colorLevel(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return levelError.Sprint(level.String())
	case level >= slog.LevelWarn:
		return levelWarn.Sprint(level.String())
	case level >= slog.LevelInfo:
		return levelInfo.Sprint(level.String())
	default:
		return levelDebug.Sprint(level.String())
	}
}
