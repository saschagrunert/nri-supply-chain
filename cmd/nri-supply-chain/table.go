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
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

// tableColumnGap is the number of spaces between two table columns.
const tableColumnGap = 3

// ansiSequence matches the SGR color sequences of github.com/fatih/color.
var ansiSequence = regexp.MustCompile("\x1b\\[[0-9;]*m")

// borderlessTable renders left-aligned columns with upper-case headers and
// no borders. Column widths ignore ANSI color sequences, which
// text/tabwriter would count as visible characters and misalign colored
// cells. A cell with several lines, such as a detail holding joined errors,
// continues in its own column on the following lines.
type borderlessTable struct {
	writer io.Writer
	rows   [][]string
}

func newBorderlessTable(writer io.Writer, headers []string) *borderlessTable {
	header := make([]string, len(headers))
	for idx, name := range headers {
		header[idx] = strings.ToUpper(name)
	}

	return &borderlessTable{writer: writer, rows: [][]string{header}}
}

// Append adds a row to the table.
func (t *borderlessTable) Append(row []string) {
	t.rows = append(t.rows, row)
}

// Render writes the table.
func (t *borderlessTable) Render() error {
	var widths []int

	for _, row := range t.rows {
		for idx, cell := range row {
			if idx == len(widths) {
				widths = append(widths, 0)
			}

			for line := range strings.SplitSeq(cell, "\n") {
				widths[idx] = max(widths[idx], visibleWidth(line))
			}
		}
	}

	var out strings.Builder

	for _, row := range t.rows {
		writeTableRow(&out, row, widths)
	}

	_, err := io.WriteString(t.writer, out.String())
	if err != nil {
		return fmt.Errorf("writing table: %w", err)
	}

	return nil
}

// writeTableRow writes row as one line per line of its highest cell, padding
// every column but the last to its width.
func writeTableRow(out *strings.Builder, row []string, widths []int) {
	cells := make([][]string, len(row))
	height := 1

	for idx, cell := range row {
		cells[idx] = strings.Split(cell, "\n")
		height = max(height, len(cells[idx]))
	}

	for lineIdx := range height {
		var line strings.Builder

		for idx, lines := range cells {
			text := ""
			if lineIdx < len(lines) {
				text = lines[lineIdx]
			}

			line.WriteString(text)

			if idx < len(cells)-1 {
				line.WriteString(strings.Repeat(" ", widths[idx]-visibleWidth(text)+tableColumnGap))
			}
		}

		out.WriteString(strings.TrimRight(line.String(), " "))
		out.WriteByte('\n')
	}
}

func visibleWidth(cell string) int {
	return utf8.RuneCountInString(ansiSequence.ReplaceAllString(cell, ""))
}
