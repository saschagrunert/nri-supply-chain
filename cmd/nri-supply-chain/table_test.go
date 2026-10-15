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
	"testing"
)

func TestBorderlessTableAlignsColoredCells(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	table := newBorderlessTable(&buf, []string{"Type", "Status", "Detail"})
	table.Append([]string{"VEX", "\x1b[32;1mpass\x1b[0;22m", "ok"})
	table.Append([]string{"RUNTIMETRACE", "\x1b[33mwarn\x1b[0m", "détail"})

	err := table.Render()
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	want := "TYPE           STATUS   DETAIL\n" +
		"VEX            \x1b[32;1mpass\x1b[0;22m     ok\n" +
		"RUNTIMETRACE   \x1b[33mwarn\x1b[0m     détail\n"
	if buf.String() != want {
		t.Errorf("Render() = %q, want %q", buf.String(), want)
	}
}

func TestBorderlessTableMultiLineCells(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	table := newBorderlessTable(&buf, []string{"Type", "Status", "Detail"})
	table.Append([]string{"SBOM", "fail", "first error\nsecond error"})
	table.Append([]string{"VEX\nVSA", "pass", ""})

	err := table.Render()
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	want := "TYPE   STATUS   DETAIL\n" +
		"SBOM   fail     first error\n" +
		"                second error\n" +
		"VEX    pass\n" +
		"VSA\n"
	if buf.String() != want {
		t.Errorf("Render() = %q, want %q", buf.String(), want)
	}
}

func TestBorderlessTableHeaderOnly(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	err := newBorderlessTable(&buf, []string{"Check", "Pass"}).Render()
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	if want := "CHECK   PASS\n"; buf.String() != want {
		t.Errorf("Render() = %q, want %q", buf.String(), want)
	}
}
