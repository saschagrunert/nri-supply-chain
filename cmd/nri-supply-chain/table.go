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
	"io"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

func newBorderlessTable(writer io.Writer, headers []string) *tablewriter.Table {
	padding := tw.Padding{Left: "", Right: "   "}

	return tablewriter.NewTable(writer,
		tablewriter.WithHeader(headers),
		tablewriter.WithHeaderAlignment(tw.AlignLeft),
		tablewriter.WithRowAlignment(tw.AlignLeft),
		tablewriter.WithRowAutoWrap(tw.WrapNone),
		tablewriter.WithPadding(padding),
		tablewriter.WithRendition(tw.Rendition{
			Borders: tw.Border{
				Left: tw.Off, Right: tw.Off, Top: tw.Off, Bottom: tw.Off,
			},
			Settings: tw.Settings{
				Separators: tw.Separators{
					BetweenColumns: tw.Off,
					ShowHeader:     tw.Off,
				},
				Lines: tw.Lines{
					ShowHeaderLine: tw.Off,
					ShowTop:        tw.Off,
					ShowBottom:     tw.Off,
				},
			},
		}),
	)
}
