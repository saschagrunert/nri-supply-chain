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

package sbom

// The helpers below parse a single document in one format. Production code
// detects the format with extractSBOMData.

func parseSPDX(data []byte) (sbomData, error) {
	raw, err := decodeRawSBOM(data)
	if err != nil {
		return sbomData{}, err
	}

	return spdxFromRaw(raw)
}

// spdx3Document is the SPDX 3 JSON-LD serialization. Both the 3.0 draft
// shapes ("@type", "declaredLicense") and the 3.0.1 shapes ("type",
// "software_packageVersion", license Relationship elements) are accepted.
type spdx3Document struct {
	Context  string         `json:"@context,omitempty"`
	Type     string         `json:"@type,omitempty"`
	SpdxID   string         `json:"spdxId,omitempty"` //nolint:tagliatelle // SPDX spec field name
	SpecVer  string         `json:"specVersion,omitempty"`
	Elements []spdx3Element `json:"@graph,omitempty"`
}

func parseSPDX3(data []byte) (sbomData, error) {
	raw, err := decodeRawSBOM(data)
	if err != nil {
		return sbomData{}, err
	}

	return spdx3FromRaw(raw)
}

type cyclonedxBOM struct {
	Components      []cyclonedxComponent     `json:"components"`
	Vulnerabilities []cyclonedxVulnerability `json:"vulnerabilities"`
}

func parseCycloneDX(data []byte) (sbomData, error) {
	raw, err := decodeRawSBOM(data)
	if err != nil {
		return sbomData{}, err
	}

	return cyclonedxFromRaw(raw)
}
