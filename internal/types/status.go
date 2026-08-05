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

package types

// StatusResponse represents the operational status of the plugin.
type StatusResponse struct {
	Ready           bool              `json:"ready"`
	Mode            string            `json:"mode"`
	Policies        PolicyStatus      `json:"policies"`
	Cache           CacheStatus       `json:"cache"`
	CircuitBreakers map[string]string `json:"circuitBreakers"`
	NRI             NRIStatus         `json:"nri"`
}

// PolicyStatus describes the currently loaded policies.
type PolicyStatus struct {
	Count      int      `json:"count"`
	Namespaces []string `json:"namespaces"`
	Source     string   `json:"source"`
}

// CacheStatus describes the verification result cache.
type CacheStatus struct {
	Size    int `json:"size"`
	MaxSize int `json:"maxSize"`
}

// NRIStatus describes the NRI runtime connection state.
type NRIStatus struct {
	Connected bool `json:"connected"`
}
