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

package circuit

import "time"

// ExportMaxBreakers exposes maxBreakers for external tests.
const ExportMaxBreakers = maxBreakers

// ExportIsOpen exposes the open state for external tests.
func (cb *Breaker) ExportIsOpen() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return cb.state == circuitOpen
}

// ExportIsClosed exposes the closed state for external tests.
func (cb *Breaker) ExportIsClosed() bool {
	return cb.isClosed()
}

// ExportThreshold exposes threshold for external tests.
func (cb *Breaker) ExportThreshold() int {
	return cb.threshold
}

// ExportCooldown exposes cooldown for external tests.
func (cb *Breaker) ExportCooldown() time.Duration {
	return cb.cooldown
}

// ExportThreshold exposes threshold for external tests.
func (r *Registry) ExportThreshold() int {
	return r.threshold
}

// ExportCooldown exposes cooldown for external tests.
func (r *Registry) ExportCooldown() time.Duration {
	return r.cooldown
}
