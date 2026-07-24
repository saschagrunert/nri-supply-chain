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

import (
	"errors"
	"fmt"
)

// Action represents a policy action for missing or failed attestations.
type Action string

const (
	// ActionAllow permits the action.
	ActionAllow Action = "allow"
	// ActionWarn logs a warning but permits the action.
	ActionWarn Action = "warn"
	// ActionDeny rejects the action.
	ActionDeny Action = "deny"
)

// ErrInvalidAction indicates an unrecognized policy action value.
var ErrInvalidAction = errors.New("invalid policy action value")

// ValidateAction validates that the given value is a valid policy action.
func ValidateAction(name string, value Action) error {
	switch value {
	case ActionAllow, ActionWarn, ActionDeny:
		return nil
	default:
		return fmt.Errorf("%w: %s %q", ErrInvalidAction, name, value)
	}
}
