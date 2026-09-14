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

package checker

import (
	"maps"
	"slices"
	"strings"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// MergeFunc combines an existing metadata value with an incoming one. It
// returns false when the values cannot be combined (for example on a type
// mismatch), in which case the existing value is kept.
type MergeFunc func(existing, incoming any) (any, bool)

// Sum adds int64 or float64 values.
func Sum() MergeFunc {
	return func(existing, incoming any) (any, bool) {
		switch dst := existing.(type) {
		case int64:
			src, ok := incoming.(int64)

			return dst + src, ok
		case float64:
			src, ok := incoming.(float64)

			return dst + src, ok
		default:
			return nil, false
		}
	}
}

// Max keeps the larger of two int64 or float64 values.
func Max() MergeFunc {
	return func(existing, incoming any) (any, bool) {
		switch dst := existing.(type) {
		case int64:
			src, ok := incoming.(int64)

			return max(dst, src), ok
		case float64:
			src, ok := incoming.(float64)

			return max(dst, src), ok
		default:
			return nil, false
		}
	}
}

// Min keeps the smaller of two int64 or float64 values.
func Min() MergeFunc {
	return func(existing, incoming any) (any, bool) {
		switch dst := existing.(type) {
		case int64:
			src, ok := incoming.(int64)

			return min(dst, src), ok
		case float64:
			src, ok := incoming.(float64)

			return min(dst, src), ok
		default:
			return nil, false
		}
	}
}

// CSV merges comma-separated string lists, deduplicating case-insensitively.
func CSV() MergeFunc {
	return func(existing, incoming any) (any, bool) {
		dst, dstOK := existing.(string)
		src, srcOK := incoming.(string)

		if !dstOK || !srcOK {
			return nil, false
		}

		return types.MergeCommaSeparated(dst, src), true
	}
}

// And combines booleans with a logical AND.
func And() MergeFunc {
	return func(existing, incoming any) (any, bool) {
		dst, dstOK := existing.(bool)
		src, srcOK := incoming.(bool)

		return dst && src, dstOK && srcOK
	}
}

// UnionMap adds keys from the incoming map[string]string that are absent from
// the existing map. Values already present are kept.
func UnionMap() MergeFunc {
	return func(existing, incoming any) (any, bool) {
		dst, dstOK := existing.(map[string]string)
		src, srcOK := incoming.(map[string]string)

		if !dstOK || !srcOK {
			return nil, false
		}

		merged := make(map[string]string, len(dst)+len(src))

		maps.Copy(merged, src)

		maps.Copy(merged, dst)

		return merged, true
	}
}

// ConflictingMap is the intermediate result of UnionMapDropConflicts: the
// map entries all documents agree on, and the keys dropped because documents
// disagree on their value. ResolveConflictingMap replaces it in aggregated
// metadata with a plain map and the list of dropped keys.
type ConflictingMap struct {
	// Values holds the entries all documents agree on.
	Values map[string]string
	// Dropped maps the lowercase form of each dropped key to its spelling in
	// the first document that carried it.
	Dropped map[string]string
}

// UnionMapDropConflicts merges map[string]string values. A key (compared
// case-insensitively) whose value differs between documents is removed from
// the merged map and stays removed for later documents, so a rule reading it
// fails closed instead of seeing the value of an arbitrary document. The
// merged value is a ConflictingMap; call ResolveConflictingMap on the
// aggregated metadata.
//
//nolint:cyclop // sequential merge logic
func UnionMapDropConflicts() MergeFunc {
	return func(existing, incoming any) (any, bool) {
		var acc ConflictingMap

		switch dst := existing.(type) {
		case map[string]string:
			acc = foldConflictingMap(dst)
		case ConflictingMap:
			acc = ConflictingMap{Values: maps.Clone(dst.Values), Dropped: maps.Clone(dst.Dropped)}
		default:
			return nil, false
		}

		src, srcOK := incoming.(map[string]string)
		if !srcOK {
			return nil, false
		}

		// Values of acc hold one spelling per case-folded key.
		byFold := make(map[string]string, len(acc.Values))
		for key := range acc.Values {
			byFold[strings.ToLower(key)] = key
		}

		folded := foldConflictingMap(src)

		for foldedKey, spelling := range folded.Dropped {
			acc.dropKey(byFold, foldedKey, spelling)
		}

		for _, key := range slices.Sorted(maps.Keys(folded.Values)) {
			foldedKey := strings.ToLower(key)
			if _, dropped := acc.Dropped[foldedKey]; dropped {
				continue
			}

			existingKey, found := byFold[foldedKey]
			if !found {
				acc.Values[key] = folded.Values[key]
				byFold[foldedKey] = key

				continue
			}

			if acc.Values[existingKey] != folded.Values[key] {
				acc.dropKey(byFold, foldedKey, existingKey)
			}
		}

		return acc, true
	}
}

// foldConflictingMap reduces a document's map to one spelling per
// case-folded key (the first in sorted order). A key spelled several times
// with different values conflicts within the document and is dropped.
func foldConflictingMap(src map[string]string) ConflictingMap {
	acc := ConflictingMap{Values: make(map[string]string, len(src)), Dropped: map[string]string{}}
	byFold := make(map[string]string, len(src))

	for _, key := range slices.Sorted(maps.Keys(src)) {
		foldedKey := strings.ToLower(key)
		if _, dropped := acc.Dropped[foldedKey]; dropped {
			continue
		}

		existingKey, found := byFold[foldedKey]
		if !found {
			acc.Values[key] = src[key]
			byFold[foldedKey] = key

			continue
		}

		if acc.Values[existingKey] != src[key] {
			acc.dropKey(byFold, foldedKey, existingKey)
		}
	}

	return acc
}

// dropKey removes the case-folded key from Values and records it as dropped
// under spelling, unless it is already dropped.
func (m *ConflictingMap) dropKey(byFold map[string]string, foldedKey, spelling string) {
	if existingKey, found := byFold[foldedKey]; found {
		delete(m.Values, existingKey)
		delete(byFold, foldedKey)
	}

	if _, dropped := m.Dropped[foldedKey]; !dropped {
		m.Dropped[foldedKey] = spelling
	}
}

// ResolveConflictingMap replaces a ConflictingMap stored under key with its
// agreed values and stores the sorted dropped keys under droppedKey. A plain
// map under key (a single document) gets an empty dropped list.
func ResolveConflictingMap(meta map[string]any, key, droppedKey string) {
	if meta == nil {
		return
	}

	switch value := meta[key].(type) {
	case ConflictingMap:
		meta[key] = value.Values
		meta[droppedKey] = slices.Sorted(maps.Values(value.Dropped))
	case map[string]string:
		meta[droppedKey] = []string{}
	default:
	}
}

// MinMap merges map[string]int64 values, keeping the smaller value per key.
func MinMap() MergeFunc {
	return func(existing, incoming any) (any, bool) {
		dst, dstOK := existing.(map[string]int64)
		src, srcOK := incoming.(map[string]int64)

		if !dstOK || !srcOK {
			return nil, false
		}

		merged := make(map[string]int64, len(dst)+len(src))

		maps.Copy(merged, dst)

		for key, val := range src {
			if cur, found := merged[key]; !found || val < cur {
				merged[key] = val
			}
		}

		return merged, true
	}
}

// MaxBy keeps the value with the higher rank according to rankOf. Values
// that are not strings are left unmerged.
func MaxBy(rankOf func(string) int) MergeFunc {
	return func(existing, incoming any) (any, bool) {
		dst, dstOK := existing.(string)
		src, srcOK := incoming.(string)

		if !dstOK || !srcOK {
			return nil, false
		}

		if rankOf(src) > rankOf(dst) {
			return src, true
		}

		return dst, true
	}
}
