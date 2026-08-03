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

package notation

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	"github.com/notaryproject/notation-go/verifier/truststore"

	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

var (
	// ErrNoCertificates indicates no certificates were found in a PEM file.
	ErrNoCertificates = errors.New("no certificates found in PEM file")

	// ErrUnknownStoreType indicates an unknown trust store type.
	ErrUnknownStoreType = errors.New("unknown trust store type")

	// ErrStoreNotFound indicates a trust store name was not found.
	ErrStoreNotFound = errors.New("trust store not found")

	// ErrStoreTypeMismatch indicates the requested store type does not match the configured type.
	ErrStoreTypeMismatch = errors.New("trust store type mismatch")
)

// policyTrustStore implements the notation-go truststore.X509TrustStore interface.
// It serves certificates from policy-configured file paths, caching loaded
// certificates for the lifetime of the policy.
type policyTrustStore struct {
	stores map[string]*storeEntry
	mu     sync.RWMutex
}

type storeEntry struct {
	storeType truststore.Type
	certPaths []string
	certs     []*x509.Certificate
	loaded    bool
	loadErr   error
}

func newTrustStore(stores []policy.NotationTrustStore) (*policyTrustStore, error) {
	trustStoreMap := &policyTrustStore{
		stores: make(map[string]*storeEntry, len(stores)),
		mu:     sync.RWMutex{},
	}

	for _, store := range stores {
		storeType, err := parseStoreType(store.Type)
		if err != nil {
			return nil, fmt.Errorf("trust store %q: %w", store.Name, err)
		}

		trustStoreMap.stores[store.Name] = &storeEntry{
			storeType: storeType,
			certPaths: store.Certificates,
			certs:     nil,
			loaded:    false,
			loadErr:   nil,
		}
	}

	return trustStoreMap, nil
}

func parseStoreType(rawType string) (truststore.Type, error) {
	switch rawType {
	case "ca":
		return truststore.TypeCA, nil
	case "signingAuthority":
		return truststore.TypeSigningAuthority, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnknownStoreType, rawType)
	}
}

// GetCertificates returns certificates for the named trust store.
// This implements the truststore.X509TrustStore interface.
func (ts *policyTrustStore) GetCertificates(
	_ context.Context, storeType truststore.Type, namedStore string,
) ([]*x509.Certificate, error) {
	ts.mu.RLock()
	entry, ok := ts.stores[namedStore]
	ts.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrStoreNotFound, namedStore)
	}

	if entry.storeType != storeType {
		return nil, fmt.Errorf(
			"%w: store %q has type %q, requested %q",
			ErrStoreTypeMismatch, namedStore, entry.storeType, storeType,
		)
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	if entry.loaded {
		return entry.certs, entry.loadErr
	}

	certs, err := loadCertificates(entry.certPaths)

	entry.certs = certs
	entry.loadErr = err
	entry.loaded = true

	return certs, err
}

func loadCertificates(paths []string) ([]*x509.Certificate, error) {
	var allCerts []*x509.Certificate

	for _, path := range paths {
		certs, err := loadPEMCertificates(path)
		if err != nil {
			return nil, fmt.Errorf("loading certificates from %q: %w", path, err)
		}

		allCerts = append(allCerts, certs...)
	}

	return allCerts, nil
}

func loadPEMCertificates(path string) ([]*x509.Certificate, error) {
	data, err := fileutil.ReadLimited(path, fileutil.MaxCredentialFileSize)
	if err != nil {
		return nil, fmt.Errorf("reading certificate file: %w", err)
	}

	var certs []*x509.Certificate

	for len(data) > 0 {
		var block *pem.Block

		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing certificate from %q: %w", path, parseErr)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrNoCertificates, path)
	}

	return certs, nil
}
