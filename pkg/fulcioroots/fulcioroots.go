//
// Copyright 2022 The Sigstore Authors.
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

// Package fulcioroots fetches Fulcio root and intermediate certificates from TUF metadata
package fulcioroots

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/tuf"
)

var (
	rootsOnce        sync.Once
	roots            []*x509.Certificate
	intermediates    []*x509.Certificate
	singletonRootErr error
)

const (
	// This is the root in the fulcio project.
	envSigstoreRootFile = "SIGSTORE_ROOT_FILE"

	// This is the root in the fulcio project.
	fulcioTargetStr = `fulcio.crt.pem`

	// This is the v1 migrated root.
	fulcioV1TargetStr = `fulcio_v1.crt.pem`

	// This is the untrusted v1 intermediate CA certificate, used or chain building.
	fulcioV1IntermediateTargetStr = `fulcio_intermediate_v1.crt.pem`
)

// Get returns the Fulcio root certificate.
// This is a wrapper around [GetWithCertPool] with a new CertPool.
func Get() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if err := GetWithCertPool(pool); err != nil {
		return nil, err
	}
	return pool, nil
}

// GetWithCertPool returns the Fulcio root certificate appended to the given CertPool.
//
// If the SIGSTORE_ROOT_FILE environment variable is set, the root config found
// there will be used instead of the normal Fulcio intermediates.
func GetWithCertPool(pool *x509.CertPool) error {
	rootsOnce.Do(func() {
		roots, intermediates, singletonRootErr = initRoots()
		if singletonRootErr != nil {
			return
		}
	})
	if singletonRootErr != nil {
		return singletonRootErr
	}

	for _, c := range roots {
		pool.AddCert(c)
	}
	return nil
}

// GetIntermediates returns the Fulcio intermediate certificates.
// This is a wrapper around [GetIntermediatesWithCertPool] with a new CertPool.
func GetIntermediates() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if err := GetIntermediatesWithCertPool(pool); err != nil {
		return nil, err
	}
	return pool, nil
}

// GetIntermediatesWithCertPool returns the Fulcio intermediate certificates appended to the given CertPool.
//
// If the SIGSTORE_ROOT_FILE environment variable is set, the root config found
// there will be used instead of the normal Fulcio intermediates.
func GetIntermediatesWithCertPool(pool *x509.CertPool) error {
	rootsOnce.Do(func() {
		roots, intermediates, singletonRootErr = initRoots()
		if singletonRootErr != nil {
			return
		}
	})
	if singletonRootErr != nil {
		return singletonRootErr
	}

	for _, c := range intermediates {
		pool.AddCert(c)
	}
	return nil
}

func initRoots() ([]*x509.Certificate, []*x509.Certificate, error) {
	raw := [][]byte{}
	if rootEnv := os.Getenv(envSigstoreRootFile); rootEnv != "" {
		b, err := os.ReadFile(rootEnv)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading root PEM file: %w", err)
		}
		raw = append(raw, b)
	} else {
		tufClient, err := tuf.NewFromEnv(context.Background())
		if err != nil {
			return nil, nil, fmt.Errorf("initializing tuf: %w", err)
		}
		// Retrieve from the embedded or cached TUF root. If expired, a network
		// call is made to update the root.
		targets, err := tufClient.GetTargetsByMeta(tuf.Fulcio, []string{fulcioTargetStr, fulcioV1TargetStr, fulcioV1IntermediateTargetStr})
		if err != nil {
			return nil, nil, fmt.Errorf("error getting targets: %w", err)
		}
		if len(targets) == 0 {
			return nil, nil, errors.New("none of the Fulcio roots have been found")
		}
		for _, t := range targets {
			raw = append(raw, t.Target)
		}
	}

	rootPool := []*x509.Certificate{}
	intermediatePool := []*x509.Certificate{}
	for _, cert := range raw {
		certs, err := cryptoutils.UnmarshalCertificatesFromPEM(cert)
		if err != nil {
			return nil, nil, fmt.Errorf("error unmarshalling certificates: %w", err)
		}
		for _, cert := range certs {
			// root certificates are self-signed
			if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
				rootPool = append(rootPool, cert)
			} else {
				intermediatePool = append(intermediatePool, cert)
			}
		}
	}
	return rootPool, intermediatePool, nil
}
