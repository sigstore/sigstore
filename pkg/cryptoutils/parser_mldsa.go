// Copyright 2026 The Sigstore Authors.
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

package cryptoutils

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"filippo.io/mldsa"
)

// ParseCertificateMLDSA parses a certificate and populates ML-DSA public key if needed.
func ParseCertificateMLDSA(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	if cert.PublicKey == nil || cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		pub, err := UnmarshalMLDSAPublicKey(cert.RawSubjectPublicKeyInfo)
		if err == nil {
			cert.PublicKey = pub
		}
	}

	return cert, nil
}

// verifyCertificateSignatureMLDSA verifies that the certificate was signed by the issuer using ML-DSA.
func verifyCertificateSignatureMLDSA(cert, issuerCert *x509.Certificate) error {
	pubKey, ok := issuerCert.PublicKey.(*mldsa.PublicKey)
	if !ok {
		return errors.New("issuer public key is not ML-DSA")
	}
	// Verify signature
	if err := mldsa.Verify(pubKey, cert.RawTBSCertificate, cert.Signature, nil); err != nil {
		return fmt.Errorf("ML-DSA signature verification failed: %w", err)
	}
	return nil
}

// VerifyChainMLDSA attempts to verify a chain for an ML-DSA leaf certificate.
// It accepts slices of certificates for intermediates and roots because x509.CertPool
// does not allow external iteration.
func VerifyChainMLDSA(leaf *x509.Certificate, intermediates, roots []*x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	var result [][]*x509.Certificate

	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}

	var build func(chain []*x509.Certificate)
	build = func(chain []*x509.Certificate) {
		current := chain[len(chain)-1]

		// Check if current is a root
		for _, root := range roots {
			if bytes.Equal(current.RawIssuer, root.RawSubject) {
				// Verify signature of current with root
				if err := verifySig(current, root); err == nil {
					// Found a valid chain to root!
					result = append(result, appendToFreshChain(chain, root))
					return
				}
			}
		}

		// Try to find parents in intermediates
		for _, inter := range intermediates {
			if bytes.Equal(current.RawIssuer, inter.RawSubject) {
				// Check if already in chain to avoid loops
				if alreadyInChain(inter, chain) {
					continue
				}
				// Verify signature
				if err := verifySig(current, inter); err != nil {
					continue
				}
				// Check validity of intermediate
				if now.Before(inter.NotBefore) || now.After(inter.NotAfter) {
					continue
				}
				// Check basic constraints
				if !inter.IsCA {
					continue
				}
				// Recurse
				build(appendToFreshChain(chain, inter))
			}
		}
	}

	// Verify leaf validity
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("leaf certificate is expired or not yet valid")
	}

	build([]*x509.Certificate{leaf})

	if len(result) > 0 {
		return result, nil
	}
	return nil, errors.New("x509: certificate signed by unknown authority")
}

func verifySig(child, parent *x509.Certificate) error {
	_, ok := parent.PublicKey.(*mldsa.PublicKey)
	if ok {
		return verifyCertificateSignatureMLDSA(child, parent)
	}
	return child.CheckSignatureFrom(parent)
}

func alreadyInChain(candidate *x509.Certificate, chain []*x509.Certificate) bool {
	for _, cert := range chain {
		if bytes.Equal(candidate.Raw, cert.Raw) {
			return true
		}
	}
	return false
}

func appendToFreshChain(chain []*x509.Certificate, cert *x509.Certificate) []*x509.Certificate {
	n := make([]*x509.Certificate, len(chain)+1)
	copy(n, chain)
	n[len(chain)] = cert
	return n
}
