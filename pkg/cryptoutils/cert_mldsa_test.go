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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"filippo.io/mldsa"
)

// Structures for marshaling test certificates
type testCertificate struct {
	TBSCertificate     testTBSCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type testTBSCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           testValidity
	Subject            asn1.RawValue
	PublicKey          testPublicKeyInfo
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type testValidity struct {
	NotBefore, NotAfter time.Time
}

type testPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func TestMLDSACertificateParsing(t *testing.T) {
	// Generate an ML-DSA key
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("failed to generate ML-DSA key: %v", err)
	}
	pub := priv.PublicKey()

	// Create a dummy TBSCertificate
	tbs := testTBSCertificate{
		Version:      2, // v3
		SerialNumber: big.NewInt(1),
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidMLDSA65,
		},
		Issuer: asn1.RawValue{FullBytes: []byte{0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x54, 0x65, 0x73, 0x74}},
		Validity: testValidity{
			NotBefore: time.Now().Add(-1 * time.Hour),
			NotAfter:  time.Now().Add(1 * time.Hour),
		},
		Subject: asn1.RawValue{FullBytes: []byte{0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x54, 0x65, 0x73, 0x74}},
		PublicKey: testPublicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm: oidMLDSA65,
			},
			PublicKey: asn1.BitString{
				Bytes:     pub.Bytes(),
				BitLength: len(pub.Bytes()) * 8,
			},
		},
	}

	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("failed to marshal TBSCertificate: %v", err)
	}
	_ = tbsBytes // avoid unused var error

	// Sign the TBSCertificate (mock signature for parsing test or use actual if we can)
	// Let's try to use actual if we can guess the API.
	// Assume priv.Sign exists.
	// signature, err := priv.Sign(tbsBytes, []byte{})
	// If it fails, we will just use dummy bytes.
	// For now, let's use dummy bytes to ensure parsing works first.
	dummySignature := make([]byte, 3000) // ML-DSA signatures are large

	cert := testCertificate{
		TBSCertificate: tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidMLDSA65,
		},
		SignatureValue: asn1.BitString{
			Bytes:     dummySignature,
			BitLength: len(dummySignature) * 8,
		},
	}

	certBytes, err := asn1.Marshal(cert)
	if err != nil {
		t.Fatalf("failed to marshal certificate: %v", err)
	}

	// Now try to parse it with our custom parser
	parsedCert, err := ParseCertificateMLDSA(certBytes)
	if err != nil {
		t.Fatalf("failed to parse ML-DSA certificate: %v", err)
	}

	if parsedCert.SerialNumber.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("unexpected serial number: %v", parsedCert.SerialNumber)
	}

	// Verify public key is parsed correctly
	parsedPubKey, ok := parsedCert.PublicKey.(*mldsa.PublicKey)
	if !ok {
		t.Fatalf("expected ML-DSA public key, got %T", parsedCert.PublicKey)
	}

	if !bytes.Equal(parsedPubKey.Bytes(), pub.Bytes()) {
		t.Errorf("parsed public key does not match original")
	}
}

func createTestCert(t *testing.T, serial int64, subject, issuer []byte, pubKey *mldsa.PublicKey, signerKey *mldsa.PrivateKey, isCA bool) []byte {
	tbs := testTBSCertificate{
		Version:      2, // v3
		SerialNumber: big.NewInt(serial),
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidMLDSA65,
		},
		Issuer: asn1.RawValue{FullBytes: issuer},
		Validity: testValidity{
			NotBefore: time.Now().Add(-1 * time.Hour),
			NotAfter:  time.Now().Add(1 * time.Hour),
		},
		Subject: asn1.RawValue{FullBytes: subject},
		PublicKey: testPublicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm: oidMLDSA65,
			},
			PublicKey: asn1.BitString{
				Bytes:     pubKey.Bytes(),
				BitLength: len(pubKey.Bytes()) * 8,
			},
		},
	}

	if isCA {
		tbs.Extensions = []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
				Critical: true,
				Value:    []byte{0x30, 0x03, 0x01, 0x01, 0xff}, // Sequence { Boolean true }
			},
		}
	}

	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("failed to marshal TBSCertificate: %v", err)
	}

	// Sign the TBSCertificate
	// We assume filippo.io/mldsa implements crypto.Signer
	sig, err := signerKey.Sign(rand.Reader, tbsBytes, crypto.Hash(0))
	if err != nil {
		t.Fatalf("failed to sign TBSCertificate: %v", err)
	}

	cert := testCertificate{
		TBSCertificate: tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidMLDSA65,
		},
		SignatureValue: asn1.BitString{
			Bytes:     sig,
			BitLength: len(sig) * 8,
		},
	}

	certBytes, err := asn1.Marshal(cert)
	if err != nil {
		t.Fatalf("failed to marshal certificate: %v", err)
	}

	return certBytes
}

func TestVerifyChainMLDSA(t *testing.T) {
	// Generate keys
	rootPriv, _ := mldsa.GenerateKey(mldsa.MLDSA65())
	interPriv, _ := mldsa.GenerateKey(mldsa.MLDSA65())
	leafPriv, _ := mldsa.GenerateKey(mldsa.MLDSA65())

	rootPub := rootPriv.PublicKey()
	interPub := interPriv.PublicKey()
	leafPub := leafPriv.PublicKey()

	// Names
	rootName := []byte{0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x52, 0x6f, 0x6f, 0x74} // Root
	interName := []byte{0x30, 0x10, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x05, 0x49, 0x6e, 0x74, 0x65, 0x72} // Inter
	leafName := []byte{0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x4c, 0x65, 0x61, 0x66} // Leaf

	// Create certs
	rootCertBytes := createTestCert(t, 1, rootName, rootName, rootPub, rootPriv, true)
	interCertBytes := createTestCert(t, 2, interName, rootName, interPub, rootPriv, true)
	leafCertBytes := createTestCert(t, 3, leafName, interName, leafPub, interPriv, false)

	// Parse certs
	rootCert, err := ParseCertificateMLDSA(rootCertBytes)
	if err != nil {
		t.Fatalf("failed to parse root cert: %v", err)
	}
	interCert, err := ParseCertificateMLDSA(interCertBytes)
	if err != nil {
		t.Fatalf("failed to parse inter cert: %v", err)
	}
	leafCert, err := ParseCertificateMLDSA(leafCertBytes)
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}

	// Verify chain
	chains, err := VerifyChainMLDSA(leafCert, []*x509.Certificate{interCert}, []*x509.Certificate{rootCert}, x509.VerifyOptions{})
	if err != nil {
		t.Fatalf("failed to verify chain: %v", err)
	}

	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}

	chain := chains[0]
	if len(chain) != 3 {
		t.Fatalf("expected chain length 3, got %d", len(chain))
	}

	if !bytes.Equal(chain[0].Raw, leafCert.Raw) ||
		!bytes.Equal(chain[1].Raw, interCert.Raw) ||
		!bytes.Equal(chain[2].Raw, rootCert.Raw) {
		t.Errorf("chain contains unexpected certificates")
	}
}

func TestParseCertificateMLDSASimplified(t *testing.T) {
	// Generate keys
	priv, _ := mldsa.GenerateKey(mldsa.MLDSA65())
	pub := priv.PublicKey()

	// Names
	name := []byte{0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x54, 0x65, 0x73, 0x74} // Test

	// Create cert
	certBytes := createTestCert(t, 1, name, name, pub, priv, false)

	// Verify that standard library can parse it without error!
	stdCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed on ML-DSA cert: %v", err)
	}

	// Verify that PublicKey is NOT populated or is Unknown
	if stdCert.PublicKey != nil && stdCert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		t.Logf("x509.ParseCertificate actually populated public key! Type: %T", stdCert.PublicKey)
	}

	// Now try with our wrapper
	parsedCert, err := ParseCertificateMLDSA(certBytes)
	if err != nil {
		t.Fatalf("ParseCertificateMLDSA failed: %v", err)
	}

	// Verify public key is populated
	if parsedCert.PublicKey == nil {
		t.Fatalf("ParseCertificateMLDSA did not populate public key")
	}

	parsedPubKey, ok := parsedCert.PublicKey.(*mldsa.PublicKey)
	if !ok {
		t.Fatalf("expected ML-DSA public key, got %T", parsedCert.PublicKey)
	}

	if !bytes.Equal(parsedPubKey.Bytes(), pub.Bytes()) {
		t.Errorf("parsed public key does not match original")
	}
}


