// Copyright 2021 The Sigstore Authors.
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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func verifyPublicKeyPEMRoundtrip(t *testing.T, pub crypto.PublicKey) {
	t.Helper()
	pemBytes, err := MarshalPublicKeyToPEM(pub)
	if err != nil {
		t.Fatalf("MarshalPublicKeyToPEM returned error: %v", err)
	}
	rtPub, err := UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		t.Fatalf("UnmarshalPEMToPublicKey returned error: %v", err)
	}
	if d := cmp.Diff(pub, rtPub); d != "" {
		t.Errorf("round-tripped public key was malformed (-before +after): %s", d)
	}
}

func TestECDSAPublicKeyPEMRoundtrip(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	verifyPublicKeyPEMRoundtrip(t, priv.Public())
}

func TestEd25519PublicKeyPEMRoundtrip(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	verifyPublicKeyPEMRoundtrip(t, pub)
}

func TestRSAPublicKeyPEMRoundtrip(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	verifyPublicKeyPEMRoundtrip(t, priv.Public())
}

func TestMLDSAPublicKeyPEMRoundtrip(t *testing.T) {
	t.Parallel()
	for _, param := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		priv, err := mldsa.GenerateKey(param)
		if err != nil {
			t.Fatalf("mldsa.GenerateKey failed: %v", err)
		}
		verifyPublicKeyPEMRoundtrip(t, priv.PublicKey())
	}
}

func TestSKIDRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	skid, err := SKID(priv.Public())
	if err != nil {
		t.Fatalf("SKID failed: %v", err)
	}
	// Expect SKID is 160 bits (20 bytes)
	if len(skid) != 20 {
		t.Fatalf("SKID failed: %v", skid)
	}
}

func TestSKIDECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	skid, err := SKID(priv.Public())
	if err != nil {
		t.Fatalf("SKID failed: %v", err)
	}
	// Expect SKID is 160 bits (20 bytes)
	if len(skid) != 20 {
		t.Fatalf("SKID failed: %v", skid)
	}
}

func TestSKIDED25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	skid, err := SKID(pub)
	if err != nil {
		t.Fatalf("SKID failed: %v", err)
	}
	// Expect SKID is 160 bits (20 bytes)
	if len(skid) != 20 {
		t.Fatalf("SKID failed: %v", skid)
	}
}

func TestSKIDMLDSA(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey failed: %v", err)
	}
	skid, err := SKID(priv.PublicKey())
	if err != nil {
		t.Fatalf("SKID failed for valid ML-DSA key: %v", err)
	}
	if len(skid) != 20 {
		t.Fatalf("expected 20-byte SKID, got %d bytes", len(skid))
	}

	// Nil ML-DSA key
	if _, err := SKID((*mldsa.PublicKey)(nil)); err == nil || !strings.Contains(err.Error(), "ML-DSA public key must not be nil") {
		t.Fatalf("expected error for nil mldsa key, got %v", err)
	}

	// Empty ML-DSA key
	if _, err := SKID(&mldsa.PublicKey{}); err == nil || !strings.Contains(err.Error(), "invalid ML-DSA public key") {
		t.Fatalf("expected error for empty mldsa key, got %v", err)
	}
}

func TestEqualKeys(t *testing.T) {
	// Test RSA (success and failure)
	privRsa, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	privRsa2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	if err := EqualKeys(privRsa.Public(), privRsa.Public()); err != nil {
		t.Fatalf("unexpected error for rsa equality, got %v", err)
	}
	if err := EqualKeys(privRsa.Public(), privRsa2.Public()); err == nil || !strings.Contains(err.Error(), "rsa public keys are not equal") {
		t.Fatalf("expected error for different rsa keys, got %v", err)
	}
	// Test ECDSA (success and failure)
	privEcdsa, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	privEcdsa2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	if err := EqualKeys(privEcdsa.Public(), privEcdsa.Public()); err != nil {
		t.Fatalf("unexpected error for ecdsa equality, got %v", err)
	}
	if err := EqualKeys(privEcdsa.Public(), privEcdsa2.Public()); err == nil || !strings.Contains(err.Error(), "ecdsa public keys are not equal") {
		t.Fatalf("expected error for different ecdsa keys, got %v", err)
	}
	// Test ED25519 (success and failure)
	pubEd, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	pubEd2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	if err := EqualKeys(pubEd, pubEd); err != nil {
		t.Fatalf("unexpected error for ed25519 equality, got %v", err)
	}
	if err := EqualKeys(pubEd, pubEd2); err == nil || !strings.Contains(err.Error(), "ed25519 public keys are not equal") {
		t.Fatalf("expected error for different ed25519 keys, got %v", err)
	}
	// Test ML-DSA (success and failure)
	mldsa44First, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey failed: %v", err)
	}
	mldsa44Second, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey failed: %v", err)
	}
	mldsa65Key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey failed: %v", err)
	}
	// Verify equality with a separately constructed representation of the same key
	mldsa44Same, err := mldsa.NewPublicKey(mldsa.MLDSA44(), mldsa44First.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("mldsa.NewPublicKey failed: %v", err)
	}
	if err := EqualKeys(mldsa44First.PublicKey(), mldsa44Same); err != nil {
		t.Fatalf("unexpected error for mldsa equality with separate representation, got %v", err)
	}
	if err := EqualKeys(mldsa44First.PublicKey(), mldsa44Second.PublicKey()); err == nil || !strings.Contains(err.Error(), "mldsa public keys are not equal") {
		t.Fatalf("expected error for different mldsa keys, got %v", err)
	}
	if err := EqualKeys(mldsa44First.PublicKey(), mldsa65Key.PublicKey()); err == nil || !strings.Contains(err.Error(), "mldsa public keys are not equal") {
		t.Fatalf("expected error for different mldsa parameter keys, got %v", err)
	}
	// Broken first argument
	if err := EqualKeys((*mldsa.PublicKey)(nil), mldsa44First.PublicKey()); err == nil || !strings.Contains(err.Error(), "ML-DSA public key must not be nil") {
		t.Fatalf("expected error for nil first mldsa key, got %v", err)
	}
	if err := EqualKeys(&mldsa.PublicKey{}, mldsa44First.PublicKey()); err == nil || !strings.Contains(err.Error(), "invalid ML-DSA public key") {
		t.Fatalf("expected error for empty first mldsa key, got %v", err)
	}
	// Broken second argument reports inequality without panicking
	if err := EqualKeys(mldsa44First.PublicKey(), (*mldsa.PublicKey)(nil)); err == nil || !strings.Contains(err.Error(), "mldsa public keys are not equal") {
		t.Fatalf("expected inequality error for nil second mldsa key, got %v", err)
	}
	if err := EqualKeys(mldsa44First.PublicKey(), &mldsa.PublicKey{}); err == nil || !strings.Contains(err.Error(), "mldsa public keys are not equal") {
		t.Fatalf("expected inequality error for empty second mldsa key, got %v", err)
	}
	// Keys of different type are not equal
	if err := EqualKeys(privRsa.Public(), pubEd); err == nil || !strings.Contains(err.Error(), "are not equal") {
		t.Fatalf("expected error for different key types (rsa vs ed25519), got %v", err)
	}
	if err := EqualKeys(mldsa44First.PublicKey(), pubEd); err == nil || !strings.Contains(err.Error(), "are not equal") {
		t.Fatalf("expected error for different key types (mldsa vs ed25519), got %v", err)
	}
	// Verify that EqualKeys with a valid non-ML-DSA key and an invalid ML-DSA key exercises
	// the SKID guard in genErrMsg without panicking.
	if err := EqualKeys(privRsa.Public(), &mldsa.PublicKey{}); err == nil || !strings.Contains(err.Error(), "rsa public keys are not equal") {
		t.Fatalf("expected error for rsa vs uninitialized mldsa key, got %v", err)
	}
	if err := EqualKeys(privRsa.Public(), (*mldsa.PublicKey)(nil)); err == nil || !strings.Contains(err.Error(), "rsa public keys are not equal") {
		t.Fatalf("expected error for rsa vs nil mldsa key, got %v", err)
	}
	// Fails with unexpected key type
	type PublicKey struct{}
	if err := EqualKeys(PublicKey{}, PublicKey{}); err == nil || err.Error() != "unsupported key type" {
		t.Fatalf("expected error for unsupported key type, got %v", err)
	}
}

func TestUnmarshalPEMToPublicKey(t *testing.T) {
	// test PKIX PEM-encoded public keys
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	pkixPubKey, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey failed: %v", err)
	}
	pkixPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixPubKey,
	})
	k, err := UnmarshalPEMToPublicKey(pkixPEMBlock)
	if err != nil {
		t.Fatalf("UnmarshalPEMToPublicKey for PKIX failed: %v", err)
	}
	if EqualKeys(priv.Public(), k) != nil {
		t.Fatalf("public keys for PKIX are not equal")
	}

	// test PKCS#1 PEM-encoded RSA public keys
	priv, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	rsaPubKey := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	pkcs1PEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: rsaPubKey,
	})
	k, err = UnmarshalPEMToPublicKey(pkcs1PEMBlock)
	if err != nil {
		t.Fatalf("UnmarshalPEMToPublicKey for PKCS#1 failed: %v", err)
	}
	if EqualKeys(priv.Public(), k) != nil {
		t.Fatalf("public keys for PKCS1 are not equal")
	}

	// test other PEM formats return an error
	invalidPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: rsaPubKey,
	})
	_, err = UnmarshalPEMToPublicKey(invalidPEMBlock)
	if err == nil || !strings.Contains(err.Error(), "unknown Public key PEM file type") {
		t.Fatalf("expected error unmarshalling invalid PEM block, got: %v", err)
	}
}

func TestValidatePubKey(t *testing.T) {
	// Valid keys
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa3072, _ := rsa.GenerateKey(rand.Reader, 3072)
	rsa4096, _ := rsa.GenerateKey(rand.Reader, 4096)
	ecdsaP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecdsaP521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	ed25519Key, _, _ := ed25519.GenerateKey(rand.Reader)
	mldsaPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey failed: %v", err)
	}

	// Invalid keys
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	ecdsaP224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	type TestPublicKey struct{}

	testCases := []struct {
		name    string
		key     crypto.PublicKey
		wantErr bool
	}{
		{
			name: "valid rsa 2048",
			key:  &rsa2048.PublicKey,
		},
		{
			name: "valid rsa 3072",
			key:  &rsa3072.PublicKey,
		},
		{
			name: "valid rsa 4096",
			key:  &rsa4096.PublicKey,
		},
		{
			name: "valid ecdsa p256",
			key:  &ecdsaP256.PublicKey,
		},
		{
			name: "valid ecdsa p384",
			key:  &ecdsaP384.PublicKey,
		},
		{
			name: "valid ecdsa p521",
			key:  &ecdsaP521.PublicKey,
		},
		{
			name: "valid ed25519",
			key:  ed25519Key,
		},
		{
			name: "valid mldsa",
			key:  mldsaPriv.PublicKey(),
		},
		{
			name:    "invalid rsa 1024",
			key:     &rsa1024.PublicKey,
			wantErr: true,
		},
		{
			name:    "invalid ecdsa p224",
			key:     &ecdsaP224.PublicKey,
			wantErr: true,
		},
		{
			name:    "unsupported key type",
			key:     TestPublicKey{},
			wantErr: true,
		},
		{
			name:    "nil key",
			key:     nil,
			wantErr: true,
		},
		{
			name:    "invalid mldsa nil",
			key:     (*mldsa.PublicKey)(nil),
			wantErr: true,
		},
		{
			name:    "invalid mldsa empty",
			key:     &mldsa.PublicKey{},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePubKey(tc.key)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidatePubKey() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateMLDSAPublicKey(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey failed: %v", err)
	}
	params, err := ValidateMLDSAPublicKey(priv.PublicKey())
	if err != nil {
		t.Errorf("unexpected error for valid ML-DSA public key: %v", err)
	}
	if params != mldsa.MLDSA44() {
		t.Errorf("expected MLDSA44 parameters, got %v", params)
	}

	if _, err := ValidateMLDSAPublicKey(nil); err == nil || !strings.Contains(err.Error(), "ML-DSA public key must not be nil") {
		t.Errorf("expected error containing 'ML-DSA public key must not be nil', got %v", err)
	}

	if _, err := ValidateMLDSAPublicKey(&mldsa.PublicKey{}); err == nil || !strings.Contains(err.Error(), "invalid ML-DSA public key") {
		t.Errorf("expected error containing 'invalid ML-DSA public key', got %v", err)
	}
}
