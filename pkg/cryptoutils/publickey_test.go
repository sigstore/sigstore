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
	// Keys of different type are not equal
	if err := EqualKeys(privRsa.Public(), pubEd); err == nil || !strings.Contains(err.Error(), "are not equal") {
		t.Fatalf("expected error for different key types, got %v", err)
	}
	// Fails with unexpected key type
	type PublicKey struct{}
	if err := EqualKeys(PublicKey{}, PublicKey{}); err == nil || err.Error() != "unsupported key type" {
		t.Fatalf("expected error for unsupported key type, got %v", err)
	}
}

func TestValidatePubKeyUnsupported(t *testing.T) {
	// Fails with unexpected key type
	type PublicKey struct{}
	err := ValidatePubKey(PublicKey{})
	if err == nil || err.Error() != "unsupported public key type" {
		t.Errorf("expected unsupported public key type, got %v", err)
	}
}

func TestValidatePubKeyRsa(t *testing.T) {
	// Validate common RSA key sizes
	for _, bits := range []int{2048, 3072, 4096} {
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatalf("rsa.GenerateKey failed: %v", err)
		}
		if err := ValidatePubKey(priv.Public()); err != nil {
			t.Errorf("unexpected error validating public key: %v", err)
		}
	}
	// Fails with small key size
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	if err := ValidatePubKey(priv.Public()); err == nil || err.Error() != "key too small: 1024" {
		t.Errorf("expected rsa key size too small, got %v", err)
	}
	// Fails with large key size
	priv, err = rsa.GenerateKey(rand.Reader, 5000)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	if err := ValidatePubKey(priv.Public()); err == nil || err.Error() != "key too large: 5000 > 4096" {
		t.Errorf("expected rsa key size too large, got %v", err)
	}
	// Fails with key size that's not a multiple of 8
	priv, err = rsa.GenerateKey(rand.Reader, 4095)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	if err := ValidatePubKey(priv.Public()); err == nil || err.Error() != "key length wasn't a multiple of 8: 4095" {
		t.Errorf("expected rsa key multiple error, got %v", err)
	}
}

func TestValidatePubKeyEcdsa(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey failed: %v", err)
		}
		if err := ValidatePubKey(priv.Public()); err != nil {
			t.Errorf("unexpected error validating public key: %v", err)
		}
	}
	// Fails with smalller curve
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	if err := ValidatePubKey(priv.Public()); err == nil || err.Error() != "unsupported ec curve, expected NIST P-256, P-384, or P-521" {
		t.Errorf("expected unsupported curve, got %v", err)
	}
	// Fails with unknown curve
	err = ValidatePubKey(&ecdsa.PublicKey{})
	if err == nil || err.Error() != "unexpected ec curve" {
		t.Errorf("expected unexpected curve, got %v", err)
	}
}

func TestValidatePubKeyEd25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	if err := ValidatePubKey(pub); err != nil {
		t.Errorf("unexpected error validating public key: %v", err)
	}
	// Only success, ED25519 keys do not support customization
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
