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
	type PublicKey struct {
	}
	if err := EqualKeys(PublicKey{}, PublicKey{}); err == nil || err.Error() != "unsupported key type" {
		t.Fatalf("expected error for unsupported key type, got %v", err)
	}
}
