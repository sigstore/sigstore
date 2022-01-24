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
