//
// Copyright 2024 The Sigstore Authors.
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

package signature

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// Generated with:
// openssl genpkey -algorithm ed25519 -outform PEM -out -
const ed25519phPriv = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFP9CZb6J1DiOLfdIkPfy1bwBOCjEG6KR/cIdhw90J1H
-----END PRIVATE KEY-----`

// Extracted from above with:
// openssl ec -in ec_private.pem -pubout
const ed25519phPub = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9wy4umF4RHQ8UQXo8fzEQNBWE4GsBMkCzQPAfHvkf/s=
-----END PUBLIC KEY-----`

func TestED25519phSignerVerifier(t *testing.T) {
	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey([]byte(ed25519phPriv), cryptoutils.SkipPassword)
	if err != nil {
		t.Fatalf("unexpected error unmarshalling public key: %v", err)
	}
	edPriv, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey")
	}

	sv, err := LoadED25519phSignerVerifier(edPriv)
	if err != nil {
		t.Fatalf("unexpected error creating signer/verifier: %v", err)
	}

	message := []byte("sign me")
	sig, _ := base64.StdEncoding.DecodeString("9D4pA8jutZnbqKy4fFRl+kDsVUCO50qrOD1lxmsiUFk6NX+7OXUK5BCMkE2KYPRDxjkDFBzbDZEQhaFdDV5tDg==")
	testingSigner(t, sv, "ed25519ph", crypto.SHA512, message)
	testingVerifier(t, sv, "ed25519ph", crypto.SHA512, sig, message)
	pub, err := sv.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error from PublicKey(): %v", err)
	}
	assertPublicKeyIsx509Marshalable(t, pub)
}

func TestED25519phVerifier(t *testing.T) {
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(ed25519phPub))
	if err != nil {
		t.Fatalf("unexpected error unmarshalling public key: %v", err)
	}
	edPub, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is not ed25519")
	}

	v, err := LoadED25519phVerifier(edPub)
	if err != nil {
		t.Fatalf("unexpected error creating verifier: %v", err)
	}

	message := []byte("sign me")
	sig, _ := base64.StdEncoding.DecodeString("9D4pA8jutZnbqKy4fFRl+kDsVUCO50qrOD1lxmsiUFk6NX+7OXUK5BCMkE2KYPRDxjkDFBzbDZEQhaFdDV5tDg==")
	testingVerifier(t, v, "ed25519ph", crypto.SHA512, sig, message)
	pub, err := v.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error from PublicKey(): %v", err)
	}
	assertPublicKeyIsx509Marshalable(t, pub)
}

func TestED25519phVerifierRejectsWrongKeySize(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33, 64} {
		if _, err := LoadED25519phVerifier(ed25519.PublicKey(make([]byte, size))); err == nil {
			t.Errorf("expected error loading verifier with %d-byte key, got nil", size)
		}
	}
	pub, _, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadED25519phVerifier(pub); err != nil {
		t.Errorf("unexpected error loading verifier with valid key size: %v", err)
	}
}

func TestED25519phVerifierRejectsSmallOrderKeysAndR(t *testing.T) {
	neutralKey, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	order2Key, _ := hex.DecodeString("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	nonCanonicalNeutral, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000080")

	for _, key := range []ed25519.PublicKey{neutralKey, order2Key, nonCanonicalNeutral} {
		if _, err := LoadED25519phVerifier(key); err == nil {
			t.Errorf("expected LoadED25519phVerifier to reject invalid key %x", key)
		}
		badPriv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
		copy(badPriv[32:], key)
		if _, err := LoadED25519phSigner(badPriv); err == nil {
			t.Errorf("expected LoadED25519phSigner to reject private key with invalid public suffix %x", key)
		}
	}

	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v, err := LoadED25519phVerifier(pub)
	if err != nil {
		t.Fatalf("unexpected error loading valid verifier: %v", err)
	}
	msg := []byte("test")
	digest := sha512.Sum512(msg)
	smallOrderSig := forgeNeutralRSig(t, priv, msg, true)
	if err := ed25519.VerifyWithOptions(pub, digest[:], smallOrderSig, &ed25519.Options{Hash: crypto.SHA512}); err != nil {
		t.Fatalf("expected stdlib ed25519.VerifyWithOptions to accept forged small-order-R signature, got: %v", err)
	}
	if err := v.VerifySignature(bytes.NewReader(smallOrderSig), bytes.NewReader(msg)); err == nil || !strings.Contains(err.Error(), "small-order R") {
		t.Errorf("expected VerifySignature to reject small-order R, got: %v", err)
	}

	// Mutating the caller's slice or the slice returned by PublicKey() must not affect the verifier.
	validSig, err := priv.Sign(nil, digest[:], crypto.SHA512)
	if err != nil {
		t.Fatalf("priv.Sign error: %v", err)
	}
	copy(pub, neutralKey)
	gotPub, err := v.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error: %v", err)
	}
	gotPubKey, ok := gotPub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", gotPub)
	}
	copy(gotPubKey, neutralKey)
	if err := v.VerifySignature(bytes.NewReader(validSig), bytes.NewReader(msg)); err != nil {
		t.Errorf("mutating external public key slices corrupted verifier: %v", err)
	}
}

func TestED25519phSignerRejectsWrongKeySize(t *testing.T) {
	for _, size := range []int{0, 16, 31, 32, 33, 63, 65} {
		if _, err := LoadED25519phSigner(ed25519.PrivateKey(make([]byte, size))); err == nil {
			t.Errorf("expected error loading signer with %d-byte key, got nil", size)
		}
		if _, err := LoadED25519phSignerVerifier(ed25519.PrivateKey(make([]byte, size))); err == nil {
			t.Errorf("expected error loading signer verifier with %d-byte key, got nil", size)
		}
	}
	_, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadED25519phSigner(priv); err != nil {
		t.Errorf("unexpected error loading signer with valid key size: %v", err)
	}
	if _, err := LoadED25519phSignerVerifier(priv); err != nil {
		t.Errorf("unexpected error loading signer verifier with valid key size: %v", err)
	}
}
