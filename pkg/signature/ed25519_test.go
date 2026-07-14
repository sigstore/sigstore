//
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

package signature

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// Generated with:
// openssl genpkey -algorithm ed25519 -outform PEM -out -
const ed25519Priv = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFP9CZb6J1DiOLfdIkPfy1bwBOCjEG6KR/cIdhw90J1H
-----END PRIVATE KEY-----`

// Extracted from above with:
// openssl ec -in ec_private.pem -pubout
const ed25519Pub = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9wy4umF4RHQ8UQXo8fzEQNBWE4GsBMkCzQPAfHvkf/s=
-----END PUBLIC KEY-----`

func TestED25519SignerVerifier(t *testing.T) {
	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey([]byte(ed25519Priv), cryptoutils.SkipPassword)
	if err != nil {
		t.Fatalf("unexpected error unmarshalling public key: %v", err)
	}
	edPriv, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey")
	}

	sv, err := LoadED25519SignerVerifier(edPriv)
	if err != nil {
		t.Fatalf("unexpected error creating signer/verifier: %v", err)
	}

	message := []byte("sign me")
	sig, _ := base64.StdEncoding.DecodeString("cnafwd8DKq2nQ564eN66ckYV8anVFGFi5vaYiQg2aal7ej/J0/OE0PPdKHLHe9wdzWRMFy5MpurRD/2cGXGLBQ==")
	testingSigner(t, sv, "ed25519", crypto.SHA256, message)
	testingVerifier(t, sv, "ed25519", crypto.SHA256, sig, message)
	pub, err := sv.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error from PublicKey(): %v", err)
	}
	assertPublicKeyIsx509Marshalable(t, pub)
}

func TestED25519Verifier(t *testing.T) {
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(ed25519Pub))
	if err != nil {
		t.Fatalf("unexpected error unmarshalling public key: %v", err)
	}
	edPub, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is not ed25519")
	}

	v, err := LoadED25519Verifier(edPub)
	if err != nil {
		t.Fatalf("unexpected error creating verifier: %v", err)
	}

	message := []byte("sign me")
	sig, _ := base64.StdEncoding.DecodeString("cnafwd8DKq2nQ564eN66ckYV8anVFGFi5vaYiQg2aal7ej/J0/OE0PPdKHLHe9wdzWRMFy5MpurRD/2cGXGLBQ==")
	testingVerifier(t, v, "ed25519", crypto.SHA256, sig, message)
	pub, err := v.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error from PublicKey(): %v", err)
	}
	assertPublicKeyIsx509Marshalable(t, pub)
}

// TestED25519VerifierRejectsWrongKeySize ensures LoadED25519Verifier validates
// the public key length up front and returns an error, instead of accepting a
// malformed key and letting ed25519.Verify panic during VerifySignature. This
// mirrors the guard already present in LoadED25519Signer.
func TestED25519VerifierRejectsWrongKeySize(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33, 64} {
		if _, err := LoadED25519Verifier(ed25519.PublicKey(make([]byte, size))); err == nil {
			t.Errorf("expected error loading verifier with %d-byte key, got nil", size)
		}
	}
	if _, err := LoadED25519Verifier(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))); err != nil {
		t.Errorf("unexpected error loading verifier with valid key size: %v", err)
	}
}
