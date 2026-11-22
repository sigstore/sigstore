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
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"filippo.io/edwards25519"
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

func TestED25519VerifierRejectsWrongKeySize(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33, 64} {
		if _, err := LoadED25519Verifier(ed25519.PublicKey(make([]byte, size))); err == nil {
			t.Errorf("expected error loading verifier with %d-byte key, got nil", size)
		}
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadED25519Verifier(pub); err != nil {
		t.Errorf("unexpected error loading verifier with valid key size: %v", err)
	}
}

// forgeNeutralRSig constructs an Ed25519 (or Ed25519ph when prehash is true)
// signature with R = neutral point (small-order) and S = k*s mod L, which
// satisfies Go stdlib's verification equation [S]B == R + [k]A.
func forgeNeutralRSig(t *testing.T, priv ed25519.PrivateKey, msg []byte, prehash bool) []byte {
	t.Helper()
	h := sha512.Sum512(priv.Seed())
	s, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		t.Fatalf("SetBytesWithClamping: %v", err)
	}
	rBytes := make([]byte, 32)
	rBytes[0] = 1 // neutral point
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", priv.Public())
	}

	kh := sha512.New()
	if prehash {
		kh.Write([]byte("SigEd25519 no Ed25519 collisions\x01\x00"))
	}
	kh.Write(rBytes)
	kh.Write(pub)
	if prehash {
		digest := sha512.Sum512(msg)
		kh.Write(digest[:])
	} else {
		kh.Write(msg)
	}
	k, err := edwards25519.NewScalar().SetUniformBytes(kh.Sum(nil))
	if err != nil {
		t.Fatalf("SetUniformBytes: %v", err)
	}
	sVal := edwards25519.NewScalar().Multiply(k, s)

	sig := make([]byte, ed25519.SignatureSize)
	copy(sig[:32], rBytes)
	copy(sig[32:], sVal.Bytes())
	return sig
}

func TestED25519VerifierRejectsSmallOrderKeysAndR(t *testing.T) {
	neutralKey, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	order2Key, _ := hex.DecodeString("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	nonCanonicalNeutral, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000080")

	for _, key := range []ed25519.PublicKey{neutralKey, order2Key, nonCanonicalNeutral} {
		if _, err := LoadED25519Verifier(key); err == nil {
			t.Errorf("expected LoadED25519Verifier to reject invalid key %x", key)
		}
		badPriv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
		copy(badPriv[32:], key)
		if _, err := LoadED25519Signer(badPriv); err == nil {
			t.Errorf("expected LoadED25519Signer to reject private key with invalid public suffix %x", key)
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v, err := LoadED25519Verifier(pub)
	if err != nil {
		t.Fatalf("unexpected error loading valid verifier: %v", err)
	}
	msg := []byte("test")
	smallOrderSig := forgeNeutralRSig(t, priv, msg, false)
	if !ed25519.Verify(pub, msg, smallOrderSig) {
		t.Fatalf("expected stdlib ed25519.Verify to accept forged small-order-R signature")
	}
	if err := v.VerifySignature(bytes.NewReader(smallOrderSig), bytes.NewReader(msg)); err == nil || !strings.Contains(err.Error(), "small-order R") {
		t.Errorf("expected VerifySignature to reject small-order R, got: %v", err)
	}

	// Mutating the caller's slice or the slice returned by PublicKey() must not affect the verifier.
	validSig := ed25519.Sign(priv, msg)
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
