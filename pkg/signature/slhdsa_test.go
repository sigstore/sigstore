//
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

package signature

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func TestSLHDSASignerVerifier(t *testing.T) {
	sv, _, err := NewDefaultSLHDSASignerVerifier()
	if err != nil {
		t.Fatalf("unexpected error creating signer/verifier: %v", err)
	}

	message := []byte("sign me")
	sig, err := sv.SignMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatalf("unexpected error signing message: %v", err)
	}

	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message)); err != nil {
		t.Fatalf("unexpected error verifying signature: %v", err)
	}

	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[0] ^= 0xFF
	if err := sv.VerifySignature(bytes.NewReader(badSig), bytes.NewReader(message)); err == nil {
		t.Fatalf("expected error verifying bad signature, got nil")
	}

	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader([]byte("bad message"))); err == nil {
		t.Fatalf("expected error verifying bad message, got nil")
	}

	pub, err := sv.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error from PublicKey(): %v", err)
	}
	if pub == nil {
		t.Fatalf("expected public key, got nil")
	}

	testingSigner(t, sv, "slhdsa", crypto.Hash(0), message)
	testingVerifier(t, sv, "slhdsa", crypto.Hash(0), sig, message)
}

func TestSLHDSAVerifier(t *testing.T) {
	sv, priv, err := NewDefaultSLHDSASignerVerifier()
	if err != nil {
		t.Fatalf("unexpected error creating signer/verifier: %v", err)
	}

	pubKey := priv.PublicKey()
	v, err := LoadSLHDSAVerifier(&pubKey)
	if err != nil {
		t.Fatalf("unexpected error creating verifier: %v", err)
	}

	message := []byte("sign me")
	sig, err := sv.SignMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatalf("unexpected error signing message: %v", err)
	}

	testingVerifier(t, v, "slhdsa", crypto.Hash(0), sig, message)

	pub, err := v.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error from PublicKey(): %v", err)
	}
	if pub == nil {
		t.Fatalf("expected public key, got nil")
	}
}

func TestSLHDSAInvalidKeys(t *testing.T) {
	if _, err := LoadSLHDSASigner(nil); err == nil || !strings.Contains(err.Error(), "invalid SLH-DSA private key specified") {
		t.Errorf("expected error containing 'invalid SLH-DSA private key specified' loading nil private key, got %v", err)
	}

	if _, err := LoadSLHDSAVerifier(nil); err == nil || !strings.Contains(err.Error(), "invalid SLH-DSA public key specified") {
		t.Errorf("expected error containing 'invalid SLH-DSA public key specified' loading nil public key, got %v", err)
	}
	if _, err := LoadSLHDSAVerifier(&slhdsa.PublicKey{}); err == nil || !strings.Contains(err.Error(), "invalid SLH-DSA public key specified") {
		t.Errorf("expected error containing 'invalid SLH-DSA public key specified' loading empty public key, got %v", err)
	}

	if _, err := LoadSLHDSASignerVerifier(nil); err == nil || !strings.Contains(err.Error(), "invalid SLH-DSA private key specified") {
		t.Errorf("expected error containing 'invalid SLH-DSA private key specified' loading nil private key in signer/verifier, got %v", err)
	}
}

func TestSLHDSASignerSignOptions(t *testing.T) {
	sv, _, err := NewDefaultSLHDSASignerVerifier()
	if err != nil {
		t.Fatalf("unexpected error creating signer: %v", err)
	}

	msg := []byte("hello world")

	if _, err := sv.Sign(nil, nil, nil); err == nil || !strings.Contains(err.Error(), "message must not be nil") {
		t.Errorf("expected error containing 'message must not be nil', got %v", err)
	}

	sig, err := sv.Sign(nil, msg, nil)
	if err != nil {
		t.Fatalf("unexpected error with nil opts: %v", err)
	}
	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)); err != nil {
		t.Fatalf("unexpected error verifying signature: %v", err)
	}

	if _, err := sv.Sign(nil, msg, crypto.SHA256); err == nil || !strings.Contains(err.Error(), "unsupported hash function") {
		t.Errorf("expected error containing 'unsupported hash function', got %v", err)
	}

	if _, err := sv.SignMessage(nil); err == nil || !strings.Contains(err.Error(), "message cannot be nil") {
		t.Errorf("expected error containing 'message cannot be nil', got %v", err)
	}

	if _, err := sv.SignMessage(bytes.NewReader(msg), options.WithDigest(msg)); err == nil || !strings.Contains(err.Error(), "WithDigest is not supported") {
		t.Errorf("expected error containing 'WithDigest is not supported', got %v", err)
	}
}

func TestSLHDSAVerifierOptions(t *testing.T) {
	sv, _, err := NewDefaultSLHDSASignerVerifier()
	if err != nil {
		t.Fatalf("unexpected error creating signer/verifier: %v", err)
	}

	msg := []byte("hello world")
	sig, err := sv.SignMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("unexpected error signing message: %v", err)
	}

	if err := sv.VerifySignature(bytes.NewReader(sig), nil); err == nil || !strings.Contains(err.Error(), "message cannot be nil") {
		t.Errorf("expected error containing 'message cannot be nil', got %v", err)
	}

	if err := sv.VerifySignature(nil, bytes.NewReader(msg)); err == nil || !strings.Contains(err.Error(), "nil signature passed") {
		t.Errorf("expected error containing 'nil signature passed', got %v", err)
	}

	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg), options.WithDigest(msg)); err == nil || !strings.Contains(err.Error(), "WithDigest is not supported") {
		t.Errorf("expected error containing 'WithDigest is not supported' in VerifySignature, got %v", err)
	}
}

// TestSLHDSAParameterSets exercises every FIPS 205 parameter set end to end so a
// change to the default or to the key handling cannot silently break one of them.
func TestSLHDSAParameterSets(t *testing.T) {
	ids := []slhdsa.ID{
		slhdsa.SHA2_128s, slhdsa.SHAKE_128s,
		slhdsa.SHA2_192s, slhdsa.SHAKE_192s,
		slhdsa.SHA2_256s, slhdsa.SHAKE_256s,
	}
	message := []byte("sign me")
	for _, id := range ids {
		sv, _, err := NewSLHDSASignerVerifier(id)
		if err != nil {
			t.Fatalf("%v: unexpected error creating signer/verifier: %v", id, err)
		}
		sig, err := sv.SignMessage(bytes.NewReader(message))
		if err != nil {
			t.Fatalf("%v: unexpected error signing: %v", id, err)
		}
		if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message)); err != nil {
			t.Fatalf("%v: unexpected error verifying: %v", id, err)
		}
	}
}

// TestSLHDSAInteropWithLibrary confirms that a signature produced by this signer
// verifies with the underlying library directly, and that a signature produced by
// the library verifies through this verifier, so the wrapper adds no divergence.
func TestSLHDSAInteropWithLibrary(t *testing.T) {
	_, priv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	if err != nil {
		t.Fatalf("unexpected error generating key: %v", err)
	}
	pub := priv.PublicKey()

	signer, err := LoadSLHDSASigner(&priv)
	if err != nil {
		t.Fatalf("unexpected error loading signer: %v", err)
	}
	verifier, err := LoadSLHDSAVerifier(&pub)
	if err != nil {
		t.Fatalf("unexpected error loading verifier: %v", err)
	}

	message := []byte("interoperability")

	sigFromWrapper, err := signer.SignMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatalf("unexpected error signing through wrapper: %v", err)
	}
	if !slhdsa.Verify(&pub, slhdsa.NewMessage(message), sigFromWrapper, nil) {
		t.Fatal("library failed to verify a signature produced by the wrapper")
	}

	sigFromLibrary, err := slhdsa.SignDeterministic(&priv, slhdsa.NewMessage(message), nil)
	if err != nil {
		t.Fatalf("unexpected error signing through library: %v", err)
	}
	if err := verifier.VerifySignature(bytes.NewReader(sigFromLibrary), bytes.NewReader(message)); err != nil {
		t.Fatalf("wrapper failed to verify a signature produced by the library: %v", err)
	}
}
