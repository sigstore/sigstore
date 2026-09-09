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
	"crypto/mldsa"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature/options"
)

func TestMLDSASignerVerifier(t *testing.T) {
	sv, _, err := NewDefaultMLDSASignerVerifier()
	if err != nil {
		t.Fatalf("unexpected error creating signer/verifier: %v", err)
	}

	message := []byte("sign me")
	sig, err := sv.SignMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatalf("unexpected error signing message: %v", err)
	}

	err = sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message))
	if err != nil {
		t.Fatalf("unexpected error verifying signature: %v", err)
	}

	// Verify that a bad signature fails
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[0] ^= 0xFF
	err = sv.VerifySignature(bytes.NewReader(badSig), bytes.NewReader(message))
	if err == nil {
		t.Fatalf("expected error verifying bad signature, got nil")
	}

	// Verify that a bad message fails
	err = sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader([]byte("bad message")))
	if err == nil {
		t.Fatalf("expected error verifying bad message, got nil")
	}

	pub, err := sv.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error from PublicKey(): %v", err)
	}
	if pub == nil {
		t.Fatalf("expected public key, got nil")
	}

	// Use the testing helpers
	testingSigner(t, sv, "mldsa", crypto.Hash(0), message)
	testingVerifier(t, sv, "mldsa", crypto.Hash(0), sig, message)
}

func TestMLDSAVerifier(t *testing.T) {
	sv, priv, err := NewDefaultMLDSASignerVerifier()
	if err != nil {
		t.Fatalf("unexpected error creating signer/verifier: %v", err)
	}

	pubKey := priv.PublicKey()

	v, err := LoadMLDSAVerifier(pubKey)
	if err != nil {
		t.Fatalf("unexpected error creating verifier: %v", err)
	}

	message := []byte("sign me")
	sig, err := sv.SignMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatalf("unexpected error signing message: %v", err)
	}

	testingVerifier(t, v, "mldsa", crypto.Hash(0), sig, message)

	pub, err := v.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error from PublicKey(): %v", err)
	}
	if pub == nil {
		t.Fatalf("expected public key, got nil")
	}
}

func TestMLDSAInvalidKeys(t *testing.T) {
	if _, err := LoadMLDSASigner(nil); err == nil || !strings.Contains(err.Error(), "invalid ML-DSA private key specified") {
		t.Errorf("expected error containing 'invalid ML-DSA private key specified' loading nil private key, got %v", err)
	}
	if _, err := LoadMLDSASigner(&mldsa.PrivateKey{}); err == nil || !strings.Contains(err.Error(), "invalid ML-DSA private key specified") {
		t.Errorf("expected error containing 'invalid ML-DSA private key specified' loading empty private key, got %v", err)
	}

	if _, err := LoadMLDSAVerifier(nil); err == nil || !strings.Contains(err.Error(), "invalid ML-DSA public key specified") {
		t.Errorf("expected error containing 'invalid ML-DSA public key specified' loading nil public key, got %v", err)
	}
	if _, err := LoadMLDSAVerifier(&mldsa.PublicKey{}); err == nil || !strings.Contains(err.Error(), "invalid ML-DSA public key specified") {
		t.Errorf("expected error containing 'invalid ML-DSA public key specified' loading empty public key, got %v", err)
	}

	if _, err := LoadMLDSASignerVerifier(nil); err == nil || !strings.Contains(err.Error(), "invalid ML-DSA private key specified") {
		t.Errorf("expected error containing 'invalid ML-DSA private key specified' loading nil private key in signer/verifier, got %v", err)
	}
	if _, err := LoadMLDSASignerVerifier(&mldsa.PrivateKey{}); err == nil || !strings.Contains(err.Error(), "invalid ML-DSA private key specified") {
		t.Errorf("expected error containing 'invalid ML-DSA private key specified' loading empty private key in signer/verifier, got %v", err)
	}
}

func TestMLDSASignerSignOptions(t *testing.T) {
	sv, _, err := NewDefaultMLDSASignerVerifier()
	if err != nil {
		t.Fatalf("unexpected error creating signer: %v", err)
	}

	msg := []byte("hello world")

	// Nil message should fail
	if _, err := sv.Sign(nil, nil, nil); err == nil || !strings.Contains(err.Error(), "message must not be nil") {
		t.Errorf("expected error containing 'message must not be nil', got %v", err)
	}

	// Nil opts should succeed
	sig, err := sv.Sign(nil, msg, nil)
	if err != nil {
		t.Fatalf("unexpected error with nil opts: %v", err)
	}
	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)); err != nil {
		t.Fatalf("unexpected error verifying signature: %v", err)
	}

	// Empty context should succeed
	sig, err = sv.Sign(nil, msg, &mldsa.Options{})
	if err != nil {
		t.Fatalf("unexpected error with empty context: %v", err)
	}
	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)); err != nil {
		t.Fatalf("unexpected error verifying signature: %v", err)
	}

	// Non-empty context should fail
	if _, err := sv.Sign(nil, msg, &mldsa.Options{Context: "domain-sep"}); err == nil || !strings.Contains(err.Error(), "non-empty context is not supported") {
		t.Errorf("expected error containing 'non-empty context is not supported', got %v", err)
	}

	// Unsupported hash func should fail
	if _, err := sv.Sign(nil, msg, crypto.SHA256); err == nil || !strings.Contains(err.Error(), "unsupported hash function") {
		t.Errorf("expected error containing 'unsupported hash function', got %v", err)
	}

	// Pre-hashed MLDSAMu should fail
	if _, err := sv.Sign(nil, msg, crypto.MLDSAMu); err == nil || !strings.Contains(err.Error(), "unsupported hash function") {
		t.Errorf("expected error containing 'unsupported hash function', got %v", err)
	}

	// SignMessage tests
	if _, err := sv.SignMessage(nil); err == nil || !strings.Contains(err.Error(), "message cannot be nil") {
		t.Errorf("expected error containing 'message cannot be nil', got %v", err)
	}

	// SignMessage with WithDigest should fail
	if _, err := sv.SignMessage(bytes.NewReader(msg), options.WithDigest(msg)); err == nil || !strings.Contains(err.Error(), "WithDigest is not supported") {
		t.Errorf("expected error containing 'WithDigest is not supported', got %v", err)
	}
}

func TestMLDSAVerifierOptions(t *testing.T) {
	sv, _, err := NewDefaultMLDSASignerVerifier()
	if err != nil {
		t.Fatalf("unexpected error creating signer/verifier: %v", err)
	}

	msg := []byte("hello world")
	sig, err := sv.SignMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("unexpected error signing message: %v", err)
	}

	// VerifySignature with nil message should fail
	if err := sv.VerifySignature(bytes.NewReader(sig), nil); err == nil || !strings.Contains(err.Error(), "message cannot be nil") {
		t.Errorf("expected error containing 'message cannot be nil', got %v", err)
	}

	// VerifySignature with nil signature should fail
	if err := sv.VerifySignature(nil, bytes.NewReader(msg)); err == nil || !strings.Contains(err.Error(), "nil signature passed") {
		t.Errorf("expected error containing 'nil signature passed', got %v", err)
	}

	// VerifySignature with WithDigest should fail
	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg), options.WithDigest(msg)); err == nil || !strings.Contains(err.Error(), "WithDigest is not supported") {
		t.Errorf("expected error containing 'WithDigest is not supported' in VerifySignature, got %v", err)
	}
}
