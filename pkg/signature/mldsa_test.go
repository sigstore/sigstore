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
	"testing"
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
	testingSigner(t, sv, "mldsa", crypto.SHA256, message)
	testingVerifier(t, sv, "mldsa", crypto.SHA256, sig, message)
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

	testingVerifier(t, v, "mldsa", crypto.SHA256, sig, message)

	pub, err := v.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error from PublicKey(): %v", err)
	}
	if pub == nil {
		t.Fatalf("expected public key, got nil")
	}
}
