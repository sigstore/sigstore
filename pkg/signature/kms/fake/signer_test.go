// Copyright 2022 The Sigstore Authors.
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

package fake

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature/kms"
)

func TestFakeSigner(t *testing.T) {
	msg := []byte{1, 2, 3, 4, 5}

	signer, err := kms.Get(context.Background(), "fakekms://key", crypto.SHA256)
	if err != nil {
		t.Fatalf("unexpected error getting signer: %v", err)
	}
	pub, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error getting public key")
	}
	createdPub, err := signer.CreateKey(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error creating key: %v", err)
	}
	if err := cryptoutils.EqualKeys(createdPub, pub); err != nil {
		t.Fatalf("expected public keys to be equal: %v", err)
	}

	if signer.DefaultAlgorithm() != signer.SupportedAlgorithms()[0] {
		t.Fatal("expected algorithms to match")
	}

	// Test crypto.Signer implementation
	cryptoSigner, _, err := signer.CryptoSigner(context.Background(), func(err error) {})
	if err != nil {
		t.Fatalf("unexpected error fetching crypto.Signer: %v", err)
	}
	if err := cryptoutils.EqualKeys(cryptoSigner.Public(), pub); err != nil {
		t.Fatalf("expected public keys to be equal: %v", err)
	}

	sha := sha256.New()
	sha.Write(msg)
	digest := sha.Sum(nil)
	sig, err := cryptoSigner.Sign(rand.Reader, digest, nil)
	if err != nil {
		t.Fatalf("unexpected error signing with crypto.Signer: %v", err)
	}
	if err := signer.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)); err != nil {
		t.Fatalf("unexpected error verifying signature: %v", err)
	}
}

func TestFakeSignerWithPrivateKey(t *testing.T) {
	msg := []byte{1, 2, 3, 4, 5}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating ecdsa private key: %v", err)
	}

	signer, err := kms.Get(context.WithValue(context.TODO(), KmsCtxKey{}, priv), "fakekms://key", crypto.SHA256)
	if err != nil {
		t.Fatalf("unexpected error getting signer: %v", err)
	}
	pub, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error getting public key")
	}

	// Compare public key to provided key
	if err := cryptoutils.EqualKeys(priv.Public(), pub); err != nil {
		t.Fatalf("expected public keys to be equal: %v", err)
	}

	createdPub, err := signer.CreateKey(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error creating key: %v", err)
	}
	if err := cryptoutils.EqualKeys(createdPub, pub); err != nil {
		t.Fatalf("expected public keys to be equal: %v", err)
	}

	if signer.DefaultAlgorithm() != signer.SupportedAlgorithms()[0] {
		t.Fatal("expected algorithms to match")
	}

	// Test crypto.Signer implementation
	cryptoSigner, _, err := signer.CryptoSigner(context.Background(), func(err error) {})
	if err != nil {
		t.Fatalf("unexpected error fetching crypto.Signer: %v", err)
	}
	if err := cryptoutils.EqualKeys(cryptoSigner.Public(), pub); err != nil {
		t.Fatalf("expected public keys to be equal: %v", err)
	}

	sha := sha256.New()
	sha.Write(msg)
	digest := sha.Sum(nil)
	sig, err := cryptoSigner.Sign(rand.Reader, digest, nil)
	if err != nil {
		t.Fatalf("unexpected error signing with crypto.Signer: %v", err)
	}
	if err := signer.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)); err != nil {
		t.Fatalf("unexpected error verifying signature: %v", err)
	}
}
