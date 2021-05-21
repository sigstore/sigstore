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
	"crypto/rand"
	"errors"
	"io"
)

type ED25519SignerVerifier struct {
	BaseSignerVerifierType
	private *ed25519.PrivateKey
}

func (e ED25519SignerVerifier) Hasher() func(crypto.SignerOpts, []byte) ([]byte, crypto.Hash, error) {
	return e.ComputeHash
}

func (e ED25519SignerVerifier) Public() crypto.PublicKey {
	return e.publicKey
}

func (e ED25519SignerVerifier) Sign(_ io.Reader, payload []byte, _ crypto.SignerOpts) ([]byte, error) {
	if e.private == nil {
		return nil, errors.New("ED25519 private key not initialized")
	}
	return ed25519.Sign(*e.private, payload), nil
}

func (e ED25519SignerVerifier) VerifySignature(payload, signature []byte) error {
	return e.VerifySignatureWithKey(e.publicKey, payload, signature)
}

func (e ED25519SignerVerifier) VerifySignatureWithKey(publicKey crypto.PublicKey, payload, signature []byte) error {
	pk := publicKey
	if pk == nil {
		pk = e.publicKey
		if pk == nil {
			return errors.New("public key has not been initialized")
		}
	}

	ed25519Pub, ok := pk.(*ed25519.PublicKey)
	if !ok {
		return errors.New("invalid ED25519 public key")
	}

	if ok := ed25519.Verify(*ed25519Pub, payload, signature); !ok {
		return errors.New("signature verification failed")
	}

	return nil
}

func NewED25519SignerVerifier(private *ed25519.PrivateKey, public *ed25519.PublicKey) ED25519SignerVerifier {
	return ED25519SignerVerifier{
		BaseSignerVerifierType: BaseSignerVerifierType{
			hashFunc:  crypto.Hash(0),
			publicKey: public,
		},
		private: private,
	}
}

func GenerateED25519SignerVerifier(seed [ed25519.SeedSize]byte) ED25519SignerVerifier {
	private := ed25519.NewKeyFromSeed(seed[:])
	public := private.Public().(ed25519.PublicKey)

	return NewED25519SignerVerifier(&private, &public)
}

func NewDefaultED25519SignerVerifier() (ED25519SignerVerifier, error) {
	var seed [ed25519.SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return ED25519SignerVerifier{}, err
	}
	return GenerateED25519SignerVerifier(seed), nil
}
