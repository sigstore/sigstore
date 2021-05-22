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
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	_ "crypto/sha256" // To ensure `crypto.SHA256` is implemented.
	"errors"
	"fmt"
)

type ED25519Verifier struct {
	Key ed25519.PublicKey
}

type ED25519SignerVerifier struct {
	ED25519Verifier
	Key ed25519.PrivateKey
}

func (k ED25519SignerVerifier) Sign(_ context.Context, rawPayload []byte) (signature, signed []byte, err error) {
	signature = ed25519.Sign(k.Key, rawPayload)
	return
}

func (k ED25519Verifier) Verify(_ context.Context, rawPayload, signature []byte) error {
	if !ed25519.Verify(k.Key, rawPayload, signature) {
		return errors.New("unable to verify signature")
	}
	return nil
}

func (k ED25519Verifier) PublicKey(_ context.Context) (crypto.PublicKey, error) { //nolint
	return k.Key, nil
}

var _ SignerVerifier = ECDSASignerVerifier{}
var _ Verifier = ECDSAVerifier{}

func NewED25519SignerVerifier(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey) ED25519SignerVerifier {
	return ED25519SignerVerifier{
		ED25519Verifier: ED25519Verifier{
			Key: pubKey,
		},
		Key: privKey,
	}
}

func NewDefaultED25519SignerVerifier() (ED25519SignerVerifier, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ED25519SignerVerifier{}, fmt.Errorf("could not generate ed25519 keypair: %v", err)
	}
	return NewED25519SignerVerifier(pubKey, privKey), nil
}
