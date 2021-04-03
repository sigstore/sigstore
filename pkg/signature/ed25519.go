/*
Copyright 2021 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signature

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

type Ed25519Verifier struct {
	Key ed25519.PublicKey
}

type Ed25519SignerVerifier struct {
	Ed25519Verifier
	Key ed25519.PrivateKey
}

func (s Ed25519SignerVerifier) Sign(_ context.Context, payload []byte) (signature []byte, err error) {
	return s.Key.Sign(rand.Reader, payload, crypto.Hash(0))
}

func (v Ed25519Verifier) Verify(_ context.Context, payload, signature []byte) error {
	if !ed25519.Verify(v.Key, payload, signature) {
		return errors.New("unable to verify signature")
	}
	return nil
}

func (v Ed25519Verifier) PublicKey(_ context.Context) (crypto.PublicKey, error) {
	return v.Key, nil
}

var _ Verifier = Ed25519Verifier{}
var _ SignerVerifier = Ed25519SignerVerifier{}

func NewEd25519SignerVerifier(key ed25519.PrivateKey) Ed25519SignerVerifier {
	return Ed25519SignerVerifier{
		Ed25519Verifier: Ed25519Verifier{Key: key.Public().(ed25519.PublicKey)},
		Key:             key,
	}
}

func NewDefaultEd25519SignerVerifier() (Ed25519SignerVerifier, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Ed25519SignerVerifier{}, fmt.Errorf("could not generate ed25519 keypair: %v", err)
	}
	return NewEd25519SignerVerifier(priv), nil
}
