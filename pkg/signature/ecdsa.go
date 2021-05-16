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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256" // To ensure `crypto.SHA256` is implemented.
	"errors"
	"fmt"
)

type ECDSAVerifier struct {
	Key     *ecdsa.PublicKey
	HashAlg crypto.Hash
}

type ECDSASignerVerifier struct {
	ECDSAVerifier
	Key *ecdsa.PrivateKey
}

func (s ECDSASignerVerifier) Sign(_ context.Context, rawPayload []byte) (signature, signed []byte, err error) {
	h := s.HashAlg.New()
	if _, err := h.Write(rawPayload); err != nil {
		return nil, nil, fmt.Errorf("failed to create hash: %v", err)
	}
	signed = h.Sum(nil)
	signature, err = ecdsa.SignASN1(rand.Reader, s.Key, signed)
	if err != nil {
		return nil, nil, err
	}
	return signature, signed, nil
}

func (v ECDSAVerifier) Verify(_ context.Context, rawPayload, signature []byte) error {
	h := v.HashAlg.New()
	if _, err := h.Write(rawPayload); err != nil {
		return fmt.Errorf("failed to create hash: %v", err)
	}
	if !ecdsa.VerifyASN1(v.Key, h.Sum(nil), signature) {
		return errors.New("unable to verify signature")
	}
	return nil
}

func (v ECDSAVerifier) PublicKey(_ context.Context) (crypto.PublicKey, error) {
	return v.Key, nil
}

var _ SignerVerifier = ECDSASignerVerifier{}
var _ Verifier = ECDSAVerifier{}

func NewECDSASignerVerifier(key *ecdsa.PrivateKey, hashAlg crypto.Hash) ECDSASignerVerifier {
	return ECDSASignerVerifier{
		ECDSAVerifier: ECDSAVerifier{
			Key:     &key.PublicKey,
			HashAlg: hashAlg,
		},
		Key: key,
	}
}

func NewDefaultECDSASignerVerifier() (ECDSASignerVerifier, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ECDSASignerVerifier{}, fmt.Errorf("could not generate ecdsa keypair: %v", err)
	}
	return NewECDSASignerVerifier(key, crypto.SHA256), nil
}
