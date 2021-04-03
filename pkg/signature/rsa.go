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
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // To ensure `crypto.SHA256` is implemented.
	"fmt"
)

type RSAVerifier struct {
	Key     *rsa.PublicKey
	HashAlg crypto.Hash
}

type RSASignerVerifier struct {
	RSAVerifier
	Key *rsa.PrivateKey
}

func (s RSASignerVerifier) Sign(_ context.Context, payload []byte) (signature []byte, err error) {
	h := s.HashAlg.New()
	if _, err := h.Write(payload); err != nil {
		return nil, fmt.Errorf("failed to create hash: %v", err)
	}
	return rsa.SignPKCS1v15(rand.Reader, s.Key, s.HashAlg, h.Sum(nil))
}

func (v RSAVerifier) Verify(_ context.Context, payload, signature []byte) error {
	h := v.HashAlg.New()
	if _, err := h.Write(payload); err != nil {
		return fmt.Errorf("failed to create hash: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(v.Key, v.HashAlg, h.Sum(nil), signature); err != nil {
		return fmt.Errorf("unable to verify signature: %v", err)
	}
	return nil
}

func (v RSAVerifier) PublicKey(_ context.Context) (crypto.PublicKey, error) {
	return v.Key, nil
}

var _ SignerVerifier = RSASignerVerifier{}
var _ Verifier = RSAVerifier{}

func NewRSASignerVerifier(key *rsa.PrivateKey, hashAlg crypto.Hash) RSASignerVerifier {
	return RSASignerVerifier{
		RSAVerifier: RSAVerifier{
			Key:     &key.PublicKey,
			HashAlg: hashAlg,
		},
		Key: key,
	}
}

func NewDefaultRSASignerVerifier() (RSASignerVerifier, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return RSASignerVerifier{}, fmt.Errorf("could not generate RSA keypair: %v", err)
	}
	return NewRSASignerVerifier(key, crypto.SHA256), nil
}
