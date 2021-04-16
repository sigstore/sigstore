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
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // To ensure `crypto.SHA256` is implemented.
	"fmt"
)

type RSAVerifier struct {
	Key  *rsa.PublicKey
	opts rsa.PSSOptions
}

type RSASignerVerifier struct {
	RSAVerifier
	Key *rsa.PrivateKey
}

func (s RSASignerVerifier) Sign(_ context.Context, rawPayload []byte) (signature, signed []byte, err error) {
	h := s.opts.Hash.New()
	if _, err := h.Write(rawPayload); err != nil {
		return nil, nil, fmt.Errorf("failed to create hash: %v", err)
	}
	signed = h.Sum(nil)
	signature, err = rsa.SignPSS(rand.Reader, s.Key, s.opts.Hash, signed, &s.opts)
	if err != nil {
		return nil, nil, err
	}
	return signature, signed, nil
}

func (v RSAVerifier) Verify(_ context.Context, rawPayload, signature []byte) error {
	h := v.opts.Hash.New()
	if _, err := h.Write(rawPayload); err != nil {
		return fmt.Errorf("failed to create hash: %v", err)
	}
	if err := rsa.VerifyPSS(v.Key, v.opts.Hash, h.Sum(nil), signature, &v.opts); err != nil {
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
			Key: &key.PublicKey,
			opts: rsa.PSSOptions{
				SaltLength: hashAlg.Size(),
				Hash:       hashAlg,
			},
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
