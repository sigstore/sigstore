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
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // To ensure `crypto.SHA256` is implemented.
	"io"

	"github.com/pkg/errors"
)

type RSASignerVerifier struct {
	BaseSignerVerifierType
	private *rsa.PrivateKey
}

func (r RSASignerVerifier) Hasher() func(crypto.SignerOpts, []byte) ([]byte, crypto.Hash, error) {
	return r.ComputeHash
}

func (r RSASignerVerifier) Public() crypto.PublicKey {
	return r.publicKey
}

func (r RSASignerVerifier) Sign(rand io.Reader, payload []byte, opts crypto.SignerOpts) ([]byte, error) {
	if r.private == nil {
		return nil, errors.New("RSA private key not initialized")
	}
	digest, hasher, err := r.ComputeHash(opts, payload)
	if err != nil {
		return nil, err
	}
	// PKCS #1 v1.5 has known vulnerabilities so we do not support it
	var pssOpts *rsa.PSSOptions
	if opts != nil {
		var ok bool
		if pssOpts, ok = opts.(*rsa.PSSOptions); !ok {
			return nil, errors.New("invalid signing options")
		}
	}
	return rsa.SignPSS(rand, r.private, hasher, digest, pssOpts)
}

func (r RSASignerVerifier) VerifySignature(payload, signature []byte) error {
	return r.VerifySignatureWithKey(r.publicKey, payload, signature)
}

func (r RSASignerVerifier) VerifySignatureWithKey(publicKey crypto.PublicKey, payload, signature []byte) error {
	pk := publicKey
	if pk == nil {
		pk = r.publicKey
		if pk == nil {
			return errors.New("public key has not been initialized")
		}
	}

	digest, _, err := r.ComputeHash(r.hashFunc, payload)
	if err != nil {
		return err
	}

	rsaPub, ok := pk.(*rsa.PublicKey)
	if !ok {
		return errors.New("invalid RSA public key")
	}

	return rsa.VerifyPSS(rsaPub, r.hashFunc, digest, signature, nil)
}

func NewRSASignerVerifier(private *rsa.PrivateKey, public *rsa.PublicKey, hashFunc crypto.Hash) RSASignerVerifier {
	return RSASignerVerifier{
		BaseSignerVerifierType: BaseSignerVerifierType{
			hashFunc:  hashFunc,
			publicKey: public,
		},
		private: private,
	}
}

func GenerateRSASignerVerifier(bits int, hashFunc crypto.Hash) (RSASignerVerifier, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return RSASignerVerifier{}, err
	}

	return NewRSASignerVerifier(key, &key.PublicKey, hashFunc), nil
}

func NewDefaultRSASignerVerifier() (RSASignerVerifier, error) {
	return GenerateRSASignerVerifier(2048, crypto.SHA256)
}
