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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256" // To ensure `crypto.SHA256` is implemented.
	"errors"
	"io"
)

type ECDSASignerVerifier struct {
	BaseSignerVeriiferType
	private *ecdsa.PrivateKey
}

func (e ECDSASignerVerifier) Public() crypto.PublicKey {
	return e.publicKey
}

func (e ECDSASignerVerifier) Sign(rand io.Reader, payload []byte, opts crypto.SignerOpts) ([]byte, error) {
	if e.private == nil {
		return nil, errors.New("ECDSA private key not initialized")
	}
	digest, _, err := e.ComputeHash(opts, payload)
	if err != nil {
		return nil, err
	}
	return ecdsa.SignASN1(rand, e.private, digest)
}

func (e ECDSASignerVerifier) VerifySignature(payload, signature []byte) error {
	return e.VerifySignatureWithKey(e.publicKey, payload, signature)
}

func (e ECDSASignerVerifier) VerifySignatureWithKey(publicKey crypto.PublicKey, payload, signature []byte) error {
	pk := publicKey
	if pk == nil {
		pk = e.publicKey
		if pk == nil {
			return errors.New("public key has not been initialized")
		}
	}

	digest, _, err := e.ComputeHash(e.hashFunc, payload)
	if err != nil {
		return err
	}

	ecPub, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("invalid ECDSA public key")
	}

	if !ecdsa.VerifyASN1(ecPub, digest, signature) {
		return errors.New("ECDSA signature failed to verify")
	}
	return nil
}

func NewECDSASignerVerifier(private *ecdsa.PrivateKey, public *ecdsa.PublicKey, hashFunc crypto.Hash) ECDSASignerVerifier {
	return ECDSASignerVerifier{
		BaseSignerVeriiferType: BaseSignerVeriiferType{
			hashFunc:  hashFunc,
			publicKey: public,
		},
		private: private,
	}
}

func GenerateECDSASignerVerifier(curve elliptic.Curve, hashFunc crypto.Hash) (ECDSASignerVerifier, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return ECDSASignerVerifier{}, err
	}

	return NewECDSASignerVerifier(key, &key.PublicKey, hashFunc), nil
}

func NewDefaultECDSASignerVerifier() (ECDSASignerVerifier, error) {
	return GenerateECDSASignerVerifier(elliptic.P256(), crypto.SHA256)
}
