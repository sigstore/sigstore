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
	"fmt"
	"io"
)

var ecdsaSupportedHashAlgs = []crypto.Hash{
	crypto.SHA256,
	crypto.SHA512,
	crypto.SHA384,
	crypto.SHA224,
	crypto.SHA1,
}

type ECDSAVerifier struct {
	Key     *ecdsa.PublicKey
	HashAlg crypto.Hash
}

type ECDSASignerVerifier struct {
	ECDSAVerifier
	Key *ecdsa.PrivateKey
}

func (s ECDSASignerVerifier) Sign(rawMessage io.Reader, opts ...SignOption) (signature []byte, err error) {
	digest, _, err := MessageToSign(rawMessage, s.HashAlg, ecdsaSupportedHashAlgs, opts...)
	if err != nil {
		return nil, err
	}
	randReader := GetRand(rand.Reader, opts...)
	signature, err = ecdsa.SignASN1(randReader, s.Key, digest)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (v ECDSAVerifier) Verify(rawMessage io.Reader, signature []byte, opts ...VerifyOption) error {
	digest, _, err := MessageToVerify(rawMessage, v.HashAlg, ecdsaSupportedHashAlgs, opts...)
	if err != nil {
		return err
	}

	if !ecdsa.VerifyASN1(v.Key, digest, signature) {
		return errors.New("unable to verify signature")
	}
	return nil
}

func (v ECDSAVerifier) PublicKey(...PublicKeyOption) (crypto.PublicKey, error) {
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
