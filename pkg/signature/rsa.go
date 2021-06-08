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
	"io"
)

var rsaSupportedHashAlgs = []crypto.Hash{
	crypto.SHA256,
	crypto.SHA512,
	crypto.SHA224,
	crypto.SHA384,
	crypto.SHA1,
}

type RSAVerifier struct {
	Key            *rsa.PublicKey
	defaultHashAlg crypto.Hash
}

type RSASignerVerifier struct {
	RSAVerifier
	Key *rsa.PrivateKey
}

func (s RSASignerVerifier) CryptoSigner(_ context.Context) (crypto.Signer, error) {
	return s.Key, nil
}

func (s RSASignerVerifier) Sign(rawMessage io.Reader, opts ...SignOption) (signature []byte, err error) {
	digest, hashAlg, err := MessageToSign(rawMessage, s.defaultHashAlg, rsaSupportedHashAlgs, opts...)
	if err != nil {
		return nil, err
	}
	pssOpts := rsa.PSSOptions{
		SaltLength: hashAlg.Size(),
		Hash:       hashAlg,
	}
	return rsa.SignPSS(rand.Reader, s.Key, hashAlg, digest, &pssOpts)
}

func (v RSAVerifier) Verify(rawMessage io.Reader, signature []byte, opts ...VerifyOption) error {
	digest, hashAlg, err := MessageToVerify(rawMessage, v.defaultHashAlg, rsaSupportedHashAlgs, opts...)
	if err != nil {
		return err
	}
	pssOpts := rsa.PSSOptions{
		SaltLength: hashAlg.Size(),
		Hash:       hashAlg,
	}
	if err := rsa.VerifyPSS(v.Key, hashAlg, digest, signature, &pssOpts); err != nil {
		return fmt.Errorf("unable to verify signature: %v", err)
	}
	return nil
}

func (v RSAVerifier) PublicKey(...PublicKeyOption) (crypto.PublicKey, error) {
	return v.Key, nil
}

var _ SignerVerifier = RSASignerVerifier{}
var _ Verifier = RSAVerifier{}

func NewRSASignerVerifier(key *rsa.PrivateKey, defaultHashAlg crypto.Hash) RSASignerVerifier {
	return RSASignerVerifier{
		RSAVerifier: RSAVerifier{
			Key:            &key.PublicKey,
			defaultHashAlg: defaultHashAlg,
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
