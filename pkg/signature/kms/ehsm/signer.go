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

package ehsm

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// nolint:revive
const (
	EH_RSA_4096 = "EH_RSA_4096"
	EH_RSA_3072 = "EH_RSA_3072"
	EH_RSA_2048 = "EH_RSA_2048"
	EH_EC_P256  = "EH_EC_P256"
	EH_EC_P256K = "EH_EC_P256K"
	EH_EC_P224  = "EH_EC_P224"
	EH_EC_P384  = "EH_EC_P384"
	EH_EC_P521  = "EH_EC_P521"
)

var ehsmSupportedAlgorithms = []string{
	EH_RSA_4096,
	EH_RSA_3072,
	EH_RSA_2048,
	EH_EC_P256,
	EH_EC_P256K,
	EH_EC_P224,
	EH_EC_P384,
	EH_EC_P521,
}

var ehsmSupportedHashFuncs = []crypto.Hash{
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
	crypto.Hash(0),
}

// SignerVerifier creates and verifies digital signatures over a message using EHSM KMS service
type SignerVerifier struct {
	hashFunc crypto.Hash
	client   *ehsmClient
}

// LoadSignerVerifier generates signatures using the specified key object in Ehsm and hash algorithm.
//
// It also can verify signatures (via a remote vall to the Ehsm instance). hashFunc should be
// set to crypto.Hash(0) if the key referred to by referenceStr is an ED25519 signing key.
func LoadSignerVerifier(referenceStr string, hashFunc crypto.Hash, opts ...signature.RPCOption) (*SignerVerifier, error) {
	e := &SignerVerifier{}
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	var err error
	e.client, err = newEhsmClient(referenceStr)
	if err != nil {
		return nil, err
	}

	switch hashFunc {
	case 0, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		e.hashFunc = hashFunc
	default:
		return nil, errors.New("hash function not supported by Ehsm")
	}

	return e, nil
}

// SignMessage signs the provided message using Ehsm KMS. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the HashiehsmSigner was created.
//
// SignMessage recognizes the following Options listed in order of preference:
//
// - WithDigest()
//
// All other options are ignored if specified.
func (e SignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	var digest []byte
	var signerOpts crypto.SignerOpts = e.hashFunc

	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	digest, hf, err := signature.ComputeDigestForSigning(message, signerOpts.HashFunc(), ehsmSupportedHashFuncs, opts...)
	if err != nil {
		return nil, err
	}

	return e.client.sign(digest, hf, opts...)
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer. All options provided in arguments to this method are ignored.
func (e SignerVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return e.client.public()
}

// VerifySignature verifies the signature for the given message. Unless provided
// in an option, the digest of the message will be computed using the hash function specified
// when the SignerVerifier was created.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// This function recognizes the following Options listed in order of preference:
//
// - WithDigest()
//
// - WithCryptoSignerOpts()
//
// All other options are ignored if specified.
func (e SignerVerifier) VerifySignature(sig, message io.Reader, opts ...signature.VerifyOption) error {
	var digest []byte
	var signerOpts crypto.SignerOpts = e.hashFunc

	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	digest, hf, err := signature.ComputeDigestForVerifying(message, signerOpts.HashFunc(), ehsmSupportedHashFuncs, opts...)
	if err != nil {
		return err
	}

	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}

	return e.client.verify(sigBytes, digest, hf, opts...)
}

// CreateKey attempts to create a new key in ehsm with the specified algorithm.
func (e SignerVerifier) CreateKey(_ context.Context, algorithm string) (crypto.PublicKey, error) {
	return e.client.createKey(algorithm)
}

type cryptoSignerWrapper struct {
	ctx      context.Context
	hashFunc crypto.Hash
	sv       *SignerVerifier
	errFunc  func(error)
}

func (c cryptoSignerWrapper) Public() crypto.PublicKey {
	pk, err := c.sv.PublicKey(options.WithContext(c.ctx))
	if err != nil && c.errFunc != nil {
		c.errFunc(err)
	}
	return pk
}

func (c cryptoSignerWrapper) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashFunc := c.hashFunc
	if opts != nil {
		hashFunc = opts.HashFunc()
	}
	hvOptions := []signature.SignOption{
		options.WithContext(c.ctx),
		options.WithDigest(digest),
		options.WithCryptoSignerOpts(hashFunc),
	}

	return c.sv.SignMessage(nil, hvOptions...)
}

// CryptoSigner returns a crypto.Signer object that uses the underlying SignerVerifier, along with a crypto.SignerOpts object
// that allows the KMS to be used in APIs that only accept the standard golang objects
func (e *SignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	csw := &cryptoSignerWrapper{
		ctx:      ctx,
		sv:       e,
		hashFunc: e.hashFunc,
		errFunc:  errFunc,
	}

	return csw, e.hashFunc, nil
}

// SupportedAlgorithms returns the list of algorithms supported by the EHSM service
func (*SignerVerifier) SupportedAlgorithms() []string {
	return ehsmSupportedAlgorithms
}

// DefaultAlgorithm returns the default algorithm for the EHSM service
func (*SignerVerifier) DefaultAlgorithm() string {
	return EH_EC_P256
}
