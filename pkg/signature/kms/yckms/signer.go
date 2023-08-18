//
// Copyright 2023 The Sigstore Authors.
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

package yckms

import (
	"context"
	"crypto"
	"fmt"
	"io"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

var ycSupportedHashFuncs = []crypto.Hash{
	crypto.SHA256,
	crypto.SHA512,
	crypto.SHA384,
}

// SignerVerifier is a signature.SignerVerifier that uses the AWS Key Management Service
type SignerVerifier struct {
	client *ycKmsClient
}

// LoadSignerVerifier generates signatures using the specified key object in AWS KMS and hash algorithm.
//
// It also can verify signatures locally using the public key. hashFunc must not be crypto.Hash(0).
func LoadSignerVerifier(ctx context.Context, referenceStr string) (*SignerVerifier, error) {
	y := &SignerVerifier{}

	var err error
	y.client, err = newYcKmsClient(ctx, referenceStr)
	if err != nil {
		return nil, err
	}

	return y, nil
}

// SignMessage signs the provided message using YC KMS. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the Signer was created.
func (y *SignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	var digest []byte
	var err error
	var signerOpts crypto.SignerOpts
	ctx := context.Background()
	signerOpts, err = y.client.getHashFunc(ctx)

	if err != nil {
		return nil, fmt.Errorf("getting fetching default hash function: %w", err)
	}

	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	hf := signerOpts.HashFunc()

	if len(digest) == 0 {
		digest, hf, err = signature.ComputeDigestForSigning(message, hf, ycSupportedHashFuncs, opts...)
		if err != nil {
			return nil, err
		}
	}

	return y.client.sign(ctx, digest, hf)
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer. If the caller wishes to specify the context to use to obtain
// the public key, pass option.WithContext(desiredCtx).
//
// All other options are ignored if specified.
func (y *SignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}

	sk, err := y.client.getSK(ctx)
	if err != nil {
		return nil, err
	}
	return sk.Verifier.PublicKey(opts...)
}

// VerifySignature verifies the signature for the given message. Unless provided
// in an option, the digest of the message will be computed using the hash function specified
// when the SignerVerifier was created.
func (y *SignerVerifier) VerifySignature(sig, message io.Reader, opts ...signature.VerifyOption) (err error) {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	return y.client.verify(ctx, sig, message, opts...)
}

// CreateKey attempts to create a new key in Vault with the specified algorithm.
func (y *SignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	return y.client.createKey(ctx, algorithm)
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
	awsOptions := []signature.SignOption{
		options.WithContext(c.ctx),
		options.WithDigest(digest),
		options.WithCryptoSignerOpts(hashFunc),
	}

	return c.sv.SignMessage(nil, awsOptions...)
}

// CryptoSigner returns a crypto.Signer object that uses the underlying SignerVerifier, along with a crypto.SignerOpts object
// that allows the KMS to be used in APIs that only accept the standard golang objects
func (y *SignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	defaultHf, err := y.client.getHashFunc(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting fetching default hash function: %w", err)
	}

	csw := &cryptoSignerWrapper{
		ctx:      ctx,
		sv:       y,
		hashFunc: defaultHf,
		errFunc:  errFunc,
	}

	return csw, defaultHf, nil
}

// SupportedAlgorithms returns the list of algorithms supported by YC AWS KMS service
func (*SignerVerifier) SupportedAlgorithms() (result []string) {
	for k := range algorithmMap {
		result = append(result, k)
	}
	return
}

// DefaultAlgorithm returns the default algorithm for the YC KMS service
func (*SignerVerifier) DefaultAlgorithm() string {
	return Algorithm_ECDSA_NIST_P256_SHA_256
}
