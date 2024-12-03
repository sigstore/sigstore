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

package akeyless

import (
	"context"
	"crypto"
	"fmt"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"io"
)

// SignerVerifier creates and verifies digital signatures over a message using Akeyless vaultless platform service
type SignerVerifier struct {
	client *akeylessClient
}

type cryptoSignerWrapper struct {
	ctx     context.Context
	sv      *SignerVerifier
	errFunc func(error)
}

func (c cryptoSignerWrapper) Public() crypto.PublicKey {
	pk, err := c.sv.PublicKey(options.WithContext(c.ctx))
	if err != nil && c.errFunc != nil {
		c.errFunc(err)
	}
	return pk
}

func (c cryptoSignerWrapper) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashFunc, _, err := c.sv.client.getDefaultAndSupportedHashFunctions(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get supported hash functions: %w", err)
	}

	if opts != nil {
		hashFunc = opts.HashFunc()
	}

	aklOptions := []signature.SignOption{
		options.WithContext(c.ctx),
		options.WithCryptoSignerOpts(hashFunc),
		options.WithDigest(digest),
	}

	return c.sv.SignMessage(nil, aklOptions...)
}

// LoadSignerVerifier generates signatures using the specified key object in Akeyless KMS and hash algorithm.
//
// It also can verify signatures locally using the public key. hashFunc must not be crypto.Hash(0).
func LoadSignerVerifier(referenceStr string, opts ...signature.RPCOption) (*SignerVerifier, error) {
	a := &SignerVerifier{}

	var err error
	a.client, err = newAkeylessClient(referenceStr)
	if err != nil {
		return nil, err
	}

	return a, nil
}

func (a *SignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	return a.client.createKey(ctx, keyAlg(algorithm))
}

// CryptoSigner returns a crypto.Signer object that uses the underlying SignerVerifier, along with a crypto.SignerOpts object
// that allows the KMS to be used in APIs that only accept the standard golang objects
func (a *SignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	hf, _, err := a.client.getDefaultAndSupportedHashFunctions(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get supported hash functions: %w", err)
	}

	return cryptoSignerWrapper{
		ctx:     ctx,
		sv:      a,
		errFunc: errFunc,
	}, hf, nil
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer. If the caller wishes to specify the context to use to obtain
// the public key, pass option.WithContext(desiredCtx).
//
// All other options are ignored if specified.
func (a *SignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}

	pub, err := a.client.public(ctx)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// SignMessage signs the provided message using Akeyless vaultless platform service.  Unless provided
// in an option, the digest of the message will be computed using a default hash matching the key type
//
// SignMessage recognizes the following Options listed in order of preference:
//
// - WithContext()
//
// - WithDigest()
//
// - WithCryptoSignerOpts()
//
// All other options are ignored if specified.
func (a *SignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	ctx := context.Background()
	dftHash, supportedHashFuncs, err := a.client.getDefaultAndSupportedHashFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get supported hash functions: %w", err)
	}
	var signerOpts crypto.SignerOpts = dftHash

	var digest []byte

	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	digest, hf, err := signature.ComputeDigestForSigning(message, signerOpts.HashFunc(), supportedHashFuncs, opts...)
	if err != nil {
		return nil, err
	}

	return a.client.sign(ctx, digest, hf, opts...)
}

// VerifySignature verifies the signature for the given message. Unless provided
// in an option, the digest of the message will be computed using a default hash matching the key type
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// VerifySignature recognizes the following Options listed in order of preference:
//
// - WithDigest()
//
// - WithCryptoSignerOpts()
//
// All other options are ignored if specified.
func (a *SignerVerifier) VerifySignature(sig, message io.Reader, opts ...signature.VerifyOption) error {
	ctx := context.Background()

	dftHash, supportedHashFuncs, err := a.client.getDefaultAndSupportedHashFunctions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get supported hash functions: %w", err)
	}
	var signerOpts crypto.SignerOpts = dftHash

	var digest []byte

	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	digest, hf, err := signature.ComputeDigestForVerifying(message, signerOpts.HashFunc(), supportedHashFuncs, opts...)
	if err != nil {
		return err
	}

	return a.client.verify(ctx, sigBytes, digest, hf, opts...)
}

// SupportedAlgorithms returns the list of algorithms supported by the Akeyless vaultless platform service
func (a *SignerVerifier) SupportedAlgorithms() []string {
	return supportedAlgorithms
}

// DefaultAlgorithm returns the default algorithm for the Akeyless vaultless platform service
func (a *SignerVerifier) DefaultAlgorithm() string {
	return string(keyAlgRsa4096)
}
