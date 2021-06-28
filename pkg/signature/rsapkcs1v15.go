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
	"io"

	"github.com/pkg/errors"
)

type RSAPKCS1v15Signer struct {
	hashFunc crypto.Hash
	priv     *rsa.PrivateKey
}

// LoadRSAPKCS1v15Signer calculates signatures using the specified private key and hash algorithm.
//
// hf must not be crypto.Hash(0).
func LoadRSAPKCS1v15Signer(priv *rsa.PrivateKey, hf crypto.Hash) (*RSAPKCS1v15Signer, error) {
	if priv == nil {
		return nil, errors.New("invalid RSA private key specified")
	}

	if hf == crypto.Hash(0) {
		return nil, errors.New("invalid hash function specified")
	}

	return &RSAPKCS1v15Signer{
		priv:     priv,
		hashFunc: hf,
	}, nil
}

// SignMessage signs the provided message using PKCS1v15. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the RSAPKCS1v15Signer was created.
//
// SignMessage recognizes the following Options listed in order of preference:
//
// - WithRand()
//
// - WithDigest()
//
// All other options are ignored if specified.
func (r RSAPKCS1v15Signer) SignMessage(message []byte, opts ...SignerOption) ([]byte, error) {
	req := &SignRequest{
		Message:  message,
		Rand:     rand.Reader,
		HashFunc: r.hashFunc,
	}

	for _, opt := range opts {
		opt.ApplySigner(req)
	}

	if err := r.validate(req); err != nil {
		return nil, err
	}

	return r.computeSignature(req)
}

// validate ensures that the provided signRequest can be successfully processed
// given internal fields as well as request-specific parameters (which take precedence).
func (r RSAPKCS1v15Signer) validate(req *SignRequest) error {
	// r.priv must be set
	if r.priv == nil {
		return errors.New("private key is not initialized")
	}

	// req.hashFunc must not be crypto.Hash(0)
	if req.HashFunc == crypto.Hash(0) {
		return errors.New("invalid hash function specified")
	}

	if req.Message == nil && req.Digest == nil {
		return errors.New("digest or message is required to generate RSA signature")
	}

	if req.Rand == nil {
		return errors.New("rand cannot be nil")
	}

	return nil
}

// computeSignature computes the signature for the specified signing request
func (r RSAPKCS1v15Signer) computeSignature(req *SignRequest) ([]byte, error) {
	hf := req.HashFunc
	if hf == crypto.Hash(0) {
		hf = r.hashFunc
	}

	digest := req.Digest
	if digest == nil {
		hasher := hf.New()
		if _, err := hasher.Write(req.Message); err != nil {
			return nil, errors.Wrap(err, "hashing during RSA signature")
		}
		digest = hasher.Sum(nil)
	} else if hf.Size() != len(digest) {
		return nil, errors.New("unexpected length of digest for hash functions specified")
	}

	return rsa.SignPKCS1v15(req.Rand, r.priv, hf, digest)
}

// Public returns the public key that can be used to verify signatures created by
// this signer.
func (r RSAPKCS1v15Signer) Public() crypto.PublicKey {
	if r.priv == nil {
		return nil
	}

	return r.priv.Public()
}

// PublicWithContext returns the public key that can be used to verify signatures created by
// this signer. As this value is held in memory, the context argument to this method is ignored.
func (r RSAPKCS1v15Signer) PublicWithContext(_ context.Context) (crypto.PublicKey, error) {
	return r.Public(), nil
}

// Sign computes the signature for the specified digest using PKCS1v15.
//
// If a source of entropy is given in rand, it will be used instead of the default value (rand.Reader
// from crypto/rand).
//
// If opts are specified, they should specify the hash function used to compute digest. If opts are
// not specified, this function assumes the hash function provided when the signer was created was
// used to create the value specified in digest.
func (r RSAPKCS1v15Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	rsaOpts := []SignerOption{}
	if rand != nil {
		rsaOpts = append(rsaOpts, WithRand(rand))
	}
	if opts != nil {
		rsaOpts = append(rsaOpts, WithDigest(digest, opts.HashFunc()))
	} else {
		rsaOpts = append(rsaOpts, WithDigest(digest, r.hashFunc))
	}
	return r.SignMessage(nil, rsaOpts...)
}

type RSAPKCS1v15Verifier struct {
	publicKey *rsa.PublicKey
	hashFunc  crypto.Hash
}

// LoadRSAPKCS1v15Verifier returns a Verifier that verifies signatures using the specified
// RSA public key and hash algorithm.
//
// hf must not be crypto.Hash(0).
func LoadRSAPKCS1v15Verifier(pub *rsa.PublicKey, hashFunc crypto.Hash) (*RSAPKCS1v15Verifier, error) {
	if pub == nil {
		return nil, errors.New("invalid RSA public key specified")
	}

	if hashFunc == crypto.Hash(0) {
		return nil, errors.New("invalid hash function specified")
	}

	return &RSAPKCS1v15Verifier{
		publicKey: pub,
		hashFunc:  hashFunc,
	}, nil
}

// VerifySignature verifies the signature for the given message using PKCS1v15. Unless provided
// in an option, the digest of the message will be computed using the hash function specified
// when the RSAPKCS1v15Verifier was created.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// This function recognizes the following Options listed in order of preference:
//
// - WithDigest()
//
// All other options are ignored if specified.
func (r RSAPKCS1v15Verifier) VerifySignature(signature []byte, message []byte, opts ...VerifierOption) error {
	req := &VerifyRequest{
		Signature: signature,
		Message:   message,
		HashFunc:  r.hashFunc,
	}

	for _, opt := range opts {
		opt.ApplyVerifier(req)
	}

	if err := r.validate(req); err != nil {
		return err
	}

	return r.verify(req)
}

// validate ensures that the provided verifyRequest can be successfully processed
// given internal fields as well as request-specific parameters (which take precedence).
func (r RSAPKCS1v15Verifier) validate(req *VerifyRequest) error {
	if req == nil {
		return errors.New("verifyRequest is nil")
	}
	// r.PublicKey must be set
	if r.publicKey == nil {
		return errors.New("public key is not initialized")
	}

	if req.HashFunc == crypto.Hash(0) {
		return errors.New("hash function is required to verify RSA signature")
	}

	if req.Digest == nil && req.Message == nil {
		return errors.New("digest or message is required to verify RSA signature")
	}

	return nil
}

// verify verifies the signature for the specified verify request
func (r RSAPKCS1v15Verifier) verify(req *VerifyRequest) error {
	if req == nil {
		return errors.New("verifyRequest is nil")
	}

	hf := req.HashFunc
	if hf == crypto.Hash(0) {
		hf = r.hashFunc
	}

	digest := req.Digest
	if digest == nil {
		hasher := hf.New()
		if _, err := hasher.Write(req.Message); err != nil {
			return errors.Wrap(err, "hashing during RSA verification")
		}
		digest = hasher.Sum(nil)
	} else if hf.Size() != len(digest) {
		return errors.New("unexpected length of digest for hash function specified")
	}

	return rsa.VerifyPKCS1v15(r.publicKey, hf, digest, req.Signature)
}

type RSAPKCS1v15SignerVerifier struct {
	*RSAPKCS1v15Signer
	*RSAPKCS1v15Verifier
}

// LoadRSAPKCS1v15SignerVerifier creates a combined signer and verifier. This is a convenience object
// that simply wraps an instance of RSAPKCS1v15Signer and RSAPKCS1v15Verifier.
func LoadRSAPKCS1v15SignerVerifier(priv *rsa.PrivateKey, hf crypto.Hash) (*RSAPKCS1v15SignerVerifier, error) {
	signer, err := LoadRSAPKCS1v15Signer(priv, hf)
	if err != nil {
		return nil, errors.Wrap(err, "initializing signer")
	}
	verifier, err := LoadRSAPKCS1v15Verifier(&priv.PublicKey, hf)
	if err != nil {
		return nil, errors.Wrap(err, "initializing verifier")
	}

	return &RSAPKCS1v15SignerVerifier{
		RSAPKCS1v15Signer:   signer,
		RSAPKCS1v15Verifier: verifier,
	}, nil
}

// NewDefaultRSAPKCS1v15SignerVerifier creates a combined signer and verifier using RSA PKCS1v15.
// This creates a new RSA key of 2048 bits and uses the SHA256 hashing algorithm.
func NewDefaultRSAPKCS1v15SignerVerifier() (*RSAPKCS1v15SignerVerifier, *rsa.PrivateKey, error) {
	return NewRSAPKCS1v15SignerVerifier(rand.Reader, 2048, crypto.SHA256)
}

// NewRSAPKCS1v15SignerVerifier creates a combined signer and verifier using RSA PKCS1v15.
// This creates a new RSA key of the specified length of bits, entropy source, and hash function.
func NewRSAPKCS1v15SignerVerifier(rand io.Reader, bits int, hashFunc crypto.Hash) (*RSAPKCS1v15SignerVerifier, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand, bits)
	if err != nil {
		return nil, nil, err
	}

	sv, err := LoadRSAPKCS1v15SignerVerifier(priv, hashFunc)
	if err != nil {
		return nil, nil, err
	}

	return sv, priv, nil
}
