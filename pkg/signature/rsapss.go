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
	"fmt"
	"io"

	"github.com/pkg/errors"
)

type RSAPSSSigner struct {
	hashFunc crypto.Hash
	priv     *rsa.PrivateKey
	pssOpts  *rsa.PSSOptions
}

// LoadRSAPSSSigner calculates signatures using the specified private key and hash algorithm.
//
// If opts are specified, then they will be stored and used as a default if not overridden
// by the value passed to Sign().
//
// hf must not be crypto.Hash(0).
func LoadRSAPSSSigner(priv *rsa.PrivateKey, hf crypto.Hash, opts *rsa.PSSOptions) (*RSAPSSSigner, error) {
	if priv == nil {
		return nil, errors.New("invalid RSA private key specified")
	}

	if hf == crypto.Hash(0) {
		return nil, errors.New("invalid hash function specified")
	}

	return &RSAPSSSigner{
		priv:     priv,
		pssOpts:  opts,
		hashFunc: hf,
	}, nil
}

// SignMessage signs the provided message using PSS. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the RSAPSSSigner was created.
//
// This function recognizes the following Options listed in order of preference:
//
// - WithRand()
//
// - WithDigest()
//
// All other options are ignored if specified.
func (r RSAPSSSigner) SignMessage(message []byte, opts ...SignerOption) ([]byte, error) {
	req := &SignRequest{
		Message:  message,
		Rand:     rand.Reader,
		HashFunc: r.hashFunc,
		PSSOpts:  r.pssOpts,
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
func (r RSAPSSSigner) validate(req *SignRequest) error {
	// r.priv must be set
	if r.priv == nil {
		return errors.New("private key is not initialized")
	}

	if req.Message == nil && req.Digest == nil {
		return errors.New("digest or message is required to generate RSA signature")
	}

	// req.HashFunc must not be crypto.Hash(0)
	if req.HashFunc == crypto.Hash(0) {
		return errors.New("invalid hash function specified")
	} else if req.PSSOpts != nil && req.PSSOpts.Hash == crypto.Hash(0) {
		return errors.New("invalid hash function specified in PSS options")
	}

	if req.Rand == nil {
		return errors.New("rand cannot be nil")
	}

	return nil
}

// computeSignature computes the signature for the specified signing request
func (r RSAPSSSigner) computeSignature(req *SignRequest) ([]byte, error) {
	hf := req.HashFunc
	if hf == crypto.Hash(0) {
		if req.PSSOpts != nil {
			hf = req.PSSOpts.Hash
		}
		if hf == crypto.Hash(0) {
			hf = r.hashFunc
		}
	}

	digest := req.Digest
	if digest == nil {
		hasher := hf.New()
		if _, err := hasher.Write(req.Message); err != nil {
			return nil, errors.Wrap(err, "hashing during RSA signature")
		}
		digest = hasher.Sum(nil)
	} else if hf.Size() != len(digest) {
		fmt.Printf("hf.Size() = %v, len(digest) = %v\n", hf.Size(), len(digest))
		return nil, errors.New("unexpected length of digest for hash functions specified")
	}

	return rsa.SignPSS(req.Rand, r.priv, hf, digest, req.PSSOpts)
}

// Public returns the public key that can be used to verify signatures created by
// this signer.
func (r RSAPSSSigner) Public() crypto.PublicKey {
	if r.priv == nil {
		return nil
	}

	return r.priv.Public()
}

// PublicWithContext returns the public key that can be used to verify signatures created by
// this signer. As this value is held in memory, the context argument to this method is ignored.
func (r RSAPSSSigner) PublicWithContext(_ context.Context) (crypto.PublicKey, error) {
	return r.Public(), nil
}

// Sign computes the signature for the specified digest using PSS.
//
// If a source of entropy is given in rand, it will be used instead of the default value (rand.Reader
// from crypto/rand).
//
// If opts are specified, they must be *rsa.PSSOptions. If opts are not specified, the value
// provided when the signer was created will be used instead.
func (r RSAPSSSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	rsaOpts := []SignerOption{}
	if rand != nil {
		rsaOpts = append(rsaOpts, WithRand(rand))
	}
	if opts != nil {
		if optsArg, ok := opts.(*rsa.PSSOptions); ok {
			rsaOpts = append(rsaOpts, WithDigest(digest, optsArg.Hash), withPSSOptions(optsArg))
		} else {
			return nil, errors.New("opts must be nil or of type *rsa.PSSOptions")
		}
	} else {
		rsaOpts = append(rsaOpts, WithDigest(digest, r.hashFunc))
	}
	return r.SignMessage(nil, rsaOpts...)
}

type RSAPSSVerifier struct {
	publicKey *rsa.PublicKey
	hashFunc  crypto.Hash
	pssOpts   *rsa.PSSOptions
}

// LoadRSAPSSVerifier verifies signatures using the specified public key and hash algorithm.
//
// hf must not be crypto.Hash(0). opts.Hash is ignored.
func LoadRSAPSSVerifier(pub *rsa.PublicKey, hashFunc crypto.Hash, opts *rsa.PSSOptions) (*RSAPSSVerifier, error) {
	if pub == nil {
		return nil, errors.New("invalid RSA public key specified")
	}

	if hashFunc == crypto.Hash(0) {
		return nil, errors.New("invalid hash function specified")
	}

	return &RSAPSSVerifier{
		publicKey: pub,
		hashFunc:  hashFunc,
		pssOpts:   opts,
	}, nil
}

// VerifySignature verifies the signature for the given message using PSS. Unless provided
// in an option, the digest of the message will be computed using the hash function specified
// when the RSAPSSVerifier was created.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// This function recognizes the following Options listed in order of preference:
//
// - WithDigest()
//
// All other options are ignored if specified.
func (r RSAPSSVerifier) VerifySignature(signature []byte, message []byte, opts ...VerifierOption) error {
	req := &VerifyRequest{
		Signature: signature,
		Message:   message,
		HashFunc:  r.hashFunc,
		PSSOpts:   r.pssOpts,
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
func (r RSAPSSVerifier) validate(req *VerifyRequest) error {
	// r.PublicKey must be set
	if r.publicKey == nil {
		return errors.New("public key is not initialized")
	}

	if req.Message == nil && req.Digest == nil {
		return errors.New("digest or message is required to verify RSA signature")
	}

	// pssOpts.Hash is ignored by VerifyPSS so we don't check it here
	if req.HashFunc == crypto.Hash(0) {
		return errors.New("hash function is required to verify RSA signature")
	}

	return nil
}

// verify verifies the signature for the specified verify request
func (r RSAPSSVerifier) verify(req *VerifyRequest) error {
	if req == nil {
		return errors.New("verifyRequest is nil")
	}

	// we do not use req.pssOpts.Hash since it is ignored in VerifyPSS
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
		fmt.Printf("hf.Size() = %v, len(digest) = %v\n", hf.Size(), len(digest))
		return errors.New("unexpected length of digest for hash function specified")
	}

	return rsa.VerifyPSS(r.publicKey, hf, digest, req.Signature, req.PSSOpts)
}

type RSAPSSSignerVerifier struct {
	*RSAPSSSigner
	*RSAPSSVerifier
}

// LoadRSAPSSSignerVerifier creates a combined signer and verifier using RSA PSS. This is
// a convenience object that simply wraps an instance of RSAPSSSigner and RSAPSSVerifier.
func LoadRSAPSSSignerVerifier(priv *rsa.PrivateKey, hf crypto.Hash, opts *rsa.PSSOptions) (*RSAPSSSignerVerifier, error) {
	signer, err := LoadRSAPSSSigner(priv, hf, opts)
	if err != nil {
		return nil, errors.Wrap(err, "initializing signer")
	}
	verifier, err := LoadRSAPSSVerifier(&priv.PublicKey, hf, opts)
	if err != nil {
		return nil, errors.Wrap(err, "initializing verifier")
	}

	return &RSAPSSSignerVerifier{
		RSAPSSSigner:   signer,
		RSAPSSVerifier: verifier,
	}, nil
}

// NewDefaultRSAPSSSignerVerifier creates a combined signer and verifier using RSA PSS.
// This creates a new RSA key of 2048 bits and uses the SHA256 hashing algorithm.
func NewDefaultRSAPSSSignerVerifier() (*RSAPSSSignerVerifier, *rsa.PrivateKey, error) {
	return NewRSAPSSSignerVerifier(rand.Reader, 2048, crypto.SHA256)
}

// NewRSAPSSSignerVerifier creates a combined signer and verifier using RSA PSS.
// This creates a new RSA key of the specified length of bits, entropy source, and hash function.
func NewRSAPSSSignerVerifier(rand io.Reader, bits int, hashFunc crypto.Hash) (*RSAPSSSignerVerifier, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand, bits)
	if err != nil {
		return nil, nil, err
	}

	sv, err := LoadRSAPSSSignerVerifier(priv, hashFunc, &rsa.PSSOptions{Hash: hashFunc})
	if err != nil {
		return nil, nil, err
	}

	return sv, priv, nil
}
