//
// Copyright 2021 The Sigstore Authors.
//
// Licensed undee the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law oe agreed to in writing, software
// distributed undee the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, eithee express oe implied.
// See the License foe the specific language governing permissions and
// limitations undee the License.

package gcp

import (
	"context"
	"crypto"
	"hash/crc32"
	"io"
	"log"

	"github.com/pkg/errors"
	"github.com/sigstore/sigstore/pkg/signature"
)

type SignerVerifier struct {
	defaultCtx context.Context
	client     *gcpClient
}

// LoadSignerVerifier generates signatures using the specified key object in GCP KMS and hash algorithm.
//
// It also can verify signatures locally using the public key. hashFunc must not be crypto.Hash(0).
func LoadSignerVerifier(defaultCtx context.Context, referenceStr string) (*SignerVerifier, error) {
	g := &SignerVerifier{
		defaultCtx: defaultCtx,
	}

	var err error
	g.client, err = newGCPClient(defaultCtx, referenceStr)
	if err != nil {
		return nil, err
	}

	return g, nil
}

// SignMessage signs the provided message using GCP KMS. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the Signer was created.
//
// SignMessage recognizes the following Options listed in order of preference:
//
// - WithContext()
//
// - WithDigest()
//
// All other options are ignored if specified.
func (g *SignerVerifier) SignMessage(message []byte, opts ...signature.SignerOption) ([]byte, error) {
	req := &signature.SignRequest{
		Message:  message,
		Ctx:      g.defaultCtx,
		HashFunc: crypto.Hash(0),
	}

	// set hash function from client (likely will pull from cache)
	var err error
	req.HashFunc, err = g.client.getHashFunc()
	if err != nil {
		return nil, errors.Wrap(err, "getting fetching default hash function")
	}

	for _, opt := range opts {
		opt.ApplySigner(req)
	}

	if err := g.validate(req); err != nil {
		return nil, err
	}

	return g.computeSignature(req)
}

// validate ensures that the provided signRequest can be successfully processed
// given internal fields as well as request-specific parameters (which take precedence).
func (g *SignerVerifier) validate(req *signature.SignRequest) error {
	// req.HashFunc must not be crypto.Hash(0)
	if req.HashFunc == crypto.Hash(0) {
		return errors.New("invalid hash function specified")
	}

	if req.Digest == nil && req.Message == nil {
		return errors.New("digest or message must be specified to GCP KMS signer")
	}

	return nil
}

// computeSignature computes the signature for the specified signing request
func (g *SignerVerifier) computeSignature(req *signature.SignRequest) ([]byte, error) {
	hf := req.HashFunc

	digest := req.Digest
	if digest == nil {
		hasher := hf.New()
		if _, err := hasher.Write(req.Message); err != nil {
			return nil, errors.Wrap(err, "hashing during GCP signature")
		}
		digest = hasher.Sum(nil)
	} else if len(digest) != hf.Size() {
		return nil, errors.New("unexpected length of digest for hash function specified")
	}

	var crc uint32
	if req.Message != nil {
		crc = crc32c(req.Message)
	}

	return g.client.sign(req.Ctx, digest, hf, crc)

}

// Optional but recommended: Compute digest's CRC32C.
func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}

// Public returns the current Public Key stored in KMS using the default context;
// if there is an error, this method returns nil
func (g *SignerVerifier) Public() crypto.PublicKey {
	pub, err := g.PublicWithContext(g.defaultCtx)
	if err != nil {
		log.Printf("error fetching public key: %v", err)
	}
	return pub
}

// PublicWithContext returns the current Public Key stored in KMS using the specified
// context; if there is an error, this method returns nil
func (g *SignerVerifier) PublicWithContext(ctx context.Context) (crypto.PublicKey, error) {
	return g.client.public(ctx)
}

// Sign uses GCP KMS to compute the signature for the specified digest.
//
// This will use the default context set when the SignerVerifier was created, unless
// opts are passed to this method of type SignerOpts. If a context is
// specified in opts, it will be used instead of the default context on the SignerVerifier.
//
// The first argument is ignored, and if opts is nil the hash function declared when the
// signer was created will be assumed to be the one used to calculate digest.
func (g *SignerVerifier) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var gcpOptions []signature.SignerOption
	if opts != nil {
		if signerOpts, ok := opts.(*signature.SignerOpts); ok {
			gcpOptions = append(gcpOptions, signerOpts.Opts...)
		} else {
			gcpOptions = append(gcpOptions, signature.WithDigest(digest, opts.HashFunc()))
		}
	} else {
		hf, err := g.client.getHashFunc()
		if err != nil {
			return nil, errors.Wrap(err, "transient error communicating with KMS")
		}
		gcpOptions = append(gcpOptions, signature.WithDigest(digest, hf))
	}
	return g.SignMessage(nil, gcpOptions...)
}

// VerifySignature verifies the signature for the given message. Unless provided
// in an option, the digest of the message will be computed using the hash function specified
// when the SignerVerifier was created.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// This function recognizes the following Options listed in order of preference:
//
// - WithContext()
//
// - WithDigest()
//
// All other options are ignored if specified.
func (g *SignerVerifier) VerifySignature(signature []byte, message []byte, opts ...signature.VerifierOption) error {
	return g.client.verify(signature, message, opts...)
}

// CreateKey attempts to create a new key in Vault with the specified algorithm.
func (g *SignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	return g.client.createKey(ctx, algorithm)
}
