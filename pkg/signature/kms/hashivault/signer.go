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

package hashivault

import (
	"context"
	"crypto"
	"io"
	"log"

	"github.com/pkg/errors"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Taken from https://www.vaultproject.io/api/secret/transit
//nolint:golint
const (
	Algorithm_ECDSA_P256 = "ecdsa-p256"
	Algorithm_ECDSA_P384 = "ecdsa-p384"
	Algorithm_ECDSA_P521 = "ecdsa-p521"
	Algorithm_ED25519    = "ed25519"
	Algorithm_RSA_2048   = "rsa-2048"
	Algorithm_RSA_3072   = "rsa-3072"
	Algorithm_RSA_4096   = "rsa-4096"
)

type SignerVerifier struct {
	hashFunc crypto.Hash
	client   *hashivaultClient
}

// LoadSignerVerifier generates signatures using the specified key object in Vault and hash algorithm.
//
// It also can verify signatures (via a remote vall to the Vault instance). hashFunc should be
// set to crypto.Hash(0) if the key referred to by referenceStr is an ED25519 signing key.
func LoadSignerVerifier(referenceStr string, hashFunc crypto.Hash) (*SignerVerifier, error) {
	h := &SignerVerifier{}

	var err error
	h.client, err = newHashivaultClient(referenceStr)
	if err != nil {
		return nil, err
	}

	switch hashFunc {
	case 0, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		h.hashFunc = hashFunc
	default:
		return nil, errors.New("hash function not supported by Hashivault")
	}

	return h, nil
}

// SignMessage signs the provided message using Hashivault KMS. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the HashivaultSigner was created.
//
// SignMessage recognizes the following Options listed in order of preference:
//
// - WithDigest()
//
// All other options are ignored if specified.
func (h SignerVerifier) SignMessage(message []byte, opts ...signature.SignerOption) ([]byte, error) {
	req := &signature.SignRequest{
		Message:  message,
		HashFunc: h.hashFunc,
	}

	for _, opt := range opts {
		opt.ApplySigner(req)
	}

	if err := h.validate(req); err != nil {
		return nil, err
	}

	return h.computeSignature(req)
}

// validate ensures that the provided signRequest can be successfully processed
// given internal fields as well as request-specific parameters (which take precedence).
func (h SignerVerifier) validate(req *signature.SignRequest) error {
	if req.Digest == nil && req.Message == nil {
		return errors.New("digest or message must be specified to Hashivault KMS signer")
	}

	// crypto.Hash(0) is allowed because we may be signing with ED25519 which
	// requires the actual message

	return nil
}

// computeSignature computes the signature for the specified signing request
func (h SignerVerifier) computeSignature(req *signature.SignRequest) ([]byte, error) {
	hf := req.HashFunc
	if hf == crypto.Hash(0) {
		hf = h.hashFunc
	}

	digest := req.Digest
	if digest == nil {
		if hf == crypto.Hash(0) {
			digest = req.Message
		} else {
			hasher := hf.New()
			if _, err := hasher.Write(req.Message); err != nil {
				return nil, errors.Wrap(err, "hashing during Hashivault signature")
			}
			digest = hasher.Sum(nil)
		}
	} else if len(digest) != hf.Size() {
		return nil, errors.New("unexpected length of digest for hash function specified")
	}

	return h.client.sign(digest, hf)

}

// Sign uses Hashivault KMS to compute the signature for the specified digest.
//
// This will use the default context set when the SignerVerifier was created, unless
// opts are passed to this method of type SignerOpts. If a context is
// specified in opts, it will be used instead of the default context on the SignerVerifier.
//
// The first argument is ignored, and if opts is nil the hash function declared when the
// signer was created will be assumed to be the one used to calculate digest.
func (h SignerVerifier) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var hvOptions []signature.SignerOption
	if opts != nil {
		if signerOpts, ok := opts.(*signature.SignerOpts); ok {
			hvOptions = append(hvOptions, signerOpts.Opts...)
		}
		hvOptions = append(hvOptions, signature.WithDigest(digest, opts.HashFunc()))
	} else {
		hvOptions = append(hvOptions, signature.WithDigest(digest, h.hashFunc))
	}
	return h.SignMessage(nil, hvOptions...)
}

// Public returns the current Public Key stored in KMS using the default context;
// if there is an error, this method returns nil
func (h SignerVerifier) Public() crypto.PublicKey {
	pubKey, err := h.client.public()
	if err != nil {
		log.Println(err)
		return nil
	}
	return pubKey
}

// PublicWithContext returns the current Public Key stored in KMS.
//
// The context argument is ignored.
func (h SignerVerifier) PublicWithContext(_ context.Context) (crypto.PublicKey, error) {
	return h.client.public()
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
// All other options are ignored if specified.
func (h SignerVerifier) VerifySignature(sig []byte, message []byte, opts ...signature.VerifierOption) error {
	req := &signature.VerifyRequest{
		Signature: sig,
		Message:   message,
		HashFunc:  h.hashFunc,
	}

	for _, opt := range opts {
		opt.ApplyVerifier(req)
	}

	if err := h.validateVerify(req); err != nil {
		return err
	}

	return h.verify(req)
}

// validateVerify ensures that the provided verifyRequest can be successfully processed
// given internal fields as well as request-specific parameters (which take precedence).
func (h SignerVerifier) validateVerify(req *signature.VerifyRequest) error {
	if req == nil {
		return errors.New("verifyRequest is nil")
	}

	if req.Digest == nil && req.Message == nil {
		return errors.New("digest or message is required to verify signature")
	}

	return nil
}

// verify verifies the signature for the specified verify request
func (h SignerVerifier) verify(req *signature.VerifyRequest) error {
	if req == nil {
		return errors.New("verifyRequest is nil")
	}

	hf := req.HashFunc
	if hf == crypto.Hash(0) {
		hf = h.hashFunc
	}

	digest := req.Digest
	if digest == nil {
		if hf == crypto.Hash(0) {
			digest = req.Message
		} else {
			hasher := hf.New()
			if _, err := hasher.Write(req.Message); err != nil {
				return errors.Wrap(err, "hashing during verification")
			}
			digest = hasher.Sum(nil)
		}
	} else if hf.Size() != len(digest) {
		return errors.New("unexpected length of digest for hash function specified")
	}

	return h.client.verify(req.Signature, digest, hf)
}

// CreateKey attempts to create a new key in Vault with the specified algorithm.
func (h SignerVerifier) CreateKey(_ context.Context, algorithm string) (crypto.PublicKey, error) {
	return h.client.createKey(algorithm)
}
