//
// Copyright 2026 The Sigstore Authors.
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
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/slhdsa"
)

var slhdsaSupportedHashFuncs = []crypto.Hash{
	crypto.Hash(0),
}

// DefaultSLHDSAParams is the parameter set used when a caller does not pick one.
// SLH-DSA-SHA2-128s has the smallest public key and signature in the small
// tradeoff and is a sound default for code signing where verification is rare.
var DefaultSLHDSAParams = slhdsa.SHA2_128s

// validateSLHDSAPublicKey checks that the SLH-DSA public key carries a valid
// parameter set and marshals to the size that set defines. A zero value key has
// an unset parameter id, and the underlying library panics when that id is read,
// so the recover turns that panic into an error rather than taking down a caller.
func validateSLHDSAPublicKey(pub *slhdsa.PublicKey) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("key is invalid: %v", r)
		}
	}()
	if pub == nil {
		return errors.New("public key is nil")
	}
	raw, err := pub.MarshalBinary()
	if err != nil {
		return fmt.Errorf("public key does not marshal: %w", err)
	}
	want := pub.Scheme().PublicKeySize()
	if len(raw) != want {
		return fmt.Errorf("public key is %d bytes, want %d", len(raw), want)
	}
	return nil
}

// SLHDSASigner is a signature.Signer that uses the SLH-DSA post-quantum signature scheme.
//
// WARNING: This is experimental and may change.
type SLHDSASigner struct {
	priv *slhdsa.PrivateKey
}

// LoadSLHDSASigner calculates signatures using the specified private key.
func LoadSLHDSASigner(priv *slhdsa.PrivateKey) (*SLHDSASigner, error) {
	if priv == nil {
		return nil, errors.New("invalid SLH-DSA private key specified")
	}
	pub := priv.PublicKey()
	if err := validateSLHDSAPublicKey(&pub); err != nil {
		return nil, fmt.Errorf("invalid SLH-DSA private key specified: %w", err)
	}

	return &SLHDSASigner{
		priv: priv,
	}, nil
}

// SignMessage signs the provided message using Pure SLH-DSA with an empty context.
//
// Passing the WithDigest option with a digest is not supported as SLH-DSA handles
// its own internal message processing. Other options are ignored.
func (s SLHDSASigner) SignMessage(message io.Reader, opts ...SignOption) ([]byte, error) {
	var digest []byte
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
	}
	if len(digest) > 0 {
		return nil, errors.New("WithDigest is not supported for SLH-DSA")
	}
	messageBytes, _, err := ComputeDigestForSigning(message, crypto.Hash(0), slhdsaSupportedHashFuncs)
	if err != nil {
		return nil, err
	}

	return slhdsa.SignDeterministic(s.priv, slhdsa.NewMessage(messageBytes), nil)
}

// Public returns the public key that can be used to verify signatures created by
// this signer.
func (s SLHDSASigner) Public() crypto.PublicKey {
	if s.priv == nil {
		return nil
	}

	return s.priv.Public()
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (s SLHDSASigner) PublicKey(_ ...PublicKeyOption) (crypto.PublicKey, error) {
	return s.Public(), nil
}

// Sign computes the signature for the specified message using Pure SLH-DSA with an empty
// context for consistency across software, KMS, and hardware backends. Callers requiring
// domain separation can enforce it at the payload level.
//
// The signature is deterministic, so the rand argument is ignored.
// If opts is non-nil, only opts with HashFunc() == crypto.Hash(0) are supported;
// pre-hashed message digests are not permitted.
func (s SLHDSASigner) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if message == nil {
		return nil, errors.New("message must not be nil")
	}
	if opts != nil {
		if opts.HashFunc() != crypto.Hash(0) {
			return nil, fmt.Errorf("unsupported hash function: %v", opts.HashFunc())
		}
	}
	return s.SignMessage(bytes.NewReader(message))
}

// SLHDSAVerifier is a signature.Verifier that uses the SLH-DSA post-quantum signature system.
//
// WARNING: This is experimental and may change.
type SLHDSAVerifier struct {
	publicKey *slhdsa.PublicKey
}

// LoadSLHDSAVerifier returns a Verifier that verifies signatures using the specified SLH-DSA public key.
func LoadSLHDSAVerifier(pub *slhdsa.PublicKey) (*SLHDSAVerifier, error) {
	if pub == nil {
		return nil, errors.New("invalid SLH-DSA public key specified")
	}
	if err := validateSLHDSAPublicKey(pub); err != nil {
		return nil, fmt.Errorf("invalid SLH-DSA public key specified: %w", err)
	}

	return &SLHDSAVerifier{
		publicKey: pub,
	}, nil
}

// PublicKey returns the public key that is used to verify signatures by
// this verifier. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (s *SLHDSAVerifier) PublicKey(_ ...PublicKeyOption) (crypto.PublicKey, error) {
	return s.publicKey, nil
}

// VerifySignature verifies the signature for the given message using Pure SLH-DSA with an empty context.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// Passing the WithDigest option with a digest is explicitly rejected as SLH-DSA does not support
// pre-hashed message digests. Other options are ignored.
func (s *SLHDSAVerifier) VerifySignature(signature, message io.Reader, opts ...VerifyOption) error {
	if signature == nil {
		return errors.New("nil signature passed to VerifySignature")
	}
	var digest []byte
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
	}
	if len(digest) > 0 {
		return errors.New("WithDigest is not supported for SLH-DSA")
	}
	messageBytes, _, err := ComputeDigestForVerifying(message, crypto.Hash(0), slhdsaSupportedHashFuncs)
	if err != nil {
		return err
	}

	sigBytes, err := io.ReadAll(signature)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}

	if !slhdsa.Verify(s.publicKey, slhdsa.NewMessage(messageBytes), sigBytes, nil) {
		return errors.New("failed to verify signature")
	}
	return nil
}

// SLHDSASignerVerifier is a signature.SignerVerifier that uses the SLH-DSA post-quantum signature system.
type SLHDSASignerVerifier struct {
	*SLHDSASigner
	*SLHDSAVerifier
}

// LoadSLHDSASignerVerifier creates a combined signer and verifier. This is
// a convenience object that simply wraps an instance of SLHDSASigner and SLHDSAVerifier.
func LoadSLHDSASignerVerifier(priv *slhdsa.PrivateKey) (*SLHDSASignerVerifier, error) {
	signer, err := LoadSLHDSASigner(priv)
	if err != nil {
		return nil, fmt.Errorf("initializing signer: %w", err)
	}
	pub := priv.PublicKey()
	verifier, err := LoadSLHDSAVerifier(&pub)
	if err != nil {
		return nil, fmt.Errorf("initializing verifier: %w", err)
	}

	return &SLHDSASignerVerifier{
		SLHDSASigner:   signer,
		SLHDSAVerifier: verifier,
	}, nil
}

// NewDefaultSLHDSASignerVerifier creates a combined signer and verifier using SLH-DSA.
// This creates a new SLH-DSA key using the recommended default parameter set.
func NewDefaultSLHDSASignerVerifier() (*SLHDSASignerVerifier, *slhdsa.PrivateKey, error) {
	return NewSLHDSASignerVerifier(DefaultSLHDSAParams)
}

// NewSLHDSASignerVerifier creates a combined signer and verifier using SLH-DSA.
// This creates a new SLH-DSA key using the specified parameter set.
func NewSLHDSASignerVerifier(id slhdsa.ID) (*SLHDSASignerVerifier, *slhdsa.PrivateKey, error) {
	_, priv, err := slhdsa.GenerateKey(rand.Reader, id)
	if err != nil {
		return nil, nil, err
	}

	sv, err := LoadSLHDSASignerVerifier(&priv)
	if err != nil {
		return nil, nil, err
	}

	return sv, &priv, nil
}

// PublicKey returns the public key that is used to verify signatures by
// this verifier. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (s SLHDSASignerVerifier) PublicKey(_ ...PublicKeyOption) (crypto.PublicKey, error) {
	return s.publicKey, nil
}
