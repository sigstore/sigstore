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
	"crypto/ed25519"
	"crypto/rand"
	"io"

	"github.com/pkg/errors"
)

type ED25519Signer struct {
	priv *ed25519.PrivateKey
}

// ELoadED25519Signer calculates signatures using the specified private key.
func LoadED25519Signer(priv *ed25519.PrivateKey) (*ED25519Signer, error) {
	if priv == nil {
		return nil, errors.New("invalid ED25519 private key specified")
	}

	return &ED25519Signer{
		priv: priv,
	}, nil
}

// SignMessage signs the provided message. Passing the WithDigest option is not
// supported as ED25519 performs a two pass hash over the message during the
// signing process.
//
// All options are ignored.
func (e ED25519Signer) SignMessage(message []byte, _ ...SignerOption) ([]byte, error) {
	req := &SignRequest{
		Message: message,
	}

	if err := e.validate(req); err != nil {
		return nil, err
	}

	return e.computeSignature(req)
}

// validate ensures that the provided signRequest can be successfully processed
// given internal fields as well as request-specific parameters (which take precedence).
func (e ED25519Signer) validate(req *SignRequest) error {
	// e.priv must be set
	if e.priv == nil {
		return errors.New("ED25519 private key is not initialized")
	}

	if req.Message == nil {
		return errors.New("message must be provided to sign using ED25519")
	}

	return nil
}

// computeSignature computes the signature for the specified signing request
func (e ED25519Signer) computeSignature(req *SignRequest) ([]byte, error) {
	return ed25519.Sign(*e.priv, req.Message), nil
}

// Public returns the public key that can be used to verify signatures created by
// this signer.
func (e ED25519Signer) Public() crypto.PublicKey {
	if e.priv == nil {
		return nil
	}

	return e.priv.Public()
}

// PublicWithContext returns the public key that can be used to verify signatures created by
// this signer. As this value is held in memory, the context argument to this method is ignored.
func (e ED25519Signer) PublicWithContext(_ context.Context) (crypto.PublicKey, error) {
	return e.Public(), nil
}

// Sign computes the signature for the specified message; the first and third arguments to this
// function are ignored as they are not used by the ED25519 algorithm.
func (e ED25519Signer) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	return e.SignMessage(message)
}

type ED25519Verifier struct {
	publicKey *ed25519.PublicKey
}

// LoadED25519Verifier returns a Verifier that verifies signatures using the specified ED25519 public key.
func LoadED25519Verifier(pub ed25519.PublicKey) (*ED25519Verifier, error) {
	if pub == nil {
		return nil, errors.New("invalid ED25519 public key specified")
	}

	return &ED25519Verifier{
		publicKey: &pub,
	}, nil
}

// VerifySignature verifies the signature for the given message.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// All options are ignored if specified.
func (e ED25519Verifier) VerifySignature(signature []byte, message []byte, _ ...VerifierOption) error {
	req := &VerifyRequest{
		Message:   message,
		Signature: signature,
	}

	if err := e.validate(req); err != nil {
		return err
	}

	return e.verify(req)
}

// validate ensures that the provided verifyRequest can be successfully processed
// given internal fields as well as request-specific parameters (which take precedence).
func (e ED25519Verifier) validate(req *VerifyRequest) error {
	// e.PublicKey must be set
	if e.publicKey == nil {
		return errors.New("public key is not initialized")
	}

	if req.Message == nil {
		return errors.New("message must be specified in WithMessage() option")
	}

	return nil
}

// verify verifies the signature for the specified verify request
func (e ED25519Verifier) verify(req *VerifyRequest) error {
	if !ed25519.Verify(*e.publicKey, req.Message, req.Signature) {
		return errors.New("failed to verify signature")
	}
	return nil
}

type ED25519SignerVerifier struct {
	*ED25519Signer
	*ED25519Verifier
}

// LoadD25519SignerVerifier creates a combined signer and verifier. This is
// a convenience object that simply wraps an instance of ED25519Signer and ED25519Verifier.
func LoadED25519SignerVerifier(priv *ed25519.PrivateKey) (*ED25519SignerVerifier, error) {
	signer, err := LoadED25519Signer(priv)
	if err != nil {
		return nil, errors.Wrap(err, "initializing signer")
	}
	pub := priv.Public().(ed25519.PublicKey)
	verifier, err := LoadED25519Verifier(pub)
	if err != nil {
		return nil, errors.Wrap(err, "initializing verifier")
	}

	return &ED25519SignerVerifier{
		ED25519Signer:   signer,
		ED25519Verifier: verifier,
	}, nil
}

// NewDefaultD25519SignerVerifier creates a combined signer and verifier using ED25519.
// This creates a new ED25519 key using crypto/rand as an entropy source.
func NewDefaultED25519SignerVerifierE() (SignerVerifier, *ed25519.PrivateKey, error) {
	return NewED25519SignerVerifier(rand.Reader)
}

// NewD25519SignerVerifier creates a combined signer and verifier using ED25519.
// This creates a new ED25519 key using the specified entropy source.
func NewED25519SignerVerifier(rand io.Reader) (SignerVerifier, *ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}

	sv, err := LoadED25519SignerVerifier(&priv)
	if err != nil {
		return nil, nil, err
	}

	return sv, &priv, nil
}
