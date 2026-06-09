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
	"errors"
	"fmt"
	"io"

	"filippo.io/mldsa"
)

var mldsaSupportedHashFuncs = []crypto.Hash{
	crypto.Hash(0),
}

// MLDSASigner is a signature.Signer that uses the ML-DSA post-quantum signature system
type MLDSASigner struct {
	priv *mldsa.PrivateKey
}

// LoadMLDSASigner calculates signatures using the specified private key.
func LoadMLDSASigner(priv *mldsa.PrivateKey) (*MLDSASigner, error) {
	if priv == nil {
		return nil, errors.New("invalid ML-DSA private key specified")
	}

	return &MLDSASigner{
		priv: priv,
	}, nil
}

// SignMessage signs the provided message. Passing the WithDigest option is not
// supported as ML-DSA handles its own internal message processing.
//
// All options are ignored.
func (m MLDSASigner) SignMessage(message io.Reader, _ ...SignOption) ([]byte, error) {
	messageBytes, _, err := ComputeDigestForSigning(message, crypto.Hash(0), mldsaSupportedHashFuncs)
	if err != nil {
		return nil, err
	}

	return m.priv.SignDeterministic(messageBytes, nil)
}

// Public returns the public key that can be used to verify signatures created by
// this signer.
func (m MLDSASigner) Public() crypto.PublicKey {
	if m.priv == nil {
		return nil
	}

	return m.priv.Public()
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (m MLDSASigner) PublicKey(_ ...PublicKeyOption) (crypto.PublicKey, error) {
	return m.Public(), nil
}

// Sign computes the signature for the specified message; the first and third arguments to this
// function are ignored as they are not used by the ML-DSA algorithm (using deterministic signing).
func (m MLDSASigner) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	if message == nil {
		return nil, errors.New("message must not be nil")
	}
	return m.SignMessage(bytes.NewReader(message))
}

// MLDSAVerifier is a signature.Verifier that uses the ML-DSA post-quantum signature system
type MLDSAVerifier struct {
	publicKey *mldsa.PublicKey
}

// LoadMLDSAVerifier returns a Verifier that verifies signatures using the specified ML-DSA public key.
func LoadMLDSAVerifier(pub *mldsa.PublicKey) (*MLDSAVerifier, error) {
	if pub == nil {
		return nil, errors.New("invalid ML-DSA public key specified")
	}

	return &MLDSAVerifier{
		publicKey: pub,
	}, nil
}

// PublicKey returns the public key that is used to verify signatures by
// this verifier. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (m *MLDSAVerifier) PublicKey(_ ...PublicKeyOption) (crypto.PublicKey, error) {
	return m.publicKey, nil
}

// VerifySignature verifies the signature for the given message.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// All options are ignored if specified.
func (m *MLDSAVerifier) VerifySignature(signature, message io.Reader, _ ...VerifyOption) error {
	messageBytes, _, err := ComputeDigestForVerifying(message, crypto.Hash(0), mldsaSupportedHashFuncs)
	if err != nil {
		return err
	}

	if signature == nil {
		return errors.New("nil signature passed to VerifySignature")
	}

	sigBytes, err := io.ReadAll(signature)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}

	return mldsa.Verify(m.publicKey, messageBytes, sigBytes, nil)
}

// MLDSASignerVerifier is a signature.SignerVerifier that uses the ML-DSA post-quantum signature system
type MLDSASignerVerifier struct {
	*MLDSASigner
	*MLDSAVerifier
}

// LoadMLDSASignerVerifier creates a combined signer and verifier. This is
// a convenience object that simply wraps an instance of MLDSASigner and MLDSAVerifier.
func LoadMLDSASignerVerifier(priv *mldsa.PrivateKey) (*MLDSASignerVerifier, error) {
	signer, err := LoadMLDSASigner(priv)
	if err != nil {
		return nil, fmt.Errorf("initializing signer: %w", err)
	}
	pub, ok := priv.Public().(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("given key is not *mldsa.PublicKey")
	}
	verifier, err := LoadMLDSAVerifier(pub)
	if err != nil {
		return nil, fmt.Errorf("initializing verifier: %w", err)
	}

	return &MLDSASignerVerifier{
		MLDSASigner:   signer,
		MLDSAVerifier: verifier,
	}, nil
}

// NewDefaultMLDSASignerVerifier creates a combined signer and verifier using ML-DSA.
// This creates a new ML-DSA key using the recommended default MLDSA44 parameter set.
func NewDefaultMLDSASignerVerifier() (*MLDSASignerVerifier, *mldsa.PrivateKey, error) {
	return NewMLDSASignerVerifier(mldsa.MLDSA44())
}

// NewMLDSASignerVerifier creates a combined signer and verifier using ML-DSA.
// This creates a new ML-DSA key using the specified parameter set.
func NewMLDSASignerVerifier(params *mldsa.Parameters) (*MLDSASignerVerifier, *mldsa.PrivateKey, error) {
	priv, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, nil, err
	}

	sv, err := LoadMLDSASignerVerifier(priv)
	if err != nil {
		return nil, nil, err
	}

	return sv, priv, nil
}

// PublicKey returns the public key that is used to verify signatures by
// this verifier. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (m MLDSASignerVerifier) PublicKey(_ ...PublicKeyOption) (crypto.PublicKey, error) {
	return m.publicKey, nil
}
