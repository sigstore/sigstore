// Copyright 2024 The Sigstore Authors.
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

// Package main implements fake signer to be used in tests
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	defaultAlgorithm = "rsa-2048"
)

var (
	supportedAlgorithms = []string{defaultAlgorithm}
)

// LocalSignerVerifier creates and verifies digital signatures with a key saved at KeyResourceID,
// and implements signerverifier.SignerVerifier.
type LocalSignerVerifier struct {
	keyResourceID string
	hashFunc      crypto.Hash
}

// DefaultAlgorithm returns the default algorithm for the signer.
func (i LocalSignerVerifier) DefaultAlgorithm() string {
	return defaultAlgorithm
}

// SupportedAlgorithms returns the supported algorithms for the signer.
func (i LocalSignerVerifier) SupportedAlgorithms() []string {
	return supportedAlgorithms
}

// CreateKey returns a new public key, and saves the private key to the path at KeyResourceID.
// Don't do this in your own real implementation!
func (i LocalSignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !slices.Contains(i.SupportedAlgorithms(), algorithm) {
		return nil, fmt.Errorf("algorithm %s not supported", algorithm)
	}

	path := i.keyResourceID

	if _, err := os.Stat(path); err == nil { // file exists
		privateKey, err := loadRSAPrivateKey(path)
		if err != nil {
			return nil, err
		}
		return &privateKey.PublicKey, nil
	} else if !errors.Is(err, os.ErrNotExist) { // any error other than ErrNotExist
		return nil, err
	}
	// proceed with creating the key

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %w", err)
	}

	// write to the path
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privateKeyPEMBuffer := new(bytes.Buffer)
	if err := pem.Encode(privateKeyPEMBuffer, privateKeyPEM); err != nil {
		return nil, fmt.Errorf("error encoding private key: %w", err)
	}

	if err := pem.Encode(privateKeyPEMBuffer, privateKeyPEM); err != nil {
		return nil, fmt.Errorf("error encoding private key: %w", err)
	}

	if err := os.WriteFile(path, privateKeyPEMBuffer.Bytes(), 0400); err != nil {
		return nil, fmt.Errorf("error creating private key file: %w", err)
	}

	publicKey := &privateKey.PublicKey
	return publicKey, nil
}

// PublicKey returns the public key.
func (i LocalSignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	privateKey, err := loadRSAPrivateKey(i.keyResourceID)
	if err != nil {
		return nil, err
	}
	return &privateKey.PublicKey, nil
}

// SignMessage signs the message with the KeyResourceID.
func (i LocalSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	privateKey, err := loadRSAPrivateKey(i.keyResourceID)
	if err != nil {
		return nil, err
	}

	var digest []byte
	var signerOpts crypto.SignerOpts = i.hashFunc
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	if len(digest) == 0 {
		digest, err = computeDigest(&message, signerOpts.HashFunc())
		if err != nil {
			return nil, err
		}
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, signerOpts.HashFunc(), digest)
	if err != nil {
		return nil, fmt.Errorf("error signing data: %w", err)
	}
	return signature, nil
}

// VerifySignature verifies the signature.
func (i LocalSignerVerifier) VerifySignature(signature io.Reader, message io.Reader, opts ...signature.VerifyOption) error {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	privateKey, err := loadRSAPrivateKey(i.keyResourceID)
	if err != nil {
		return err
	}
	publicKey := privateKey.PublicKey

	var digest []byte
	var signerOpts crypto.SignerOpts = i.hashFunc
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	if len(digest) == 0 {
		digest, err = computeDigest(&message, signerOpts.HashFunc())
		if err != nil {
			return err
		}
	}

	sig, err := io.ReadAll(signature)
	if err != nil {
		return fmt.Errorf("error reading signature: %w", err)
	}

	if err := rsa.VerifyPKCS1v15(&publicKey, signerOpts.HashFunc(), digest, sig); err != nil {
		return fmt.Errorf("error verifying signature: %w", err)
	}
	return nil
}

// loadRSAPrivateKey loads the private key from the path.
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	privateKeyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil || privateKeyBlock.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// computeDigest computes the message digest with the hash function.
func computeDigest(message *io.Reader, hashFunc crypto.Hash) ([]byte, error) {
	hasher := hashFunc.New()
	if _, err := io.Copy(hasher, *message); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

// CryptoSigner need not be fully implemented by plugins.
func (i LocalSignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	panic("CryptoSigner() not implemented")
}
