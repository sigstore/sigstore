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

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
)

const (
	defaultAlgorithm = "rsa-2048"
)

// LocalSignerVerifier creates and verifies digital signatures with a key saved at KeyResourceID.
type LocalSignerVerifier struct {
	kms.SignerVerifier
	keyResourceID string
	hashFunc      crypto.Hash
}

// DefaultAlgorithm returns the default algorithm for the signer
func (i LocalSignerVerifier) DefaultAlgorithm() string {
	return defaultAlgorithm
}

// CreateKey returns a new public key, and saves the private key to the path at KeyResourceID.
// Don't do this in your own real implementation!
func (i LocalSignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	// TODO: implement SupportedAlgorithms()
	// if !slices.Contains(i.SupportedAlgorithms(), algorithm) {
	// 	return nil, fmt.Errorf("algorithm %s not supported", algorithm)
	// }
	if algorithm != i.DefaultAlgorithm() {
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

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privateKeyFile, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("error creating private key file: %w", err)
	}
	defer privateKeyFile.Close()

	// os.WriteFile(path, privateKeyBytes, 0600)

	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return nil, fmt.Errorf("error encoding private key: %w", err)
	}

	publicKey := &privateKey.PublicKey
	return publicKey, nil
}

// SignMessage signs the message with the KeyResourceID.
func (i LocalSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
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
