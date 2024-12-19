// Copyright 2022 The Sigstore Authors.
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
	"fmt"
	"os"

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

// CreateKey returns a new public key, and saves the private key to the KeyResourceID.
func (i LocalSignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	// TODO: implement SupportedAlgorithms()
	// if !slices.Contains(i.SupportedAlgorithms(), algorithm) {
	// 	return nil, fmt.Errorf("algorithm %s not supported", algorithm)
	// }
	if algorithm != i.DefaultAlgorithm() {
		return nil, fmt.Errorf("algorithm %s not supported", algorithm)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %w", err)
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	path := i.keyResourceID
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
