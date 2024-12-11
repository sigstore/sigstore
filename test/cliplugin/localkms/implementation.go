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

// Package fake implements fake signer to be used in tests
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

// SupportedAlgorithms returns a list with the default algorithm
func (i *LocalSignerVerifier) SupportedAlgorithms() (result []string) {
	return []string{defaultAlgorithm}
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

func computeDigest(message *io.Reader, hashFunc crypto.Hash) ([]byte, error) {
	hasher := hashFunc.New()
	if _, err := io.Copy(hasher, *message); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func (i LocalSignerVerifier) signMessageWithPrivateKey(privateKey *rsa.PrivateKey, message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	var digest []byte
	var signerOpts crypto.SignerOpts = i.hashFunc
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	var err error
	if len(digest) == 0 {
		digest, err = computeDigest(&message, signerOpts.HashFunc())
		if err != nil {
			return nil, err
		}
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
	if err != nil {
		return nil, fmt.Errorf("error signing data: %w", err)
	}
	return signature, nil
}

// SignMessage signs the message with the KeyResourceID.
func (i LocalSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	privateKey, err := loadRSAPrivateKey(i.keyResourceID)
	if err != nil {
		return nil, err
	}
	return i.signMessageWithPrivateKey(privateKey, message, opts...)
}
