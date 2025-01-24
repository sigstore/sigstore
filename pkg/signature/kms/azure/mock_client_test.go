//
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

package azure

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type mockVaultClient struct {
	pubKey     crypto.PublicKey
	privKey    crypto.PrivateKey
	azSigAlg   azkeys.SignatureAlgorithm
	hashAlg    crypto.Hash
	verifyFunc func(context.Context, []byte, []byte) error
}

func (c *mockVaultClient) isRSAKey() bool {
	algString := string(c.azSigAlg)
	return strings.HasPrefix(algString, "RS")
}

func (c *mockVaultClient) createKey(ctx context.Context) (crypto.PublicKey, error) {
	return c.pubKey, nil
}

func (c *mockVaultClient) fetchPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	return c.pubKey, nil
}

func (c *mockVaultClient) getKey(ctx context.Context) (azkeys.KeyBundle, error) {
	return azkeys.KeyBundle{}, nil
}

func (c *mockVaultClient) getKeyVaultHashFunc(ctx context.Context) (crypto.Hash, azkeys.SignatureAlgorithm, error) {
	return c.hashAlg, c.azSigAlg, nil
}

func (c *mockVaultClient) public(ctx context.Context) (crypto.PublicKey, error) {
	return c.pubKey, nil
}

func (c *mockVaultClient) sign(ctx context.Context, hash []byte) ([]byte, error) {
	if c.isRSAKey() {
		rsaPrivKey, ok := c.privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not of type *rsa.PrivateKey")
		}

		// Sign the hashed input
		signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivKey, c.hashAlg, hash)
		if err != nil {
			return nil, fmt.Errorf("error signing input: %w", err)
		}

		return signature, nil
	}

	ecdsaPrivKey, ok := c.privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not of type *ecdsa.PrivateKey")
	}

	// Sign the hashed input
	signature, err := ecdsa.SignASN1(rand.Reader, ecdsaPrivKey, hash)
	if err != nil {
		return nil, fmt.Errorf("error signing input: %w", err)
	}

	return signature, nil
}

func (c *mockVaultClient) verify(ctx context.Context, signature, hash []byte) error {
	if c.isRSAKey() {
		// Convert the public key to an *rsa.PublicKey
		rsaPubKey, ok := c.pubKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key is not of type *rsa.PublicKey")
		}

		// Verify the signature
		if err := rsa.VerifyPKCS1v15(rsaPubKey, c.hashAlg, hash, signature); err != nil {
			return fmt.Errorf("verification error: %w", err)
		}

		return nil
	}

	// Convert the public key to an *ecdsa.PublicKey
	ecdsaPubKey, ok := c.pubKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not of type *ecdsa.PublicKey")
	}

	// Verify the signature
	if verified := ecdsa.VerifyASN1(ecdsaPubKey, hash, signature); !verified {
		return fmt.Errorf("verification error")
	}

	return nil
}

func newRSAMockAzureVaultClient(t *testing.T) *mockVaultClient {
	priv, pub, err := cryptoutils.GeneratePEMEncodedRSAKeyPair(4098, nil)
	if err != nil {
		t.Fatalf("error generating RSA key pair: %v", err)
	}

	privKey, err := cryptoutils.UnmarshalPEMToPrivateKey(priv, nil)
	if err != nil {
		t.Fatalf("error unmarshalling private key: %v", err)
	}

	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(pub)
	if err != nil {
		t.Fatalf("error unmarshalling private key: %v", err)
	}

	return &mockVaultClient{
		pubKey:   pubKey,
		privKey:  privKey,
		azSigAlg: azkeys.SignatureAlgorithmRS512,
		hashAlg:  crypto.SHA512,
	}
}

func newECDSAMockAzureVaultClient(t *testing.T) *mockVaultClient {
	priv, pub, err := cryptoutils.GeneratePEMEncodedECDSAKeyPair(elliptic.P256(), nil)
	if err != nil {
		t.Fatalf("error generating ECDSA key pair: %v", err)
	}

	privKey, err := cryptoutils.UnmarshalPEMToPrivateKey(priv, nil)
	if err != nil {
		t.Fatalf("error unmarshalling private key: %v", err)
	}

	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(pub)
	if err != nil {
		t.Fatalf("error unmarshalling private key: %v", err)
	}

	return &mockVaultClient{
		pubKey:   pubKey,
		privKey:  privKey,
		azSigAlg: azkeys.SignatureAlgorithmES256,
		hashAlg:  crypto.SHA256,
	}
}
