package azure

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type mockAzureVaultClient struct {
	pubKey   crypto.PublicKey
	privKey  crypto.PrivateKey
	azSigAlg azkeys.SignatureAlgorithm
	hashAlg  crypto.Hash
}

func (c *mockAzureVaultClient) createKey(ctx context.Context) (crypto.PublicKey, error) {
	return c.pubKey, nil
}

func (c *mockAzureVaultClient) fetchPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	return c.pubKey, nil
}

func (c *mockAzureVaultClient) getKey(ctx context.Context) (azkeys.KeyBundle, error) {
	return azkeys.KeyBundle{}, nil
}

func (c *mockAzureVaultClient) getKeyVaultHashFunc(ctx context.Context) (crypto.Hash, azkeys.SignatureAlgorithm, error) {
	return c.hashAlg, c.azSigAlg, nil
}

func (c *mockAzureVaultClient) public(ctx context.Context) (crypto.PublicKey, error) {
	return c.pubKey, nil
}

func (c *mockAzureVaultClient) sign(ctx context.Context, hash []byte) ([]byte, error) {
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

func (c *mockAzureVaultClient) verify(ctx context.Context, signature, hash []byte) error {
	// Convert the public key to an *rsa.PublicKey
	rsaPubKey, ok := c.pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not of type *rsa.PublicKey")
	}

	// Verify the signature
	err := rsa.VerifyPKCS1v15(rsaPubKey, c.hashAlg, hash, signature)
	if err != nil {
		return fmt.Errorf("verification error: %w", err)
	}

	return nil
}

func newRSAMockAzureVaultClient(t *testing.T) *mockAzureVaultClient {
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

	return &mockAzureVaultClient{
		pubKey:   pubKey,
		privKey:  privKey,
		azSigAlg: azkeys.SignatureAlgorithmRS512,
		hashAlg:  crypto.SHA512,
	}
}

func newECDSAMockAzureVaultClient(t *testing.T) *mockAzureVaultClient {
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

	return &mockAzureVaultClient{
		pubKey:   pubKey,
		privKey:  privKey,
		azSigAlg: azkeys.SignatureAlgorithmES256,
		hashAlg:  crypto.SHA256,
	}
}
