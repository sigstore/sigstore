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

//go:build e2e
// +build e2e

package hashivault

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"

	vault "github.com/hashicorp/vault/api"
)

type VaultSuite struct {
	suite.Suite
	vaultclient *vault.Client
}

func (suite *VaultSuite) GetProvider(key string, opts ...signature.RPCOption) *SignerVerifier {
	provider, err := LoadSignerVerifier(fmt.Sprintf("hashivault://%s", key), crypto.SHA256, opts...)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), provider)
	return provider
}

func (suite *VaultSuite) SetupSuite() {
	var err error
	suite.vaultclient, err = vault.NewClient(&vault.Config{
		Address: os.Getenv("VAULT_ADDR"),
	})
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), suite.vaultclient)

	err = suite.vaultclient.Sys().Mount("transit", &vault.MountInput{
		Type: "transit",
	})
	require.Nil(suite.T(), err)

	err = suite.vaultclient.Sys().Mount("somerandompath", &vault.MountInput{
		Type: "transit",
	})
	require.Nil(suite.T(), err)
}

func (suite *VaultSuite) TearDownSuite() {
	var err error
	if suite.vaultclient == nil {
		suite.vaultclient, err = vault.NewClient(&vault.Config{
			Address: os.Getenv("VAULT_ADDR"),
		})
		require.Nil(suite.T(), err)
		require.NotNil(suite.T(), suite.vaultclient)
	}

	err = suite.vaultclient.Sys().Unmount("transit")
	require.Nil(suite.T(), err)
	err = suite.vaultclient.Sys().Unmount("somerandompath")
	require.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestProvider() {
	suite.GetProvider("provider")
}

func (suite *VaultSuite) TestCreateKey() {
	provider := suite.GetProvider("createkey")

	key, err := provider.CreateKey(context.Background(), AlgorithmECDSAP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)
}

func (suite *VaultSuite) TestSign() {
	provider := suite.GetProvider("testsign")

	key, err := provider.CreateKey(context.Background(), AlgorithmECDSAP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	verifier, _ := signature.LoadECDSAVerifier(key.(*ecdsa.PublicKey), crypto.SHA256)
	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestSignOpts() {
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	os.Setenv("VAULT_ADDR", "")
	os.Setenv("VAULT_TOKEN", "")
	defer os.Setenv("VAULT_ADDR", addr)
	defer os.Setenv("VAULT_TOKEN", token)
	provider := suite.GetProvider("testsign",
		options.WithRPCAuthOpts(options.RPCAuth{Address: addr, Token: token}))

	key, err := provider.CreateKey(context.Background(), AlgorithmECDSAP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	verifier, _ := signature.LoadECDSAVerifier(key.(*ecdsa.PublicKey), crypto.SHA256)
	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestSignSpecificKeyVersion() {
	provider := suite.GetProvider("testsignversion")

	key, err := provider.CreateKey(context.Background(), AlgorithmECDSAP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	// test without specifying any value (aka use default)
	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)
	verifier, _ := signature.LoadECDSAVerifier(key.(*ecdsa.PublicKey), crypto.SHA256)
	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)

	// test with specifying default value
	sig, err = provider.SignMessage(bytes.NewReader(data), options.WithKeyVersion("0"))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	// test with specifying explicit value
	sig, err = provider.SignMessage(bytes.NewReader(data), options.WithKeyVersion("1"))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	// test version that doesn't (yet) exist
	sig, err = provider.SignMessage(bytes.NewReader(data), options.WithKeyVersion("2"))
	assert.NotNil(suite.T(), err)
	assert.Nil(suite.T(), sig)

	// rotate key (now two valid versions)
	client := suite.vaultclient.Logical()
	_, err = client.Write("/transit/keys/testsignversion/rotate", nil)
	assert.Nil(suite.T(), err)

	// test default version again (implicitly)
	sig, err = provider.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	// test default version again (explicitly)
	sig, err = provider.SignMessage(bytes.NewReader(data), options.WithKeyVersion("0"))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	// test explicit previous version (should still work as we haven't set min_encryption_version yet)
	sig, err = provider.SignMessage(bytes.NewReader(data), options.WithKeyVersion("1"))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	// test explicit new version
	sig, err = provider.SignMessage(bytes.NewReader(data), options.WithKeyVersion("2"))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	// test bad value
	sig, err = provider.SignMessage(bytes.NewReader(data), options.WithKeyVersion("3"))
	assert.NotNil(suite.T(), err)
	assert.Nil(suite.T(), sig)

	// change minimum to v2
	_, err = client.Write("/transit/keys/testsignversion/config", map[string]interface{}{
		"min_encryption_version": 2,
	})
	assert.Nil(suite.T(), err)

	// test explicit previous version (should fail as min_encryption_version has been set)
	sig, err = provider.SignMessage(bytes.NewReader(data), options.WithKeyVersion("1"))
	assert.NotNil(suite.T(), err)
	assert.Nil(suite.T(), sig)

	provider2 := suite.GetProvider("testsignversion", options.WithKeyVersion("2"))
	sig, err = provider2.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	// test explicit new version
	sig, err = provider2.SignMessage(bytes.NewReader(data), options.WithKeyVersion("2"))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)
}

func (suite *VaultSuite) TestVerifySpecificKeyVersion() {
	provider := suite.GetProvider("testverifyversion")

	key, err := provider.CreateKey(context.Background(), AlgorithmECDSAP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	// test using v1
	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data), options.WithKeyVersion("1"))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	// test without specifying key value
	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)

	// test with explicitly specifying default value
	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), options.WithKeyVersion("1"))
	assert.Nil(suite.T(), err)

	// test version that doesn't (yet) exist
	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), options.WithKeyVersion("2"))
	assert.NotNil(suite.T(), err)

	// rotate key (now two valid versions)
	client := suite.vaultclient.Logical()
	_, err = client.Write("/transit/keys/testverifyversion/rotate", nil)
	assert.Nil(suite.T(), err)

	// test invalid version (0 is fine for signing, but must be >= 1 for verification)
	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), options.WithKeyVersion("0"))
	assert.NotNil(suite.T(), err)

	// test explicit previous version (should still as we haven't set min_decryption_version yet)
	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), options.WithKeyVersion("1"))
	assert.Nil(suite.T(), err)

	// test explicit new version (should fail since it doesn't match the v1 key)
	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), options.WithKeyVersion("2"))
	assert.NotNil(suite.T(), err)

	// test bad value
	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), options.WithKeyVersion("3"))
	assert.NotNil(suite.T(), err)

	// change minimum to v2
	_, err = client.Write("/transit/keys/testverifyversion/config", map[string]interface{}{
		"min_decryption_version": 2,
	})
	assert.Nil(suite.T(), err)

	// test explicit previous version (should fail as min_decryption_version has been set)
	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), options.WithKeyVersion("1"))
	assert.NotNil(suite.T(), err)
}

func (suite *VaultSuite) TestSignAndRecordKeyVersion() {
	provider := suite.GetProvider("testrecordsignversion")

	key, err := provider.CreateKey(context.Background(), AlgorithmECDSAP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	// test for v1
	data := []byte("mydata")
	var versionUsed string
	sig, err := provider.SignMessage(bytes.NewReader(data), options.ReturnKeyVersionUsed(&versionUsed))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)
	assert.Contains(suite.T(), versionUsed, "vault:v1:")

	// rotate
	client := suite.vaultclient.Logical()
	_, err = client.Write("/transit/keys/testrecordsignversion/rotate", nil)
	assert.Nil(suite.T(), err)

	sig, err = provider.SignMessage(bytes.NewReader(data), options.WithKeyVersion("2"), options.ReturnKeyVersionUsed(&versionUsed))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)
	assert.Contains(suite.T(), versionUsed, "vault:v2:")
}

func (suite *VaultSuite) TestSignWithDifferentTransitSecretEnginePath() {
	provider := suite.GetProvider("testsign")
	os.Setenv("TRANSIT_SECRET_ENGINE_PATH", "somerandompath")
	defer os.Setenv("TRANSIT_SECRET_ENGINE_PATH", "transit")

	key, err := provider.CreateKey(context.Background(), AlgorithmECDSAP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data), options.WithContext(context.Background()))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	verifier, err := signature.LoadECDSAVerifier(key.(*ecdsa.PublicKey), crypto.SHA256)
	assert.Nil(suite.T(), err)

	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), options.WithContext(context.Background()))
	assert.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestInvalidPublicKey() {
	var provider *SignerVerifier
	var err error
	assert.NotPanics(suite.T(), func() {
		provider, _ = LoadSignerVerifier("hashivault://pki_int", crypto.SHA256)
		_, err = provider.client.fetchPublicKey(context.Background())
	})
	assert.NotNil(suite.T(), err)
}

func (suite *VaultSuite) TestSignWithDifferentTransitSecretEnginePathOpts() {
	provider := suite.GetProvider("testsign", options.WithRPCAuthOpts(options.RPCAuth{Path: "somerandompath"}))

	key, err := provider.CreateKey(context.Background(), AlgorithmECDSAP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data), options.WithContext(context.Background()))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	verifier, err := signature.LoadECDSAVerifier(key.(*ecdsa.PublicKey), crypto.SHA256)
	assert.Nil(suite.T(), err)

	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), options.WithContext(context.Background()))
	assert.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestPubKeyVerify() {
	provider := suite.GetProvider("testsign")

	key, err := provider.CreateKey(context.Background(), AlgorithmECDSAP256)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), sig)

	k, err := provider.PublicKey()
	require.NotNil(suite.T(), k)
	require.Nil(suite.T(), err)

	pubKey, ok := k.(*ecdsa.PublicKey)
	require.True(suite.T(), ok)

	verifier, _ := signature.LoadECDSAVerifier(pubKey, crypto.SHA256)
	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestCryptoSigner() {
	provider := suite.GetProvider("testsign")

	key, err := provider.CreateKey(context.Background(), AlgorithmECDSAP256)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key)

	data := []byte("mydata")
	cs, opts, err := provider.CryptoSigner(context.Background(), func(err error) { require.Nil(suite.T(), err) })
	hasher := opts.HashFunc().New()
	_, _ = hasher.Write(data)
	sig, err := cs.Sign(rand.Reader, hasher.Sum(nil), opts)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), sig)

	k := cs.Public()
	require.NotNil(suite.T(), k)

	pubKey, ok := k.(*ecdsa.PublicKey)
	require.True(suite.T(), ok)

	verifier, _ := signature.LoadECDSAVerifier(pubKey, crypto.SHA256)
	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestVerify() {
	provider := suite.GetProvider("testverify")

	key, err := provider.CreateKey(context.Background(), AlgorithmECDSAP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestED25519() {
	provider := suite.GetProvider("testverify")

	key, err := provider.CreateKey(context.Background(), AlgorithmED25519)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestVerifyBadData() {
	provider := suite.GetProvider("testverify")

	key, err := provider.CreateKey(context.Background(), AlgorithmECDSAP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	dataInvalid := []byte("mydata-invalid")
	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(dataInvalid))
	assert.Contains(suite.T(), err.Error(), "failed vault verification")
}

func (suite *VaultSuite) TestBadSignature() {
	provider1 := suite.GetProvider("testverify1")
	provider2 := suite.GetProvider("testverify2")

	key1, err := provider1.CreateKey(context.Background(), AlgorithmECDSAP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key1)

	key2, err := provider2.CreateKey(context.Background(), AlgorithmECDSAP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key2)

	data := []byte("mydata")
	sig1, err := provider1.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig1)

	err = provider1.VerifySignature(bytes.NewReader(sig1), bytes.NewReader(data))
	assert.Nil(suite.T(), err)

	err = provider2.VerifySignature(bytes.NewReader(sig1), bytes.NewReader(data))
	assert.NotNil(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed vault verification")
}

func (suite *VaultSuite) TestNoProvider() {
	provider, err := LoadSignerVerifier("hashi://nonsense", crypto.Hash(0))
	require.Error(suite.T(), err)
	require.Nil(suite.T(), provider)
}

func (suite *VaultSuite) TestInvalidHost() {
	provider, err := LoadSignerVerifier("hashivault://keyname", crypto.SHA256,
		options.WithRPCAuthOpts(options.RPCAuth{Address: "https://unknown.example.com:8200"}))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), provider)

	_, err = provider.CreateKey(context.Background(), AlgorithmECDSAP256)
	require.Error(suite.T(), err)
}

func TestVault(t *testing.T) {
	suite.Run(t, new(VaultSuite))
}
