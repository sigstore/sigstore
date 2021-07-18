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

// +build e2e

package main

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
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
	"github.com/sigstore/sigstore/pkg/signature/options"

	vault "github.com/hashicorp/vault/api"
)

type VaultSuite struct {
	suite.Suite
}

func (suite *VaultSuite) GetProvider(key string) *hashivault.SignerVerifier {
	provider, err := kms.Get(context.Background(), fmt.Sprintf("hashivault://%s", key), crypto.SHA256)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), provider)
	return provider.(*hashivault.SignerVerifier)
}

func (suite *VaultSuite) SetupSuite() {
	client, err := vault.NewClient(&vault.Config{
		Address: os.Getenv("VAULT_ADDR"),
	})
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), client)

	err = client.Sys().Mount("transit", &vault.MountInput{
		Type: "transit",
	})
	require.Nil(suite.T(), err)

	err = client.Sys().Mount("somerandompath", &vault.MountInput{
		Type: "transit",
	})
	require.Nil(suite.T(), err)
}

func (suite *VaultSuite) TearDownSuite() {
	client, err := vault.NewClient(&vault.Config{
		Address: os.Getenv("VAULT_ADDR"),
	})
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), client)

	err = client.Sys().Unmount("transit")
	require.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestProviders() {
	providers := kms.ProvidersMux().Providers()
	assert.Len(suite.T(), providers, 4)
}

func (suite *VaultSuite) TestProvider() {
	suite.GetProvider("provider")
}

func (suite *VaultSuite) TestCreateKey() {
	provider := suite.GetProvider("createkey")

	key, err := provider.CreateKey(context.Background(), hashivault.Algorithm_ECDSA_P256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)
}

func (suite *VaultSuite) TestSign() {
	provider := suite.GetProvider("testsign")

	key, err := provider.CreateKey(context.Background(), hashivault.Algorithm_ECDSA_P256)
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

func (suite *VaultSuite) TestSignWithDifferentTransitSecretEnginePath() {
	provider := suite.GetProvider("testsign")
	os.Setenv("TRANSIT_SECRET_ENGINE_PATH", "somerandompath")
	defer os.Setenv("TRANSIT_SECRET_ENGINE_PATH", "transit")

	key, err := provider.CreateKey(context.Background(), hashivault.Algorithm_ECDSA_P256)
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

	key, err := provider.CreateKey(context.Background(), hashivault.Algorithm_ECDSA_P256)
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

	key, err := provider.CreateKey(context.Background(), hashivault.Algorithm_ECDSA_P256)
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

	key, err := provider.CreateKey(context.Background(), hashivault.Algorithm_ECDSA_P256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestNoProvider() {
	provider, err := kms.Get(context.Background(), "hashi://nonsense", crypto.Hash(0))
	require.Error(suite.T(), err)
	require.Nil(suite.T(), provider)
}

func TestVault(t *testing.T) {
	suite.Run(t, new(VaultSuite))
}
