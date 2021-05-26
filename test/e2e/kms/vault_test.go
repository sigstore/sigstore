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
	"context"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/sigstore/sigstore/pkg/kms"
	"github.com/sigstore/sigstore/pkg/signature"

	vault "github.com/hashicorp/vault/api"
)

type VaultSuite struct {
	suite.Suite
}

func (suite *VaultSuite) GetProvider(key string) kms.KMS {
	provider, err := kms.Get(context.Background(), fmt.Sprintf("hashivault://%s", key))
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), provider)
	return provider
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
	assert.Len(suite.T(), providers, 2)
}

func (suite *VaultSuite) TestProvider() {
	suite.GetProvider("provider")
}

func (suite *VaultSuite) TestCreateKey() {
	provider := suite.GetProvider("createkey")

	key, err := provider.CreateKey(context.Background())
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)
}

func (suite *VaultSuite) TestSign() {
	provider := suite.GetProvider("testsign")

	key, err := provider.CreateKey(context.Background())
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, signed, err := provider.Sign(context.Background(), data)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)
	assert.NotNil(suite.T(), signed)

	verifier := signature.ECDSAVerifier{
		Key:     key,
		HashAlg: crypto.SHA256,
	}
	err = verifier.Verify(context.TODO(), data, sig)
	assert.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestSignWithDifferentTransitSecretEnginePath() {
	provider := suite.GetProvider("testsign")
	os.Setenv("TRANSIT_SECRET_ENGINE_PATH", "somerandompath")

	key, err := provider.CreateKey(context.Background())
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, signed, err := provider.Sign(context.Background(), data)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)
	assert.NotNil(suite.T(), signed)

	verifier := signature.ECDSAVerifier{
		Key:     key,
		HashAlg: crypto.SHA256,
	}
	err = verifier.Verify(context.TODO(), data, sig)
	assert.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestPubKeyVerify() {
	provider := suite.GetProvider("testsign")

	key, err := provider.CreateKey(context.Background())
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, signed, err := provider.Sign(context.Background(), data)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), sig)
	require.NotNil(suite.T(), signed)

	k, err := provider.PublicKey(context.TODO())
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key)

	pubKey, ok := k.(*ecdsa.PublicKey)
	require.True(suite.T(), ok)

	verifier := signature.ECDSAVerifier{
		Key:     pubKey,
		HashAlg: crypto.SHA256,
	}
	err = verifier.Verify(context.TODO(), data, sig)
	assert.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestVerify() {
	provider := suite.GetProvider("testverify")

	key, err := provider.CreateKey(context.Background())
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, signed, err := provider.Sign(context.Background(), data)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)
	assert.NotNil(suite.T(), signed)

	err = provider.Verify(context.Background(), data, sig)
	assert.Nil(suite.T(), err)
}

func (suite *VaultSuite) TestNoProvider() {
	provider, err := kms.Get(context.Background(), "hashi://nonsense")
	require.Error(suite.T(), err)
	require.Nil(suite.T(), provider)
}

func TestVault(t *testing.T) {
	suite.Run(t, new(VaultSuite))
}
