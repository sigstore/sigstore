package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/sigstore/sigstore/pkg/kms"

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

	hash := sha256.Sum256(signed)
	ok := ecdsa.VerifyASN1(key, hash[:], sig)
	assert.True(suite.T(), ok)
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
