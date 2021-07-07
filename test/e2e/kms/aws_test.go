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
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	awskms "github.com/aws/aws-sdk-go/service/kms"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/aws"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

type AWSSuite struct {
	suite.Suite
	endpoint string
}

func (suite *AWSSuite) GetProvider(key string) *aws.SignerVerifier {
	provider, err := kms.Get(context.Background(), fmt.Sprintf("awskms://%s/%s", suite.endpoint, key), crypto.SHA256)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), provider)
	return provider.(*aws.SignerVerifier)
}

func (suite *AWSSuite) SetupSuite() {
	suite.endpoint = os.Getenv("AWS_ENDPOINT")
}

func (suite *AWSSuite) TestGetProvider() {
	_ = suite.GetProvider("alias/provider")
	_ = suite.GetProvider("1234abcd-12ab-34cd-56ef-1234567890ab")
}

func (suite *AWSSuite) TestInvalidProvider() {
	provider, err := kms.Get(context.Background(), "awskms://"+suite.endpoint+"/nonsense", crypto.SHA256)
	require.Error(suite.T(), err)
	require.Nil(suite.T(), provider)
}

func (suite *AWSSuite) TestCreateKey() {
	provider := suite.GetProvider("alias/provider")

	key, err := provider.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	key2, err := provider.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	// Subsequent call should produce same key
	assert.Equal(suite.T(), key, key2)
}

func (suite *AWSSuite) TestCreateKeyByID() {
	provider := suite.GetProvider("1234abcd-12ab-34cd-56ef-1234567890ab")

	// CreateKey can only work with aliases, not IDs
	key, err := provider.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), key)
}

func (suite *AWSSuite) TestSign() {
	provider := suite.GetProvider("alias/TestSign")

	key, err := provider.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
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

func (suite *AWSSuite) TestSHA384() {
	provider := suite.GetProvider("alias/TestSHA384")

	key, err := provider.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP384)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), sig)

	k, err := provider.PublicKey()
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key)

	pubKey, ok := k.(*ecdsa.PublicKey)
	require.True(suite.T(), ok)

	verifier, _ := signature.LoadECDSAVerifier(pubKey, crypto.SHA384)
	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *AWSSuite) TestPublicKey() {
	provider := suite.GetProvider("alias/TestPubKeyVerify")

	key, err := provider.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	require.NotNil(suite.T(), sig)
	require.Nil(suite.T(), err)

	k, err := provider.PublicKey()
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key)

	pubKey, ok := k.(*ecdsa.PublicKey)
	require.True(suite.T(), ok)

	verifier, _ := signature.LoadECDSAVerifier(pubKey, crypto.SHA256)
	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *AWSSuite) TestVerify() {
	provider := suite.GetProvider("alias/TestVerify")

	key, err := provider.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	require.Nil(suite.T(), err)

	err = provider.VerifySignatureRemotely(bytes.NewReader(sig), bytes.NewReader(data))
	require.Nil(suite.T(), err)
}

func (suite *AWSSuite) TestTwoProviders() {
	provider1 := suite.GetProvider("alias/TestTwoProviders")
	provider2 := suite.GetProvider("alias/TestTwoProviders")

	key, err := provider1.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider1.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	err = provider2.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	require.Nil(suite.T(), err)
}

func (suite *AWSSuite) TestKeyTypes() {
	for _, cmkSpec := range []string{
		awskms.CustomerMasterKeySpecRsa2048,
		awskms.CustomerMasterKeySpecRsa3072,
		awskms.CustomerMasterKeySpecRsa4096,
		awskms.CustomerMasterKeySpecEccNistP256,
		awskms.CustomerMasterKeySpecEccNistP384,
		awskms.CustomerMasterKeySpecEccNistP521,
		//awskms.CustomerMasterKeySpecEccSecgP256k1, // unsupported by localstack at the moment
	} {
		suite.T().Run(fmt.Sprintf("KeyType-%s", cmkSpec), func(t *testing.T) {
			provider := suite.GetProvider("alias/" + cmkSpec)
			key, err := provider.CreateKey(context.Background(), cmkSpec)
			assert.Nil(suite.T(), err)
			assert.NotNil(suite.T(), key)

			data := []byte("mydata")
			sig, err := provider.SignMessage(bytes.NewReader(data))
			assert.Nil(suite.T(), err)
			assert.NotNil(suite.T(), sig)

			err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
			require.Nil(suite.T(), err)
		})
	}
}

func (suite *AWSSuite) TestCancelContext() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	provider := suite.GetProvider("alias/TestCancelContext")
	key, err := provider.CreateKey(ctx, awskms.CustomerMasterKeySpecEccNistP256)
	assert.Error(suite.T(), err)
	require.Contains(suite.T(), err.Error(), context.Canceled.Error())
	require.Nil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data), options.WithContext(ctx))
	assert.Error(suite.T(), err)
	require.Contains(suite.T(), err.Error(), context.Canceled.Error())
	require.Nil(suite.T(), sig)

	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), options.WithContext(ctx))
	assert.Error(suite.T(), err)
	require.Contains(suite.T(), err.Error(), context.Canceled.Error())
}

func TestAWS(t *testing.T) {
	suite.Run(t, new(AWSSuite))
}
