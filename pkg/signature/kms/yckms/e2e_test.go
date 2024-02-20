//
// Copyright 2023 The Sigstore Authors.
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

//go:build yc_e2e
// +build yc_e2e

package yckms

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

/*
The following environment variables must be set:
One of YC_IAM_TOKEN, YC_OAUTH_TOKEN, YC_SERVICE_ACCOUNT_KEY_FILE access token to key and folder
KEY_ID - Already created key, make sure that access token have permission for this key
FOLDER_ID - Folder to test create key
*/

type YCSuite struct {
	suite.Suite
	endpoint string
	keyID    string
	folderID string
}

func (suite *YCSuite) GetProvider(key string) *SignerVerifier {
	log.Printf("yckms://%s/%s", suite.endpoint, key)
	provider, err := LoadSignerVerifier(context.Background(), fmt.Sprintf("yckms://%s/%s", suite.endpoint, key))
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), provider)
	return provider
}

func (suite *YCSuite) SetupSuite() {
	suite.endpoint = os.Getenv("YC_ENDPOINT")
	suite.keyID = os.Getenv("KEY_ID")
	suite.folderID = os.Getenv("FOLDER_ID")
}

func (suite *YCSuite) TestGetProvider() {
	_ = suite.GetProvider(suite.keyID)
	_ = suite.GetProvider(fmt.Sprintf("folder/%s/keyname/cosign-test-key", suite.folderID))
}

func (suite *YCSuite) TestInvalidProvider() {
	provider, err := LoadSignerVerifier(context.Background(), fmt.Sprintf("yckms://%s/abc/dd", suite.endpoint))
	require.Error(suite.T(), err)
	require.Nil(suite.T(), provider)
}

func (suite *YCSuite) TestCreateKey() {
	provider := suite.GetProvider(fmt.Sprintf("folder/%s/keyname/cosign-e2e-test-key", suite.folderID))

	key, err := provider.CreateKey(context.Background(), Algorithm_ECDSA_NIST_P256_SHA_256)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key)
}

func (suite *YCSuite) TestSignVerify() {
	provider := suite.GetProvider(suite.keyID)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), sig)

	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *YCSuite) TestPublicKey() {
	provider := suite.GetProvider(suite.keyID)

	k, err := provider.PublicKey()
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), k)

	err = cryptoutils.ValidatePubKey(k)
	assert.Nil(suite.T(), err)
}

func (suite *YCSuite) TestTwoProviders() {
	provider1 := suite.GetProvider(suite.keyID)
	provider2 := suite.GetProvider(suite.keyID)

	data := []byte("mydata")
	sig, err := provider1.SignMessage(bytes.NewReader(data))
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), sig)

	err = provider2.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *YCSuite) TestBadSignature() {
	provider1 := suite.GetProvider(suite.keyID)
	provider2 := suite.GetProvider(suite.keyID)

	data := []byte("mydata")
	sig, err := provider1.SignMessage(bytes.NewReader(data))
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), sig)

	data = append(data, []byte("somedata")...)
	err = provider2.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Contains(suite.T(), err.Error(), "invalid signature when validating ASN.1 encoded signature")
}

func TestYC(t *testing.T) {
	suite.Run(t, new(YCSuite))
}
