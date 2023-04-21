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

package aws

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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go/service/kms"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

type AWSSuite struct {
	suite.Suite
	endpoint string
}

// Address intermittent failure in issue #1110
type Issue1110Error struct{}

func (i Issue1110Error) IsErrorRetryable(err error) aws.Ternary {
	if err != nil && err.Error() == "use of closed network connection" {
		return aws.BoolTernary(true)
	}
	return aws.UnknownTernary
}

func (suite *AWSSuite) GetProvider(key string) *SignerVerifier {
	provider, err := LoadSignerVerifier(context.Background(), fmt.Sprintf("awskms://%s/%s", suite.endpoint, key),
		config.WithRetryer(func() aws.Retryer {
			return retry.NewStandard(func(opts *retry.StandardOptions) {
				opts.Retryables = append(opts.Retryables, Issue1110Error{})
			})
		}))
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), provider)
	return provider
}

func (suite *AWSSuite) SetupSuite() {
	suite.endpoint = os.Getenv("AWS_ENDPOINT")
}

func (suite *AWSSuite) TestGetProvider() {
	_ = suite.GetProvider("alias/provider")
	_ = suite.GetProvider("1234abcd-12ab-34cd-56ef-1234567890ab")
}

func (suite *AWSSuite) TestInvalidProvider() {
	provider, err := LoadSignerVerifier(context.Background(), fmt.Sprintf("awskms://%s/nonsense", suite.endpoint))
	require.Error(suite.T(), err)
	require.Nil(suite.T(), provider)
}

func (suite *AWSSuite) TestCreateKey() {
	provider := suite.GetProvider("alias/provider")

	key, err := provider.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key)

	key2, err := provider.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key)

	// Subsequent call should produce same key
	assert.Equal(suite.T(), key, key2)
}

func (suite *AWSSuite) TestCreateKeyByID() {
	provider := suite.GetProvider("1234abcd-12ab-34cd-56ef-1234567890ab")

	// CreateKey can only work with aliases, not IDs
	key, err := provider.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
	require.Error(suite.T(), err)
	require.Nil(suite.T(), key)
}

func (suite *AWSSuite) TestSign() {
	provider := suite.GetProvider("alias/TestSign")

	key, err := provider.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), sig)

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
	require.True(suite.T(), ok, fmt.Sprintf("expected type ecdsa, got type %T", k))

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
	require.True(suite.T(), ok, fmt.Sprintf("expected type ecdsa, got: %T", k))

	verifier, _ := signature.LoadECDSAVerifier(pubKey, crypto.SHA256)
	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *AWSSuite) TestVerify() {
	provider := suite.GetProvider("alias/TestVerify")

	key, err := provider.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), sig)

	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)

	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), options.WithRemoteVerification(true))
	assert.Nil(suite.T(), err)
}

func (suite *AWSSuite) TestTwoProviders() {
	provider1 := suite.GetProvider("alias/TestTwoProviders")
	provider2 := suite.GetProvider("alias/TestTwoProviders")

	key, err := provider1.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider1.SignMessage(bytes.NewReader(data))
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), sig)

	err = provider2.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *AWSSuite) TestBadSignature() {
	provider1 := suite.GetProvider("alias/TestBadSignature1")
	provider2 := suite.GetProvider("alias/TestBadSignature2")

	key1, err := provider1.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key1)

	key2, err := provider2.CreateKey(context.Background(), awskms.CustomerMasterKeySpecEccNistP256)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), key2)

	data := []byte("mydata")
	sig, err := provider1.SignMessage(bytes.NewReader(data))
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), sig)

	err = provider2.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Contains(suite.T(), err.Error(), "invalid signature when validating ASN.1 encoded signature")

	err = provider2.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), options.WithRemoteVerification(true))
	assert.Contains(suite.T(), err.Error(), "KMSInvalidSignatureException")
}

func (suite *AWSSuite) TestKeyTypes() {
	for _, cmkSpec := range []string{
		awskms.CustomerMasterKeySpecRsa2048,
		awskms.CustomerMasterKeySpecRsa3072,
		awskms.CustomerMasterKeySpecRsa4096,
		awskms.CustomerMasterKeySpecEccNistP256,
		awskms.CustomerMasterKeySpecEccNistP384,
		awskms.CustomerMasterKeySpecEccNistP521,
		// awskms.CustomerMasterKeySpecEccSecgP256k1, // unsupported by localstack at the moment
	} {
		suite.T().Run(fmt.Sprintf("KeyType-%s", cmkSpec), func(t *testing.T) {
			provider := suite.GetProvider("alias/" + cmkSpec)
			key, err := provider.CreateKey(context.Background(), cmkSpec)
			require.Nil(suite.T(), err)
			require.NotNil(suite.T(), key)

			data := []byte("mydata")
			sig, err := provider.SignMessage(bytes.NewReader(data))
			require.Nil(suite.T(), err)
			require.NotNil(suite.T(), sig)

			err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
			assert.Nil(suite.T(), err)
		})
	}
}

func (suite *AWSSuite) TestCancelContext() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	provider := suite.GetProvider("alias/TestCancelContext")
	key, err := provider.CreateKey(ctx, awskms.CustomerMasterKeySpecEccNistP256)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), context.Canceled.Error())
	assert.Nil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data), options.WithContext(ctx))
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), context.Canceled.Error())
	assert.Nil(suite.T(), sig)

	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), options.WithContext(ctx))
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), context.Canceled.Error())
}

func TestAWS(t *testing.T) {
	suite.Run(t, new(AWSSuite))
}
