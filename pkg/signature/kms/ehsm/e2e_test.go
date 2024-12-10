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

package ehsm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/sigstore/sigstore/pkg/signature"

	ehsm "github.com/intel/ehsm/sdk/go"
)

type EhsmSuite struct {
	suite.Suite
	ehsmclient *ehsm.Client
}

func (suite *EhsmSuite) GetProvider(key string, opts ...signature.RPCOption) *SignerVerifier {
	provider, err := LoadSignerVerifier(fmt.Sprintf("ehsm://%s", key), crypto.SHA256, opts...)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), provider)
	return provider
}

func (suite *EhsmSuite) SetupSuite() {
	var err error
	suite.ehsmclient, err = ehsm.NewClient()

	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), suite.ehsmclient)
}

func (suite *EhsmSuite) TestProvider() {
	suite.GetProvider("provider")
}

func (suite *EhsmSuite) TestCreateKey() {
	provider := suite.GetProvider("createkey")
	filename := fmt.Sprintf("./%s", "createkey")
	key, err := provider.CreateKey(context.Background(), EH_EC_P256)
	keyid, errkeid := ioutil.ReadFile(filename)
	assert.Nil(suite.T(), err)
	assert.Nil(suite.T(), errkeid)
	assert.NotNil(suite.T(), key)
	assert.NotNil(suite.T(), keyid)
}

func (suite *EhsmSuite) TestSign() {
	provider := suite.GetProvider("testsign")

	key, err := provider.CreateKey(context.Background(), EH_EC_P256)
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

func (suite *EhsmSuite) TestInvalidPublicKey() {
	var provider *SignerVerifier
	var err error
	assert.NotPanics(suite.T(), func() {
		provider, _ = LoadSignerVerifier("ehsm://pki_int", crypto.SHA256)
		_, err = provider.client.fetchPublicKey()
	})
	assert.NotNil(suite.T(), err)
}

func (suite *EhsmSuite) TestPubKeyVerify() {
	provider := suite.GetProvider("testsign")

	key, err := provider.CreateKey(context.Background(), EH_EC_P256)
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

func (suite *EhsmSuite) TestCryptoSigner() {
	provider := suite.GetProvider("testsign")

	key, err := provider.CreateKey(context.Background(), EH_EC_P256)
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

func (suite *EhsmSuite) TestVerify() {
	provider := suite.GetProvider("testverify")

	key, err := provider.CreateKey(context.Background(), EH_EC_P256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *EhsmSuite) TestVerifyBadData() {
	provider := suite.GetProvider("testverify")

	key, err := provider.CreateKey(context.Background(), EH_EC_P256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	dataInvalid := []byte("mydata-invalid")
	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(dataInvalid))
	assert.Contains(suite.T(), err.Error(), "failed ehsm verification")
}

func (suite *EhsmSuite) TestBadSignature() {
	provider1 := suite.GetProvider("testverify1")
	provider2 := suite.GetProvider("testverify2")

	key1, err := provider1.CreateKey(context.Background(), EH_EC_P256)
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), key1)

	key2, err := provider2.CreateKey(context.Background(), EH_EC_P256)
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
	assert.Contains(suite.T(), err.Error(), "failed ehsm verification")
}

func (suite *EhsmSuite) TestNoProvider() {
	provider, err := LoadSignerVerifier("eh://nonsense", crypto.Hash(0))
	require.Error(suite.T(), err)
	require.Nil(suite.T(), provider)
}

func TestEhsm(t *testing.T) {
	suite.Run(t, new(EhsmSuite))
}
