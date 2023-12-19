//go:build !e2e
// +build !e2e

package akeyless

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"os"
	"testing"
)

type AkeylessSuite struct {
	suite.Suite
	akeylessClient *akeyless.V2ApiService
	token          string
	createdKeys    []string
}

func (suite *AkeylessSuite) SetupSuite() {
	accessId, ok := os.LookupEnv("ACCESS_ID")
	if ok {
		os.Setenv("AUTH.ACCESS_ID", accessId)
	}

	accessKey, ok := os.LookupEnv("ACCESS_KEY")
	if ok {
		os.Setenv("AUTH.ACCESS_KEY", accessKey)
	}

	accessType := "access_key"
	os.Setenv("AUTH.ACCESS_TYPE", accessType)

	suite.akeylessClient = akeyless.NewAPIClient(&akeyless.Configuration{
		Servers: []akeyless.ServerConfiguration{
			{
				URL: os.Getenv("AKEYLESS_URL"),
			},
		},
		DefaultHeader: map[string]string{
			"Akeyless-Transaction-Level": "1",
		},
	}).V2Api
	res, _, err := suite.akeylessClient.Auth(context.Background()).Body(akeyless.Auth{
		AccessId:   &accessId,
		AccessKey:  &accessKey,
		AccessType: &accessType,
	}).Execute()

	require.NoError(suite.T(), err)
	suite.token = res.GetToken()

	t := true
	m1 := int64(-1)
	for _, key := range []string{"createkey-dfc",
		"createkey-classic",
		"testsign-dfc",
		"testsign-classic",
		"testverify-dfc",
		"testverify-classic",
		"testverify-bad-dfc",
		"testverify-bad-classic",
		"testverify-bad1-dfc",
		"testverify-bad2-dfc",
		"testverify-bad1-classic",
		"testverify-bad2-classic",
		"testverify-versioning-classic",
		"testpubkey-classic",
	} {
		suite.akeylessClient.DeleteItem(context.Background()).Body(akeyless.DeleteItem{
			Accessibility:     nil,
			DeleteImmediately: &t,
			DeleteInDays:      &m1,
			Name:              key,
			Token:             &suite.token,
		}).Execute()
	}
}
func (suite *AkeylessSuite) TearDownSuite() {
	t := true
	m1 := int64(-1)
	for _, key := range suite.createdKeys {
		_, _, err := suite.akeylessClient.DeleteItem(context.Background()).Body(akeyless.DeleteItem{
			Accessibility:     nil,
			DeleteImmediately: &t,
			DeleteInDays:      &m1,
			Name:              key,
			Token:             &suite.token,
		}).Execute()
		assert.NoError(suite.T(), err)
	}
}

func (suite *AkeylessSuite) RotateClassicKey(ctx context.Context, key string) {
	_, _, err := suite.akeylessClient.RotateKey(ctx).Body(akeyless.RotateKey{
		Name:  key,
		Token: &suite.token,
	}).Execute()
	require.NoError(suite.T(), err)
}
func (suite *AkeylessSuite) GetProvider(key string, opts ...signature.RPCOption) *SignerVerifier {
	provider, err := LoadSignerVerifier(fmt.Sprintf("akeyless://%s", key), opts...)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), provider)

	return provider
}

func (suite *AkeylessSuite) TestProvider() {
	suite.GetProvider("provider")
}

func (suite *AkeylessSuite) GetProviderAndCreateKey(keyName string, keyAlg keyAlg, opts ...signature.RPCOption) (*SignerVerifier, crypto.PublicKey) {
	provider := suite.GetProvider(keyName, opts...)

	key, err := provider.CreateKey(context.Background(), string(keyAlg))
	require.NoError(suite.T(), err)
	assert.NotNil(suite.T(), key)

	suite.createdKeys = append(suite.createdKeys, keyName)

	return provider, key
}

func (suite *AkeylessSuite) TestCreateKey() {
	suite.GetProviderAndCreateKey("createkey-dfc", keyAlgRsa2048)

	suite.GetProviderAndCreateKey("createkey-classic", keyAlgEc256)
}

func (suite *AkeylessSuite) TestSignDfc() {
	provider, key := suite.GetProviderAndCreateKey("testsign-dfc", keyAlgRsa2048)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	require.NoError(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	verifier, _ := signature.LoadRSAPKCS1v15Verifier(key.(*rsa.PublicKey), crypto.SHA256)
	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}
func (suite *AkeylessSuite) TestSignClassic() {
	provider, key := suite.GetProviderAndCreateKey("testsign-classic", keyAlgEc521)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	require.NoError(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	verifier, _ := signature.LoadECDSAVerifier(key.(*ecdsa.PublicKey), crypto.SHA512)
	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *AkeylessSuite) TestVerifyDfc() {
	provider, _ := suite.GetProviderAndCreateKey("testverify-dfc", keyAlgRsa4096)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

func (suite *AkeylessSuite) TestVerifyClassic() {
	provider, _ := suite.GetProviderAndCreateKey("testverify-classic", keyAlgEc521)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data), options.WithCryptoSignerOpts(crypto.SHA512))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), options.WithCryptoSignerOpts(crypto.SHA512))
	assert.Nil(suite.T(), err)
}

func (suite *AkeylessSuite) TestVerifyBadDataDfc() {
	provider, _ := suite.GetProviderAndCreateKey("testverify-bad-dfc", keyAlgRsa2048)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	dataInvalid := []byte("mydata-invalid")
	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(dataInvalid))
	assert.ErrorContains(suite.T(), err, "verification error")
}

func (suite *AkeylessSuite) TestVerifyBadDataClassic() {
	provider, _ := suite.GetProviderAndCreateKey("testverify-bad-classic", keyAlgEc521)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data), options.WithCryptoSignerOpts(crypto.SHA512))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	dataInvalid := []byte("mydata-invalid")
	err = provider.VerifySignature(bytes.NewReader(sig), bytes.NewReader(dataInvalid), options.WithCryptoSignerOpts(crypto.SHA512))
	assert.ErrorContains(suite.T(), err, "signature verification failed")
}

func (suite *AkeylessSuite) TestBadSignatureDfc() {
	provider1, _ := suite.GetProviderAndCreateKey("testverify-bad1-dfc", keyAlgRsa2048)
	provider2, _ := suite.GetProviderAndCreateKey("testverify-bad2-dfc", keyAlgRsa2048)

	data := []byte("mydata")
	sig1, err := provider1.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig1)

	err = provider1.VerifySignature(bytes.NewReader(sig1), bytes.NewReader(data))
	assert.Nil(suite.T(), err)

	err = provider2.VerifySignature(bytes.NewReader(sig1), bytes.NewReader(data))
	assert.NotNil(suite.T(), err)
	assert.ErrorContains(suite.T(), err, "verification error")
}

func (suite *AkeylessSuite) TestBadSignatureClassic() {
	provider1, _ := suite.GetProviderAndCreateKey("testverify-bad1-classic", keyAlgEc521)
	provider2, _ := suite.GetProviderAndCreateKey("testverify-bad2-classic", keyAlgEc521)

	data := []byte("mydata")
	sig1, err := provider1.SignMessage(bytes.NewReader(data), options.WithCryptoSignerOpts(crypto.SHA512))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig1)

	err = provider1.VerifySignature(bytes.NewReader(sig1), bytes.NewReader(data), options.WithCryptoSignerOpts(crypto.SHA512))
	assert.Nil(suite.T(), err)

	err = provider2.VerifySignature(bytes.NewReader(sig1), bytes.NewReader(data), options.WithCryptoSignerOpts(crypto.SHA512))
	assert.NotNil(suite.T(), err)
	assert.ErrorContains(suite.T(), err, "signature verification failed")
}

func (suite *AkeylessSuite) TestClassicKeyVersioning() {
	providerLatest, _ := suite.GetProviderAndCreateKey("testverify-versioning-classic", keyAlgEc256)
	suite.RotateClassicKey(context.Background(), "testverify-versioning-classic")

	providerPinned := suite.GetProvider("testverify-versioning-classic/1")

	data := []byte("mydata")
	sig1, err := providerPinned.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig1)

	sig2, err := providerLatest.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig2)

	err = providerPinned.VerifySignature(bytes.NewReader(sig1), bytes.NewReader(data))
	assert.Nil(suite.T(), err)

	err = providerLatest.VerifySignature(bytes.NewReader(sig1), bytes.NewReader(data))
	assert.NotNil(suite.T(), err)
	assert.ErrorContains(suite.T(), err, "signature verification failed")

	err = providerLatest.VerifySignature(bytes.NewReader(sig2), bytes.NewReader(data))
	assert.Nil(suite.T(), err)

	err = providerPinned.VerifySignature(bytes.NewReader(sig2), bytes.NewReader(data))
	assert.NotNil(suite.T(), err)
	assert.ErrorContains(suite.T(), err, "signature verification failed")
}

func (suite *AkeylessSuite) TestPubKeyVerify() {
	provider, _ := suite.GetProviderAndCreateKey("testpubkey-classic", keyAlgEc256)

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

func (suite *AkeylessSuite) TestNoProvider() {
	provider, err := LoadSignerVerifier("akl://nonsense")
	require.Error(suite.T(), err)
	require.Nil(suite.T(), provider)
}

func TestVault(t *testing.T) {
	suite.Run(t, new(AkeylessSuite))
}
