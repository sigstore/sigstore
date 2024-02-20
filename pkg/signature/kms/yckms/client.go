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

// Package yckms implement the interface with Yandex Cloud kms service
package yckms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"
	"google.golang.org/grpc"

	asymkms "github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1/asymmetricsignature"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"github.com/yandex-cloud/go-sdk/iamkey"
)

func init() {
	sigkms.AddProvider(ReferenceScheme, func(ctx context.Context, keyResourceID string, _ crypto.Hash, _ ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		return LoadSignerVerifier(ctx, keyResourceID)
	})
}

const (
	cacheKey                   = "sign_key"
	ReferenceScheme            = "yckms://"
	EnvYcIAMToken              = "YC_IAM_TOKEN"
	EnvYcOAuthToken            = "YC_OAUTH_TOKEN"
	EnvYcServiceAccountKeyFile = "YC_SERVICE_ACCOUNT_KEY_FILE"
)

const (
	Algorithm_ECDSA_NIST_P256_SHA_256   = "ecdsa-nist-p256-sha256"
	Algorithm_ECDSA_NIST_P384_SHA_384   = "ecdsa-nist-p384-sha384"
	Algorithm_ECDSA_NIST_P521_SHA_512   = "ecdsa-nist-p521-sha512"
	Algorithm_RSA_2048_SIGN_PSS_SHA_256 = "rsa-2048-pss-sha256"
	Algorithm_RSA_2048_SIGN_PSS_SHA_384 = "rsa-2048-pss-sha384"
	Algorithm_RSA_2048_SIGN_PSS_SHA_512 = "rsa-2048-pss-sha512"
	Algorithm_RSA_3072_SIGN_PSS_SHA_256 = "rsa-3072-pss-sha256"
	Algorithm_RSA_3072_SIGN_PSS_SHA_384 = "rsa-3072-pss-sha384"
	Algorithm_RSA_3072_SIGN_PSS_SHA_512 = "rsa-3072-pss-sha512"
	Algorithm_RSA_4096_SIGN_PSS_SHA_256 = "rsa-4096-pss-sha256"
	Algorithm_RSA_4096_SIGN_PSS_SHA_384 = "rsa-4096-pss-sha384"
	Algorithm_RSA_4096_SIGN_PSS_SHA_512 = "rsa-4096-pss-sha512"
)

var algorithmMap = map[string]asymkms.AsymmetricSignatureAlgorithm{
	Algorithm_ECDSA_NIST_P256_SHA_256:   asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P256_SHA_256,
	Algorithm_ECDSA_NIST_P384_SHA_384:   asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P384_SHA_384,
	Algorithm_ECDSA_NIST_P521_SHA_512:   asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P521_SHA_512,
	Algorithm_RSA_2048_SIGN_PSS_SHA_256: asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_256,
	Algorithm_RSA_2048_SIGN_PSS_SHA_384: asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_384,
	Algorithm_RSA_2048_SIGN_PSS_SHA_512: asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_512,
	Algorithm_RSA_3072_SIGN_PSS_SHA_256: asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_256,
	Algorithm_RSA_3072_SIGN_PSS_SHA_384: asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_384,
	Algorithm_RSA_3072_SIGN_PSS_SHA_512: asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_512,
	Algorithm_RSA_4096_SIGN_PSS_SHA_256: asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_256,
	Algorithm_RSA_4096_SIGN_PSS_SHA_384: asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_384,
	Algorithm_RSA_4096_SIGN_PSS_SHA_512: asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_512,
}

type ycKmsClient struct {
	client    *ycsdk.SDK
	endpoint  string
	refString string
	folderID  string
	keyID     string
	keyName   string
	skCache   *ttlcache.Cache[string, ycSignatureKey]
}

type ycSignatureKey struct {
	SignatureKey *asymkms.AsymmetricSignatureKey
	Verifier     signature.Verifier
	HashFunc     crypto.Hash
}

var (
	errKMSReference = errors.New("kms specification should be in the format yckms://[ENDPOINT]/KEY_ID or yckms://[ENDPOINT]/folder/FOLDER_ID/keyname/KEY_NAME (ENDPOINT optional)")

	createRE = regexp.MustCompile(`^yckms://([^/]*)/folder/([^/]+)/keyname/([^/]+)$`)
	keyIdRE  = regexp.MustCompile(`^yckms://([^/]*)/([^/]+)$`)

	allREs = []*regexp.Regexp{createRE, keyIdRE}
)

// ValidReference returns a non-nil error if the reference string is invalid
func ValidReference(ref string) error {
	for _, re := range allREs {
		if re.MatchString(ref) {
			return nil
		}
	}
	return errKMSReference
}

// ParseReference parses a ycskms-scheme URI into its constituent parts.
func ParseReference(referenceStr string) (endpoint, keyID, folderID, keyName string, err error) {
	var v []string
	if createRE.MatchString(referenceStr) {
		v = createRE.FindStringSubmatch(referenceStr)
		endpoint, folderID, keyName = v[1], v[2], v[3]
		return
	}
	if keyIdRE.MatchString(referenceStr) {
		v = keyIdRE.FindStringSubmatch(referenceStr)
		endpoint, keyID = v[1], v[2]
		return
	}
	err = fmt.Errorf("invalid yckms format %q", referenceStr)
	return
}

func newYcKmsClient(ctx context.Context, referenceStr string, opts ...grpc.DialOption) (*ycKmsClient, error) {
	if err := ValidReference(referenceStr); err != nil {
		return nil, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	y := &ycKmsClient{
		refString: referenceStr,
		skCache:   nil,
	}
	var err error
	y.endpoint, y.keyID, y.folderID, y.keyName, err = ParseReference(referenceStr)
	if err != nil {
		return nil, err
	}
	var c ycsdk.Credentials
	if c, err = credentials(ctx); err != nil {
		return nil, err
	}
	var conf = ycsdk.Config{
		Credentials: c,
	}
	if y.endpoint != "" {
		conf.Endpoint = y.endpoint
	}
	y.client, err = ycsdk.Build(ctx, conf, opts...)
	if err != nil {
		return nil, fmt.Errorf("new yc kms client: %w", err)
	}

	y.skCache = ttlcache.New[string, ycSignatureKey](
		ttlcache.WithDisableTouchOnHit[string, ycSignatureKey](),
	)

	// prime the cache
	y.skCache.Get(cacheKey)
	return y, nil
}

func credentials(ctx context.Context) (ycsdk.Credentials, error) {
	if iamToken := os.Getenv(EnvYcIAMToken); iamToken != "" {
		log.Printf("Using IAM Token from '%s' environment variable as credentials", EnvYcIAMToken)
		return ycsdk.NewIAMTokenCredentials(iamToken), nil
	} else if oAuthToken := os.Getenv(EnvYcOAuthToken); oAuthToken != "" {
		log.Printf("Using OAuth Token from '%s' environment variable as credentials", EnvYcOAuthToken)
		return ycsdk.OAuthToken(oAuthToken), nil
	} else if serviceAccountKeyFile := os.Getenv(EnvYcServiceAccountKeyFile); serviceAccountKeyFile != "" {
		key, err := iamkey.ReadFromJSONFile(serviceAccountKeyFile)
		log.Printf("Using service account key file from '%s' environment variable as credentials", EnvYcServiceAccountKeyFile)
		if err != nil {
			return nil, fmt.Errorf("error reading service account key file: %w", err)
		}
		return ycsdk.ServiceAccountKey(key)
	} else {
		creds := ycsdk.InstanceServiceAccount()
		// Try to connect Compute Instance Metadata Service
		if _, err := creds.IAMToken(ctx); err == nil {
			log.Printf("Using compute instance service account token as credentials")
			return creds, nil
		}
	}
	return nil, fmt.Errorf("one of '%s', '%s', '%s' env variable not set", EnvYcIAMToken, EnvYcOAuthToken, EnvYcServiceAccountKeyFile)
}

func (y *ycKmsClient) getYcSignatureKey(ctx context.Context) (*ycSignatureKey, error) {
	getRequest := &asymkms.GetAsymmetricSignatureKeyRequest{
		KeyId: y.keyID,
	}
	asymKey, err := y.client.KMSAsymmetricSignature().AsymmetricSignatureKey().Get(ctx, getRequest)
	if err != nil {
		return nil, err
	}
	pubKey, err := y.fetchPublicKey(ctx)
	if err != nil {
		return nil, err
	}
	sk := ycSignatureKey{
		SignatureKey: asymKey,
	}
	switch asymKey.SignatureAlgorithm {
	case asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_256,
		asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_256,
		asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_256:
		sk.Verifier, err = signature.LoadRSAPSSVerifier(pubKey.(*rsa.PublicKey), crypto.SHA256, nil)
		sk.HashFunc = crypto.SHA256
	case asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_384,
		asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_384,
		asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_384:
		sk.Verifier, err = signature.LoadRSAPSSVerifier(pubKey.(*rsa.PublicKey), crypto.SHA384, nil)
		sk.HashFunc = crypto.SHA384
	case asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_512,
		asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_512,
		asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_512:
		sk.Verifier, err = signature.LoadRSAPSSVerifier(pubKey.(*rsa.PublicKey), crypto.SHA512, nil)
		sk.HashFunc = crypto.SHA512
	case asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P256_SHA_256:
		sk.Verifier, err = signature.LoadECDSAVerifier(pubKey.(*ecdsa.PublicKey), crypto.SHA256)
		sk.HashFunc = crypto.SHA256
	case asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P384_SHA_384:
		sk.Verifier, err = signature.LoadECDSAVerifier(pubKey.(*ecdsa.PublicKey), crypto.SHA384)
		sk.HashFunc = crypto.SHA384
	case asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P521_SHA_512:
		sk.Verifier, err = signature.LoadECDSAVerifier(pubKey.(*ecdsa.PublicKey), crypto.SHA512)
		sk.HashFunc = crypto.SHA512
	default:
		return nil, errors.New("unknown algorithm specified by KMS")
	}
	if err != nil {
		return nil, fmt.Errorf("initializing internal verifier: %w", err)
	}
	return &sk, err
}

func (y *ycKmsClient) getHashFunc(ctx context.Context) (crypto.Hash, error) {
	sk, err := y.getSK(ctx)
	if err != nil {
		return 0, err
	}
	return sk.HashFunc, nil
}

func (y *ycKmsClient) getSK(ctx context.Context) (*ycSignatureKey, error) {
	var lerr error
	loader := ttlcache.LoaderFunc[string, ycSignatureKey](
		func(c *ttlcache.Cache[string, ycSignatureKey], key string) *ttlcache.Item[string, ycSignatureKey] {
			var k *ycSignatureKey
			k, lerr = y.getYcSignatureKey(ctx)
			if lerr == nil {
				return c.Set(cacheKey, *k, time.Second*300)
			}
			return nil
		},
	)

	item := y.skCache.Get(cacheKey, ttlcache.WithLoader[string, ycSignatureKey](loader))
	if lerr == nil {
		sk := item.Value()
		return &sk, nil
	}
	return nil, lerr
}

func (y *ycKmsClient) createKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	if y.folderID == "" || y.keyName == "" {
		return nil, errors.New("generate yckms key specification should be in the format yckms://[ENDPOINT]/folder/FOLDER/keyname/KEYNAME")
	}
	if _, ok := algorithmMap[algorithm]; !ok {
		return nil, errors.New("unknown algorithm requested")
	}
	createKeyRequest := &asymkms.CreateAsymmetricSignatureKeyRequest{
		SignatureAlgorithm: algorithmMap[algorithm],
		FolderId:           y.folderID,
		Name:               y.keyName,
		Description:        "Created by sigstore",
	}
	op, err := y.client.WrapOperation(y.client.KMSAsymmetricSignature().AsymmetricSignatureKey().Create(ctx, createKeyRequest))
	if err != nil {
		return nil, fmt.Errorf("yckms key create error: %w", err)
	}
	err = op.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("yckms key create error: %w", err)
	}
	resp, err := op.Response()
	if err != nil {
		return nil, fmt.Errorf("yckms key create error: %w", err)
	}
	keyID := resp.(*asymkms.AsymmetricSignatureKey).Id
	log.Printf("generated yckms KEY_ID: '%s'", keyID)
	getPubKeyRequest := &asymkms.AsymmetricGetPublicKeyRequest{
		KeyId: keyID,
	}
	pubKey, err := y.client.KMSAsymmetricSignatureCrypto().AsymmetricSignatureCrypto().GetPublicKey(ctx, getPubKeyRequest)
	if err != nil {
		return nil, err
	}
	return cryptoutils.UnmarshalPEMToPublicKey([]byte(pubKey.GetPublicKey()))
}

func (y *ycKmsClient) verify(ctx context.Context, sig, message io.Reader, opts ...signature.VerifyOption) error {
	sk, err := y.getSK(ctx)
	if err != nil {
		return err
	}
	return sk.Verifier.VerifySignature(sig, message, opts...)
}

func (y *ycKmsClient) sign(ctx context.Context, digest []byte, _ crypto.Hash) ([]byte, error) {
	signHashRequest := &asymkms.AsymmetricSignHashRequest{
		KeyId: y.keyID,
		Hash:  digest,
	}
	signResponse, err := y.client.KMSAsymmetricSignatureCrypto().AsymmetricSignatureCrypto().SignHash(ctx, signHashRequest)
	if err != nil {
		return nil, fmt.Errorf("calling YC KMS AsymmetricSignatureCrypto.SignHash: %w", err)
	}
	return signResponse.Signature, nil
}

func (y *ycKmsClient) fetchPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	getPubKeyRequest := &asymkms.AsymmetricGetPublicKeyRequest{
		KeyId: y.keyID,
	}
	pubKey, err := y.client.KMSAsymmetricSignatureCrypto().AsymmetricSignatureCrypto().GetPublicKey(ctx, getPubKeyRequest)
	if err != nil {
		return nil, err
	}
	return cryptoutils.UnmarshalPEMToPublicKey([]byte(pubKey.GetPublicKey()))
}
