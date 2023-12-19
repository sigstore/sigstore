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

// Package akeyless implement the interface with Akeyless vaultless platform service
package akeyless

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/jellydator/ttlcache/v3"
	"github.com/sigstore/sigstore/pkg/signature"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/spf13/viper"
	"os"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"time"
)

type keyAlg string

//nolint:revive
const (
	keyAlgRsa2048 keyAlg = "RSA2048"
	keyAlgRsa3072 keyAlg = "RSA3072"
	keyAlgRsa4096 keyAlg = "RSA4096"
	keyAlgEc256   keyAlg = "EC256"
	keyAlgEc384   keyAlg = "EC384"
	keyAlgEc521   keyAlg = "EC521"

	configPath        = "config_path"
	defaultConfigPath = "/var/akeyless/conf/"

	akeylessUrl = "akeyless_url"

	cacheKey = "akeyless_signer"
	cacheTtl = 300 * time.Second

	ReferenceScheme = "akeyless://"
)

func init() {
	sigkms.AddProvider(ReferenceScheme, func(ctx context.Context, keyResourceID string, _ crypto.Hash, opts ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		return LoadSignerVerifier(keyResourceID)
	})
}

var referenceRegex = regexp.MustCompile(`^akeyless://(.+?)(/\d+)?$`)

func (alg keyAlg) isRsa() bool {
	return alg == keyAlgRsa2048 || alg == keyAlgRsa3072 || alg == keyAlgRsa4096
}

func extractApiError(err error) error {
	var apiErr akeyless.GenericOpenAPIError
	errors.As(err, &apiErr)

	model := apiErr.Model()
	if model != nil {
		if errBody, ok := model.(akeyless.JSONError); ok {
			return errors.New(errBody.GetError())
		}
	}

	return err
}

var supportedHashFuncs = []crypto.Hash{
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
}
var supportedAlgorithms = []string{
	string(keyAlgRsa2048),
	string(keyAlgRsa3072),
	string(keyAlgRsa4096),

	string(keyAlgEc256),
	string(keyAlgEc384),
	string(keyAlgEc521),
}

type akeylessClient struct {
	keyName           string
	keyVersion        int32
	akylessApiClient  *akeyless.V2ApiService
	authData          *Auth
	apiToken          string
	useRsaClassicKeys bool
	splitLevel        int64
	keyCache          *ttlcache.Cache[string, crypto.PublicKey]
}

// ValidReference returns a non-nil error if the reference string is invalid
func ValidReference(ref string) error {
	if !referenceRegex.MatchString(ref) {
		return errors.New("kms specification should be in the format akeyless://[KEY_NAME]/[VERSION (Optional)]")
	}
	return nil
}

// The key version can be optionally provided for akeyless "classic" (non dfc) keys
// If provided, all key operations will specify this version.
// If not provided, the key operations will use the latest key version by default.
func parseReference(resourceID string) (keyName string, keyVersion int32, err error) {
	if isIDValid := referenceRegex.MatchString(resourceID); !isIDValid {
		err = fmt.Errorf("invalid akeyless format %q", resourceID)
		return
	}

	m := referenceRegex.FindStringSubmatch(resourceID)

	keyName = m[1]
	verPart := m[2]
	if len(verPart) != 0 {
		kv, err := strconv.ParseInt(verPart[1:], 10, 32)
		if err != nil {
			return "", 0, fmt.Errorf("failed to parse key version: %s", verPart)
		}
		keyVersion = int32(kv)
	}

	return
}

func newAkeylessClient(keyResourceID string) (*akeylessClient, error) {
	if err := ValidReference(keyResourceID); err != nil {
		return nil, err
	}

	keyName, keyVersion, err := parseReference(keyResourceID)
	if err != nil {
		return nil, err
	}

	viper.SetDefault(akeylessUrl, "https://api.akeyless.io")
	viper.SetDefault("split_level", 3)

	cPath := os.Getenv(configPath)
	if cPath == "" {
		if runtime.GOOS == "windows" {
			homedir, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("failed to get user home dir: %w", err)
			}
			cPath = path.Join(homedir, ".akeyless", "conf")
		} else {
			cPath = defaultConfigPath
		}
	}

	viper.AddConfigPath(cPath)
	viper.SetConfigName("sigstore.conf")
	viper.SetConfigType("toml")

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		var viperErrpr viper.ConfigFileNotFoundError
		if !errors.As(err, &viperErrpr) {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	splitLevel := viper.GetInt64("split_level")

	useRsaClassicKeys := viper.GetBool("rsa_classic_keys")

	authData := &Auth{
		AccessId:   viper.GetString("auth.access_id"),
		AccessType: viper.GetString("auth.access_type"),
		AccessKey:  viper.GetString("auth.access_key"),
	}

	gwUrl := viper.GetString("akeyless_url")

	apiClient := akeyless.NewAPIClient(&akeyless.Configuration{
		Servers: []akeyless.ServerConfiguration{
			{
				URL: gwUrl,
			},
		},
		DefaultHeader: map[string]string{
			"Akeyless-Transaction-Level": "1",
		},
	}).V2Api

	return &akeylessClient{
		akylessApiClient:  apiClient,
		authData:          authData,
		keyName:           keyName,
		keyVersion:        keyVersion,
		splitLevel:        splitLevel,
		useRsaClassicKeys: useRsaClassicKeys,
		keyCache: ttlcache.New[string, crypto.PublicKey](
			ttlcache.WithDisableTouchOnHit[string, crypto.PublicKey](),
		),
	}, nil
}

type Auth struct {
	AccessId   string
	AccessType string
	AccessKey  string
}

func (cl *akeylessClient) getDefaultAndSupportedHashFunctions(ctx context.Context) (crypto.Hash, []crypto.Hash, error) {
	pub, err := cl.public(ctx)
	if err != nil {
		return 0, nil, err
	}
	if ecKey, ok := pub.(*ecdsa.PublicKey); ok {
		switch ecKey.Curve {
		case elliptic.P256():
			return crypto.SHA256, []crypto.Hash{crypto.SHA256}, nil
		case elliptic.P384():
			return crypto.SHA384, []crypto.Hash{crypto.SHA384}, nil
		case elliptic.P521():
			return crypto.SHA512, []crypto.Hash{crypto.SHA512}, nil
		default:
			return 0, []crypto.Hash{0}, fmt.Errorf("unsupported key size: %s", ecKey.Params().Name)
		}
	} else {
		return crypto.SHA256, supportedHashFuncs, nil
	}
}

func (cl *akeylessClient) Login(ctx context.Context) error {
	if cl.authData.AccessId == "" {
		return fmt.Errorf("auth failed: missing access id")
	}

	if cl.authData.AccessType == "" {
		return fmt.Errorf("auth failed: missing access type")
	}

	authBody := akeyless.Auth{
		AccessId:   &cl.authData.AccessId,
		AccessKey:  &cl.authData.AccessKey,
		AccessType: &cl.authData.AccessType,
	}

	out, _, err := cl.akylessApiClient.Auth(ctx).Body(authBody).Execute()
	if err != nil {
		return fmt.Errorf("auth failed: %w", extractApiError(err))
	}

	cl.apiToken = *out.Token

	return nil
}
func (cl *akeylessClient) sign(ctx context.Context, message []byte, alg crypto.Hash, opts ...signature.SignOption) ([]byte, error) {
	if err := cl.Login(ctx); err != nil {
		return nil, err
	}

	pub, err := cl.public(ctx)
	if err != nil {
		return nil, err
	}

	msg := base64.StdEncoding.EncodeToString(message)
	var resBase64 string

	t := true
	if _, ok := pub.(*ecdsa.PublicKey); ok {
		signOut, _, err := cl.akylessApiClient.SignEcDsa(ctx).Body(akeyless.SignEcDsa{
			KeyName:   &cl.keyName,
			Token:     &cl.apiToken,
			Version:   &cl.keyVersion,
			Prehashed: &t,
			Message:   msg,
		}).Execute()
		if err != nil {
			return nil, extractApiError(err)
		}

		resBase64 = signOut.GetResult()
	} else {
		var ver int32
		if cl.useRsaClassicKeys {
			ver = cl.keyVersion
		}

		inf := "base64"
		hf := alg.String()

		signOut, _, err := cl.akylessApiClient.SignPKCS1(ctx).Body(akeyless.SignPKCS1{
			KeyName:      &cl.keyName,
			Token:        &cl.apiToken,
			Prehashed:    &t,
			InputFormat:  &inf,
			HashFunction: &hf,
			Version:      &ver,
			Message:      msg,
		}).Execute()
		if err != nil {
			return nil, extractApiError(err)
		}

		resBase64 = signOut.GetResult()
	}

	res, err := base64.StdEncoding.DecodeString(resBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	return res, nil
}
func (cl *akeylessClient) verify(ctx context.Context, sig, digest []byte, alg crypto.Hash, opts ...signature.VerifyOption) error {

	if err := cl.Login(ctx); err != nil {
		return err
	}

	pub, err := cl.public(ctx)
	if err != nil {
		return err
	}

	msgE := base64.StdEncoding.EncodeToString(digest)
	sigE := base64.StdEncoding.EncodeToString(sig)
	t := true

	if _, ok := pub.(*ecdsa.PublicKey); ok {
		_, _, err := cl.akylessApiClient.VerifyEcDsa(ctx).Body(akeyless.VerifyEcDsa{
			KeyName:   &cl.keyName,
			Token:     &cl.apiToken,
			Message:   msgE,
			Signature: sigE,
			Prehashed: &t,
			Version:   &cl.keyVersion,
		}).Execute()
		if err != nil {
			return extractApiError(err)
		}
	} else {
		var ver int32
		if cl.useRsaClassicKeys {
			ver = cl.keyVersion
		}

		inf := "base64"
		hf := alg.String()

		_, _, err := cl.akylessApiClient.VerifyPKCS1(ctx).Body(akeyless.VerifyPKCS1{
			KeyName:      cl.keyName,
			Token:        &cl.apiToken,
			Message:      msgE,
			Signature:    sigE,
			Prehashed:    &t,
			InputFormat:  &inf,
			HashFunction: &hf,
			Version:      &ver,
		}).Execute()
		if err != nil {
			return extractApiError(err)
		}
	}

	return nil
}
func (cl *akeylessClient) public(ctx context.Context) (crypto.PublicKey, error) {
	var err error
	loader := ttlcache.LoaderFunc[string, crypto.PublicKey](
		func(c *ttlcache.Cache[string, crypto.PublicKey], key string) *ttlcache.Item[string, crypto.PublicKey] {
			var pubkey crypto.PublicKey
			pubkey, err = cl.fetchPublicKey(ctx)
			if err == nil {
				item := c.Set(key, pubkey, cacheTtl)
				return item
			}
			return nil
		},
	)

	item := cl.keyCache.Get(cacheKey, ttlcache.WithLoader[string, crypto.PublicKey](loader))
	if err != nil {
		return nil, err
	}

	if item == nil {
		return nil, fmt.Errorf("unable to retrieve an item from the cache by the provided key")
	}

	return item.Value(), nil
}
func (cl *akeylessClient) fetchPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	if err := cl.Login(ctx); err != nil {
		return nil, err
	}

	key, _, err := cl.akylessApiClient.DescribeItem(ctx).Body(akeyless.DescribeItem{
		Name:  cl.keyName,
		Token: &cl.apiToken,
	}).Execute()
	if err != nil {
		return nil, extractApiError(err)
	}

	itemType := key.GetItemType()

	if keyAlg(itemType).isRsa() {
		if cl.keyVersion > 0 {
			return nil, fmt.Errorf("versioning is only supported for classic keys")
		}
		pubVal := key.GetPublicValue()
		pubKeyDer, err := base64.StdEncoding.DecodeString(pubVal)
		if err != nil {
			return nil, fmt.Errorf("failed to decode dfc rsa public key: %w", err)
		}

		pub, err := x509.ParsePKIXPublicKey(pubKeyDer)
		if err != nil {
			// fallback to try pkcs1
			pubRsa, err := x509.ParsePKCS1PublicKey(pubKeyDer)
			if err != nil {
				return nil, errors.New("failed to parse public key")
			}
			pub = pubRsa
		}

		return pub, nil
	} else if itemType == "CLASSIC_KEY" {
		t := true
		exportClassicKeyOut, _, err := cl.akylessApiClient.ExportClassicKey(ctx).Body(akeyless.ExportClassicKey{
			ExportPublicKey: &t,
			Name:            cl.keyName,
			Token:           &cl.apiToken,
			Version:         &cl.keyVersion,
		}).Execute()
		if err != nil {
			return nil, extractApiError(err)
		}

		pubKeyPem := exportClassicKeyOut.GetKey()
		b, _ := pem.Decode([]byte(pubKeyPem))
		if b == nil {
			return nil, fmt.Errorf("failed to parse public key")
		}

		pub, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			// fallback to try pkcs1
			pubRsa, err := x509.ParsePKCS1PublicKey(b.Bytes)
			if err != nil {
				return nil, errors.New("failed to parse public key")
			}
			pub = pubRsa
		}

		return pub, nil
	} else {
		return nil, fmt.Errorf("invalid item type %s", itemType)
	}

}
func (cl *akeylessClient) createKey(ctx context.Context, keyAlg keyAlg) (crypto.PublicKey, error) {
	if err := cl.Login(ctx); err != nil {
		return nil, err
	}

	if keyAlg.isRsa() && !cl.useRsaClassicKeys {
		_, _, err := cl.akylessApiClient.CreateKey(ctx).Body(akeyless.CreateKey{
			Alg:        string(keyAlg),
			Name:       cl.keyName,
			SplitLevel: &cl.splitLevel,
			Token:      &cl.apiToken,
		}).Execute()
		if err != nil {
			return nil, extractApiError(err)
		}

		return cl.public(ctx)
	} else {
		_, _, err := cl.akylessApiClient.CreateClassicKey(ctx).Body(akeyless.CreateClassicKey{
			Alg:   string(keyAlg),
			Name:  cl.keyName,
			Token: &cl.apiToken,
		}).Execute()
		if err != nil {
			return nil, extractApiError(err)
		}

		return cl.public(ctx)
	}
}
