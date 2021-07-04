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

package azure

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"

	kvauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/to"
)

type KMS struct {
	client    *keyvault.BaseClient
	vaultURL  string
	vaultName string
	keyName   string
}

var (
	errAzureReference = errors.New("kms specification should be in the format azurekms://[VAULT_NAME][VAULT_URL]/[KEY_NAME]")

	referenceRegex = regexp.MustCompile(`^azurekms://([^/]+)/([^/]+)?$`)
)

const ReferenceScheme = "azurekms://"

func ValidReference(ref string) error {
	if !referenceRegex.MatchString(ref) {
		return errAzureReference
	}
	return nil
}

func parseReference(resourceID string) (vaultURL, vaultName, keyName string, err error) {
	v := referenceRegex.FindStringSubmatch(resourceID)
	if len(v) != 3 {
		err = errors.Errorf("invalid azurekms format %q", resourceID)
		return
	}

	vaultURL = fmt.Sprintf("https://%s/", v[1])
	vaultName, keyName = strings.Split(v[1], ".")[0], v[2]
	return
}

func NewAzureKMS(ctx context.Context, keyResourceID string) (*KMS, error) {
	vaultURL, vaultName, keyName, err := parseReference(keyResourceID)
	if err != nil {
		return nil, err
	}

	azureTentatID := os.Getenv("AZURE_TENANT_ID")
	if azureTentatID == "" {
		return nil, errors.New("AZURE_TENANT_ID is not set")
	}

	azureClientID := os.Getenv("AZURE_CLIENT_ID")
	if azureClientID == "" {
		return nil, errors.New("AZURE_CLIENT_ID is not set")
	}

	azureClientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	if azureClientSecret == "" {
		return nil, errors.New("AZURE_CLIENT_SECRET is not set")
	}

	client, err := getKeysClient()
	if err != nil {
		return nil, errors.Wrap(err, "new azure kms client")
	}

	return &KMS{
		client:    &client,
		vaultURL:  vaultURL,
		vaultName: vaultName,
		keyName:   keyName,
	}, nil
}

func (a *KMS) Sign(ctx context.Context, rawPayload []byte) (signature, signed []byte, err error) {
	hash := sha256.Sum256(rawPayload)
	signed = hash[:]

	params := keyvault.KeySignParameters{
		Algorithm: keyvault.ES256,
		Value:     to.StringPtr(base64.RawURLEncoding.EncodeToString(signed)),
	}

	result, err := a.client.Sign(ctx, a.vaultURL, a.keyName, "", params)
	if err != nil {
		return nil, nil, errors.Wrap(err, "signing the payload")
	}

	decResult, err := base64.RawURLEncoding.DecodeString(*result.Result)
	if err != nil {
		return nil, nil, errors.Wrap(err, "decoding the result")
	}

	return decResult, signed, nil
}

func (a *KMS) Verify(ctx context.Context, payload, signature []byte) error {
	hash := sha256.Sum256(payload)

	params := keyvault.KeyVerifyParameters{
		Algorithm: keyvault.ES256,
		Digest:    to.StringPtr(base64.RawURLEncoding.EncodeToString(hash[:])),
		Signature: to.StringPtr(base64.RawURLEncoding.EncodeToString(signature)),
	}

	result, err := a.client.Verify(ctx, a.vaultURL, a.keyName, "", params)
	if err != nil {
		return errors.Wrap(err, "verify")
	}

	if !*result.Value {
		return errors.New("Failed vault verification")
	}

	return nil
}

func (a *KMS) CreateKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	_, err := a.PublicKey(ctx)
	if err == nil {
		fmt.Printf("Key %s already exists in Azure KMS, skipping creation.\n", a.vaultName)
		pub, err := a.ECDSAPublicKey(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "retrieving public key")
		}

		return pub, nil
	}

	_, err = a.client.CreateKey(
		ctx,
		a.vaultURL,
		a.keyName,
		keyvault.KeyCreateParameters{
			KeyAttributes: &keyvault.KeyAttributes{
				Enabled: to.BoolPtr(true),
			},
			KeySize: to.Int32Ptr(2048),
			KeyOps: &[]keyvault.JSONWebKeyOperation{
				keyvault.Sign,
				keyvault.Verify,
			},
			Kty: keyvault.EC,
			Tags: map[string]*string{
				"use": to.StringPtr("sigstore"),
			},
		})
	if err != nil {
		return nil, err
	}
	fmt.Printf("Created key %s in Azure KMS\n", a.keyName)

	pub, err := a.ECDSAPublicKey(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "retrieving public key")
	}

	return pub, nil
}

func (a *KMS) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	key, err := a.client.GetKey(ctx, a.vaultURL, a.vaultName, "")
	if err != nil {
		return nil, errors.Wrap(err, "public key")
	}

	jwkJSON, err := json.Marshal(*key.Key)
	if err != nil {
		return nil, errors.Wrap(err, "encoding the jsonWebKey")
	}

	jwk := jose.JSONWebKey{}
	err = jwk.UnmarshalJSON(jwkJSON)
	if err != nil {
		return nil, errors.Wrap(err, "decoding the jsonWebKey")
	}

	return jwk.Key, nil
}

func (a *KMS) ECDSAPublicKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	k, err := a.PublicKey(ctx)
	if err != nil {
		return nil, err
	}

	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		if err != nil {
			return nil, fmt.Errorf("public key was not ECDSA: %#v", k)
		}
	}

	return pub, nil
}

func getKeysClient() (keyvault.BaseClient, error) {
	keyClient := keyvault.New()

	authorizer, err := kvauth.NewAuthorizerFromEnvironment()
	if err != nil {
		return keyvault.BaseClient{}, err
	}

	keyClient.Authorizer = authorizer
	keyClient.AddToUserAgent("sigstore")

	return keyClient, nil
}
