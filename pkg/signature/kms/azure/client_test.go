//
// Copyright 2022 The Sigstore Authors.
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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/jellydator/ttlcache/v3"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

type testKVClient struct {
	key azkeys.JSONWebKey
}

func (c *testKVClient) CreateKey(_ context.Context, _ string, _ azkeys.CreateKeyParameters, _ *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
	key, err := generatePublicKey("EC")
	if err != nil {
		return azkeys.CreateKeyResponse{}, err
	}
	c.key = key

	return azkeys.CreateKeyResponse{
		KeyBundle: azkeys.KeyBundle{
			Key: &key,
		},
	}, nil
}

func (c *testKVClient) GetKey(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	return azkeys.GetKeyResponse{
		KeyBundle: azkeys.KeyBundle{
			Key: &c.key,
		},
	}, nil
}

func (c *testKVClient) Sign(_ context.Context, _, _ string, _ azkeys.SignParameters, _ *azkeys.SignOptions) (result azkeys.SignResponse, err error) {
	return result, nil
}

func (c *testKVClient) Verify(_ context.Context, _, _ string, _ azkeys.VerifyParameters, _ *azkeys.VerifyOptions) (result azkeys.VerifyResponse, err error) {
	return result, nil
}

type keyNotFoundClient struct {
	testKVClient
	key                 azkeys.JSONWebKey
	getKeyReturnsErr    bool
	getKeyCallThreshold int
	getKeyCallCount     int
}

func (c *keyNotFoundClient) GetKey(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	if c.getKeyReturnsErr && c.getKeyCallCount < c.getKeyCallThreshold {
		c.getKeyCallCount++
		return azkeys.GetKeyResponse{}, &azcore.ResponseError{
			StatusCode:  http.StatusNotFound,
			RawResponse: &http.Response{},
		}
	}

	return azkeys.GetKeyResponse{
		KeyBundle: azkeys.KeyBundle{
			Key: &c.key,
		},
	}, nil
}

type nonResponseErrClient struct {
	testKVClient
	keyCache *ttlcache.Cache[string, crypto.PublicKey]
}

func (c *nonResponseErrClient) GetKey(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (result azkeys.GetKeyResponse, err error) {
	err = errors.New("unexpected error")
	return result, err
}

type non404RespClient struct {
	testKVClient
	keyCache *ttlcache.Cache[string, crypto.PublicKey]
}

func (c *non404RespClient) GetKey(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (result azkeys.GetKeyResponse, err error) {
	err = &azcore.ResponseError{
		StatusCode: http.StatusServiceUnavailable,
	}

	return result, err
}

func generatePublicKey(azureKeyType string) (azkeys.JSONWebKey, error) {
	keyOps := []*azkeys.KeyOperation{to.Ptr(azkeys.KeyOperationSign), to.Ptr(azkeys.KeyOperationVerify)}
	kid := "https://honk-vault.vault.azure.net/keys/honk-key/abc123"

	key := azkeys.JSONWebKey{
		KID:    to.Ptr(azkeys.ID(kid)),
		Kty:    to.Ptr(azkeys.KeyType(azureKeyType)),
		Crv:    to.Ptr(azkeys.CurveName("P-256")),
		KeyOps: keyOps,
	}

	keyType := azkeys.KeyType(azureKeyType)
	switch keyType {
	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return azkeys.JSONWebKey{}, err
		}

		ecdsaPub, ok := privKey.Public().(*ecdsa.PublicKey)
		if !ok {
			return azkeys.JSONWebKey{}, fmt.Errorf("failed to cast public key to esdsa public key")
		}

		key.X = ecdsaPub.X.Bytes()
		key.Y = ecdsaPub.Y.Bytes()

		return key, nil
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		privKey, err := rsa.GenerateKey(rand.Reader, 256)
		if err != nil {
			return azkeys.JSONWebKey{}, err
		}

		rsaPub, ok := privKey.Public().(*rsa.PublicKey)
		if !ok {
			return azkeys.JSONWebKey{}, fmt.Errorf("failed to cast public key to rsa public key")
		}

		key.N = rsaPub.N.Bytes()
		key.E = []byte(fmt.Sprint(rsaPub.E))

		return key, nil
	default:
		return azkeys.JSONWebKey{}, fmt.Errorf("invalid key type passed: %s", azureKeyType)
	}
}

func TestAzureVaultClientFetchPublicKey(t *testing.T) {
	keyTypes := []string{"EC", "EC-HSM", "RSA", "RSA-HSM"}

	for _, keyType := range keyTypes {
		key, err := generatePublicKey(keyType)
		if err != nil {
			t.Fatalf("unexpected error while generating public key for testing: %v", err)
		}

		kvClient := testKVClient{key: key}
		client := azureVaultClient{
			client: &kvClient,
		}

		_, err = client.fetchPublicKey(context.Background())
		if err != nil {
			t.Fatalf("expected error to be nil, actual value: %v", err)
		}
	}
}

func TestAzureVaultClientCreateKey(t *testing.T) {
	type test struct {
		name          string
		client        kvClient
		expectSuccess bool
	}

	key, err := generatePublicKey("EC")
	if err != nil {
		t.Fatalf("unexpected error while generating public key for testing: %v", err)
	}

	tests := []test{
		{
			name: "Successfully create key if it doesn't exist",
			client: &keyNotFoundClient{
				key:                 key,
				getKeyReturnsErr:    true,
				getKeyCallThreshold: 1,
			},
			expectSuccess: true,
		},
		{
			name: "Return public key if it already exists",
			client: &testKVClient{
				key: key,
			},
			expectSuccess: true,
		},
		{
			name:          "Fail to create key due to unknown error",
			client:        &nonResponseErrClient{},
			expectSuccess: false,
		},
		{
			name:          "Fail to create key due to non-404 status code error",
			client:        &non404RespClient{},
			expectSuccess: false,
		},
	}

	for _, tc := range tests {
		client := azureVaultClient{
			client: tc.client,
			keyCache: ttlcache.New[string, crypto.PublicKey](
				ttlcache.WithDisableTouchOnHit[string, crypto.PublicKey](),
			),
		}

		_, err = client.createKey(context.Background())
		if err != nil && tc.expectSuccess {
			t.Fatalf("Test '%s' failed. Expected nil error, actual value: %v", tc.name, err)
		}
		if err == nil && !tc.expectSuccess {
			t.Fatalf("Test '%s' failed. Expected non-nil error", tc.name)
		}
	}
}

func TestParseReference(t *testing.T) {
	tests := []struct {
		in             string
		wantVaultURL   string
		wantKeyName    string
		wantKeyVersion string
		wantErr        bool
	}{
		{
			in:             "azurekms://honk-vault.vault.azure.net/honk-key",
			wantVaultURL:   "https://honk-vault.vault.azure.net/",
			wantKeyName:    "honk-key",
			wantKeyVersion: "",
			wantErr:        false,
		},
		{
			in:             "azurekms://honk-vault.vault.azure.net/honk-key/123abc",
			wantVaultURL:   "https://honk-vault.vault.azure.net/",
			wantKeyName:    "honk-key",
			wantKeyVersion: "123abc",
			wantErr:        false,
		},
		{
			in:      "foo://bar",
			wantErr: true,
		},
		{
			in:      "",
			wantErr: true,
		},
		{
			in:      "azurekms://wrong-test/test/1/3",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			gotVaultURL, gotKeyName, gotKeyVersion, err := parseReference(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseReference() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotVaultURL != tt.wantVaultURL {
				t.Errorf("parseReference() gotVaultURL = %v, want %v", gotVaultURL, tt.wantVaultURL)
			}
			if gotKeyName != tt.wantKeyName {
				t.Errorf("parseReference() gotKeyName = %v, want %v", gotKeyName, tt.wantKeyName)
			}
			if gotKeyVersion != tt.wantKeyVersion {
				t.Errorf("parseReference() gotKeyVersion = %v, want %v", gotKeyVersion, tt.wantKeyVersion)
			}
		})
	}
}
