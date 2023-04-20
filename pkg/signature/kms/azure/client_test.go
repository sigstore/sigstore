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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
)

type testKVClient struct {
	key keyvault.JSONWebKey
}

func (c *testKVClient) CreateKey(_ context.Context, _, _ string, _ keyvault.KeyCreateParameters) (result keyvault.KeyBundle, err error) {
	key, err := generatePublicKey("EC")
	if err != nil {
		return result, err
	}
	c.key = key

	result.Key = &key
	return result, nil
}

func (c *testKVClient) GetKey(_ context.Context, _, _, _ string) (result keyvault.KeyBundle, err error) {
	result.Key = &c.key

	return result, nil
}

func (c *testKVClient) Sign(_ context.Context, _, _, _ string, _ keyvault.KeySignParameters) (result keyvault.KeyOperationResult, err error) {
	return result, nil
}

func (c *testKVClient) Verify(_ context.Context, _, _, _ string, _ keyvault.KeyVerifyParameters) (result keyvault.KeyVerifyResult, err error) {
	return result, nil
}

func generatePublicKey(azureKeyType string) (keyvault.JSONWebKey, error) {
	keyOps := []string{"sign", "verify"}
	kid := "https://honk-vault.vault.azure.net/keys/honk-key/abc123"

	key := keyvault.JSONWebKey{
		Kid:    &kid,
		Kty:    keyvault.JSONWebKeyType(azureKeyType),
		Crv:    "P-256",
		KeyOps: &keyOps,
	}

	if !strings.HasPrefix(azureKeyType, "EC") && !strings.HasPrefix(azureKeyType, "RSA") {
		return keyvault.JSONWebKey{}, fmt.Errorf("invalid key type passed: %s", azureKeyType)
	}

	if strings.HasPrefix(azureKeyType, "EC") {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return keyvault.JSONWebKey{}, err
		}

		ecdsaPub, ok := privKey.Public().(*ecdsa.PublicKey)
		if !ok {
			return keyvault.JSONWebKey{}, fmt.Errorf("failed to cast public key to esdsa public key")
		}

		xString := base64.RawURLEncoding.EncodeToString(ecdsaPub.X.Bytes())
		key.X = &xString

		yString := base64.RawURLEncoding.EncodeToString(ecdsaPub.Y.Bytes())
		key.Y = &yString

		return key, nil
	}

	// otherwise generate a RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 256)
	if err != nil {
		return keyvault.JSONWebKey{}, err
	}

	rsaPub, ok := privKey.Public().(*rsa.PublicKey)
	if !ok {
		return keyvault.JSONWebKey{}, fmt.Errorf("failed to cast public key to rsa public key")
	}

	nString := base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes())
	key.N = &nString

	eString := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprint(rsaPub.E)))
	key.E = &eString

	return key, nil
}

func TestAzureVaultClientFetchPublicKey(t *testing.T) {
	type test struct {
		azureKeyType  string
		expectSuccess bool
	}

	tests := []test{
		{
			azureKeyType:  "EC",
			expectSuccess: true,
		},
		{
			azureKeyType:  "EC-HSM",
			expectSuccess: true,
		},
		{
			azureKeyType:  "RSA",
			expectSuccess: true,
		},
		{
			azureKeyType:  "RSA-HSM",
			expectSuccess: true,
		},
	}

	for _, tc := range tests {
		key, err := generatePublicKey(tc.azureKeyType)
		if err != nil {
			t.Fatalf("unexpected error while generating public key for testing: %v", err)
		}

		kvClient := testKVClient{key: key}
		client := azureVaultClient{
			client: &kvClient,
		}

		_, err = client.fetchPublicKey(context.Background())
		if err != nil && tc.expectSuccess {
			t.Fatalf("expected error to be nil, actual value: %v", err)
		}
		if err == nil && !tc.expectSuccess {
			t.Fatal("expected error not to be nil")
		}
	}
}

func TestGetAuthenticationMethod(t *testing.T) {
	clearEnv := map[string]string{
		"AZURE_TENANT_ID":     "",
		"AZURE_CLIENT_ID":     "",
		"AZURE_CLIENT_SECRET": "",
		"AZURE_AUTH_METHOD":   "",
	}
	resetEnv := testSetEnv(t, clearEnv)
	defer resetEnv()

	cases := []struct {
		testDescription      string
		environmentVariables map[string]string
		expectedResult       authenticationMethod
	}{
		{
			testDescription:      "No environment variables set",
			environmentVariables: map[string]string{},
			expectedResult:       unknownAuthenticationMethod,
		},
		{
			testDescription: "AZURE_AUTH_METHOD=environment",
			environmentVariables: map[string]string{
				"AZURE_AUTH_METHOD": "environment",
			},
			expectedResult: environmentAuthenticationMethod,
		},
		{
			testDescription: "AZURE_AUTH_METHOD=cli",
			environmentVariables: map[string]string{
				"AZURE_AUTH_METHOD": "cli",
			},
			expectedResult: cliAuthenticationMethod,
		},
		{
			testDescription: "Set environment variables AZURE_TENANT_ID, AZURE_CLIENT_ID & AZURE_CLIENT_SECRET",
			environmentVariables: map[string]string{
				"AZURE_TENANT_ID":     "foo",
				"AZURE_CLIENT_ID":     "bar",
				"AZURE_CLIENT_SECRET": "baz",
			},
			expectedResult: environmentAuthenticationMethod,
		},
	}

	for i, c := range cases {
		t.Logf("Test #%d: %s", i, c.testDescription)
		reset := testSetEnv(t, c.environmentVariables)

		result := getAuthenticationMethod()
		if result != c.expectedResult {
			t.Logf("got: %q, want: %q", result, c.expectedResult)
			t.Fail()
		}

		reset()
	}
}

func testSetEnv(t *testing.T, s map[string]string) func() {
	t.Helper()

	backup := map[string]string{}
	for k, v := range s {
		currentEnv := os.Getenv(k)
		backup[k] = currentEnv
		if v == "" {
			os.Unsetenv(k)
			continue
		}
		os.Setenv(k, v)
	}

	return func() {
		for k, v := range backup {
			if v == "" {
				os.Unsetenv(k)
				continue
			}
			os.Setenv(k, v)
		}
	}
}
