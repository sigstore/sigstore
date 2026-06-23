//go:build integration

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

// Package azure contains utilities related to Microsoft Azure KMS.
package azure

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/google/go-cmp/cmp"
)

/*
The following environment variables must be set:
AZURE_KEY_REF - full azure key reference in the format azurekms://[Key Vault Name].vault.azure.net/[Key Name](/[Key Version]Optional)
KEY_NAME - Azure key name
VAULT_URL - Azure Vault URL
*/

func TestMain(m *testing.M) {
	azureKeyRef := os.Getenv("AZURE_KEY_REF")
	if azureKeyRef == "" {
		panic("AZURE_KEY_REF must be set")
	}
	os.Exit(m.Run())
}

func TestGetAzClientOpts(t *testing.T) {
	testCases := []struct {
		env            string
		expectedConfig cloud.Configuration
	}{{
		env:            "AZUREUSGOVERNMENT",
		expectedConfig: cloud.AzureGovernment,
	}, {
		env:            "AZUREUSGOVERNMENTCLOUD",
		expectedConfig: cloud.AzureGovernment,
	}, {
		env:            "AZURECHINACLOUD",
		expectedConfig: cloud.AzureChina,
	}, {
		env:            "AZURECLOUD",
		expectedConfig: cloud.AzurePublic,
	}, {
		env:            "AZUREPUBLICCLOUD",
		expectedConfig: cloud.AzurePublic,
	}, {
		env:            "",
		expectedConfig: cloud.AzurePublic,
	}}

	for _, tc := range testCases {
		t.Setenv("AZURE_ENVIRONMENT", tc.env)

		opts := getAzClientOpts()
		if !cmp.Equal(tc.expectedConfig, opts.Cloud) {
			t.Errorf("opts.Cloud %v does not match expected config: %v", opts.Cloud, tc.expectedConfig)
		}
	}
}

func TestLoadSignerVerifier(t *testing.T) {
	azureKeyRef := os.Getenv("AZURE_KEY_REF")

	azureKeyName := os.Getenv("KEY_NAME")
	if azureKeyName == "" {
		t.Fatalf("KEY_NAME must be set")
	}
	azureVaultURL := os.Getenv("VAULT_URL")
	if azureVaultURL == "" {
		t.Fatalf("VAULT_URL must be set")
	}
	azureKeyVersion := os.Getenv("KEY_VERSION")

	sv, err := LoadSignerVerifier(context.Background(), azureKeyRef)
	if err != nil {
		t.Errorf("LoadSignerVerifier unexpectedly returned non-nil error: %v", err)
	}

	if sv == nil {
		t.Errorf("LoadSignerVerifier failed to create a SignerVerifier instance")
	}

	if sv.client.vaultURL != fmt.Sprintf("https://%s/", azureVaultURL) {
		t.Errorf("expected client.vaultURL to be %s, got %s", azureVaultURL, sv.client.vaultURL)
	}
	if sv.client.keyName != azureKeyName {
		t.Errorf("expected client.keyName to be %s, got %s", azureKeyName, sv.client.keyName)
	}
	if sv.client.keyVersion != azureKeyVersion {
		t.Errorf("expected client.keyVersion to be %s, got %s", azureKeyVersion, sv.client.keyVersion)
	}
}

func TestCreateKey(t *testing.T) {
	azureVaultURL := os.Getenv("VAULT_URL")
	if azureVaultURL == "" {
		t.Fatalf("VAULT_URL must be set")
	}

	newKeyRef := fmt.Sprintf("azurekms://%s.vault.azure.net/%s", azureVaultURL, "new-test-key")

	sv, err := LoadSignerVerifier(context.Background(), newKeyRef)
	if err != nil {
		t.Fatalf("LoadSignerVerifier unexpectedly returned non-nil error: %v", err)
	}

	publicKey, err := sv.client.createKey(context.Background())
	if err != nil {
		t.Errorf("getKey failed with error: %v", err)
	}
	if publicKey == nil {
		t.Errorf("public key is nil")
	}

	if _, ok := publicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("expected public key to be of type *ecdsa.PublicKey")
	}
}

func TestGetKey(t *testing.T) {
	azureKeyRef := os.Getenv("AZURE_KEY_REF")

	sv, err := LoadSignerVerifier(context.Background(), azureKeyRef)
	if err != nil {
		t.Fatalf("LoadSignerVerifier unexpectedly returned non-nil error: %v", err)
	}

	keyBundle, err := sv.client.getKey(context.Background())
	if err != nil {
		t.Errorf("getKey failed with error: %v", err)
	}

	if keyBundle.Key == nil {
		t.Errorf("key bundle key is nil")
	}
}

func TestPublicKey(t *testing.T) {
	azureKeyRef := os.Getenv("AZURE_KEY_REF")

	sv, err := LoadSignerVerifier(context.Background(), azureKeyRef)
	if err != nil {
		t.Fatalf("LoadSignerVerifier unexpectedly returned non-nil error: %v", err)
	}

	pubKey, err := sv.PublicKey()
	if err != nil {
		t.Errorf("PublicKey failed with error: %v", err)
	}
	if pubKey == nil {
		t.Errorf("PublicKey response is nil")
	}
}

func TestGetKeyVaultHashFunc(t *testing.T) {
	azureKeyRef := os.Getenv("AZURE_KEY_REF")

	sv, err := LoadSignerVerifier(context.Background(), azureKeyRef)
	if err != nil {
		t.Fatalf("LoadSignerVerifier unexpectedly returned non-nil error: %v", err)
	}

	_, _, err = sv.client.getKeyVaultHashFunc(context.Background())
	if err != nil {
		t.Errorf("failed to get crypto hash and signature algorithm associated with key: %v", err)
	}
}

func TestSignMessage(t *testing.T) {
	azureKeyRef := os.Getenv("AZURE_KEY_REF")

	sv, err := LoadSignerVerifier(context.Background(), azureKeyRef)
	if err != nil {
		t.Fatalf("LoadSignerVerifier unexpectedly returned non-nil error: %v", err)
	}

	messageToSign := strings.NewReader("myblob")
	signed, err := sv.SignMessage(messageToSign)
	if err != nil {
		t.Errorf("SignMessage unexpectedly returned non-nil error: %v", err)
	}
	if signed == nil || len(signed) == 0 {
		t.Errorf("SignMessage unexpected returned nil or empty signature")
	}
}

func TestVerifySignature(t *testing.T) {
	azureKeyRef := os.Getenv("AZURE_KEY_REF")

	sv, err := LoadSignerVerifier(context.Background(), azureKeyRef)
	if err != nil {
		t.Fatalf("LoadSignerVerifier unexpectedly returned non-nil error: %v", err)
	}

	messageToSign := "myblob"
	signed, err := sv.SignMessage(strings.NewReader(messageToSign))
	if err != nil {
		t.Errorf("SignMessage unexpectedly returned non-nil error: %v", err)
	}
	if signed == nil || len(signed) == 0 {
		t.Errorf("SignMessage unexpected returned nil or empty signature")
	}

	err = sv.VerifySignature(bytes.NewReader(signed), strings.NewReader(messageToSign))
	if err != nil {
		t.Errorf("VerifySignature unexpectedly returned non-nil error: %v", err)
	}
}
