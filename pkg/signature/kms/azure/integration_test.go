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
	"fmt"
	"os"
	"strings"
	"testing"
)

/*
The following environment variables must be set:
AZURE_KEY_REF - full azure key reference in the format azurekms://[Key Vault Name].vault.azure.net/[Key Name](/[Key Version]Optional)
KEY_NAME - Azure key name
VAULT_URL - Azure Vault URL
*/

func TestLoadSignerVerifier(t *testing.T) {
	azureKeyRef := os.Getenv("AZURE_KEY_REF")
	if azureKeyRef == "" {
		t.Fatalf("AZURE_KEY_REF must be set")
	}
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

	if sv.client.vaultURL != azureVaultURL {
		t.Errorf("expected client.vaultURL to be %s, got %s", azureVaultURL, sv.client.vaultURL)
	}
	if sv.client.keyName != azureKeyName {
		t.Errorf("expected client.keyName to be %s, got %s", azureKeyName, sv.client.keyName)
	}
	if sv.client.keyVersion != azureKeyVersion {
		t.Errorf("expected client.keyVersion to be %s, got %s", azureKeyVersion, sv.client.keyVersion)
	}
}

func TestGetKey(t *testing.T) {
	azureKeyRef := os.Getenv("AZURE_KEY_REF")
	if azureKeyRef == "" {
		t.Fatalf("AZURE_KEY_REF must be set")
	}
	fmt.Println("AZURE_KEY_REF: " + azureKeyRef)

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
	if azureKeyRef == "" {
		t.Fatalf("AZURE_KEY_REF must be set")
	}
	fmt.Println("AZURE_KEY_REF: " + azureKeyRef)

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
	if azureKeyRef == "" {
		t.Fatalf("AZURE_KEY_REF must be set")
	}
	sv, err := LoadSignerVerifier(context.Background(), azureKeyRef)
	if err != nil {
		t.Fatalf("LoadSignerVerifier unexpectedly returned non-nil error: %v", err)
	}

	cryptoHash, sigAlg, err := sv.client.getKeyVaultHashFunc(context.Background())
	if err != nil {
		t.Errorf("failed to get crypto hash and signature algorithm associated with key: %v", err)
	}
	fmt.Printf("\ncrypto hash: %v", cryptoHash)
	fmt.Printf("\nsignature algorithm: %v", sigAlg)
}

func TestSignMessage(t *testing.T) {
	azureKeyRef := os.Getenv("AZURE_KEY_REF")
	if azureKeyRef == "" {
		t.Fatalf("AZURE_KEY_REF must be set")
	}
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

func TestVerify(t *testing.T) {
	azureKeyRef := os.Getenv("AZURE_KEY_REF")
	if azureKeyRef == "" {
		t.Fatalf("AZURE_KEY_REF must be set")
	}
	sv, err := LoadSignerVerifier(context.Background(), azureKeyRef)
	if err != nil {
		t.Fatalf("LoadSignerVerifier unexpectedly returned non-nil error: %v", err)
	}

	messageToSign := strings.NewReader("myblob")
	signed, err := sv.SignMessage(messageToSign)
	if err != nil {
		t.Errorf("SignMessage unexpectedly returned non-nil error: %v", err)
	}

	err = sv.VerifySignature(bytes.NewReader(signed), messageToSign)
	if err != nil {
		t.Errorf("VerifySignature failed to verify signature: %v", err)
	}
}
