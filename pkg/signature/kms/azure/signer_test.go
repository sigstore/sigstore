//
// Copyright 2024 The Sigstore Authors.
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
	"bytes"
	"encoding/asn1"
	"strings"
	"testing"
)

type encryptionAlg string

const (
	RSA   encryptionAlg = "RSA"
	ECDSA encryptionAlg = "ECDSA"
)

func TestSignMessageWithECDSA(t *testing.T) {
	sv := SignerVerifier{
		client: newECDSAMockAzureVaultClient(t),
	}

	sig, err := sv.SignMessage(strings.NewReader("my message"))
	if err != nil {
		t.Fatalf("error signing message: %v", err)
	}

	var raw asn1.RawValue
	_, err = asn1.Unmarshal(sig, &raw)
	if err != nil {
		t.Fatalf("Failed to parse data as ASN.1: %v\n", err)
	}
}

func TestVerifyMessageWithECDSA(t *testing.T) {
	sv := SignerVerifier{
		client: newECDSAMockAzureVaultClient(t),
	}
	message := strings.NewReader("my message")

	sig, err := sv.SignMessage(message)
	if err != nil {
		t.Fatalf("error signing message: %v", err)
	}

	err = sv.VerifySignature(bytes.NewReader(sig), message)
	if err != nil {
		t.Fatalf("error verifying signature: %v", err)
	}
}

func TestSignMessageWithRSA(t *testing.T) {
	sv := SignerVerifier{
		client: newRSAMockAzureVaultClient(t),
	}

	sig, err := sv.SignMessage(strings.NewReader("my message"))
	if err != nil {
		t.Fatalf("error signing message: %v", err)
	}

	asn1Encoded, err := encodeToASN1(sig)
	if err != nil {
		t.Fatalf("error encoding signature to ASN.1: %v", err)
	}

	if bytes.Equal(sig, asn1Encoded) {
		t.Fatal("Signature should be ASN.1 encoded\n")
	}
}

func TestVerifyMessageWithRSA(t *testing.T) {
	sv := SignerVerifier{
		client: newRSAMockAzureVaultClient(t),
	}
	message := strings.NewReader("my message")

	sig, err := sv.SignMessage(message)
	if err != nil {
		t.Fatalf("error signing message: %v", err)
	}

	err = sv.VerifySignature(bytes.NewReader(sig), message)
	if err != nil {
		t.Fatalf("error verifying signature: %v", err)
	}
}
