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

	sig, err := sv.SignMessage(strings.NewReader("my message"), nil)
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

	sig, err := sv.SignMessage(message, nil)
	if err != nil {
		t.Fatalf("error signing message: %v", err)
	}

	err = sv.VerifySignature(bytes.NewReader(sig), message, nil)
	if err != nil {
		t.Fatalf("error verifying signature: %v", err)
	}
}

func TestSignMessageWithRSA(t *testing.T) {
	sv := SignerVerifier{
		client: newRSAMockAzureVaultClient(t),
	}

	sig, err := sv.SignMessage(strings.NewReader("my message"), nil)
	if err != nil {
		t.Fatalf("error signing message: %v", err)
	}

	var raw asn1.RawValue
	_, err = asn1.Unmarshal(sig, &raw)
	if err == nil {
		t.Fatalf("Signature should not be ASN.1 encoded: %v\n", err)
	}
}

func TestVerifyMessageWithRSA(t *testing.T) {
	sv := SignerVerifier{
		client: newRSAMockAzureVaultClient(t),
	}
	message := strings.NewReader("my message")

	sig, err := sv.SignMessage(message, nil)
	if err != nil {
		t.Fatalf("error signing message: %v", err)
	}

	err = sv.VerifySignature(bytes.NewReader(sig), message, nil)
	if err != nil {
		t.Fatalf("error verifying signature: %v", err)
	}
}
