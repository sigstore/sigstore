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

package signature

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// Generated with:
// openssl ecparam -genkey -name prime256v1 > ec_private.pem
// openssl pkcs8 -topk8 -in ec_private.pem  -nocrypt
const ecdsaPriv = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmrLtCpBdXgXLUr7o
nSUPfo3oXMjmvuwTOjpTulIBKlKhRANCAATH6KSpTFe6uXFmW1qNEFXaO7fWPfZt
pPZrHZ1cFykidZoURKoYXfkohJ+U/USYy8Sd8b4DMd5xDRZCnlDM0h37
-----END PRIVATE KEY-----`

// Extracted from above with:
// openssl ec -in ec_private.pem -pubout
const ecdsaPub = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx+ikqUxXurlxZltajRBV2ju31j32
baT2ax2dXBcpInWaFESqGF35KISflP1EmMvEnfG+AzHecQ0WQp5QzNId+w==
-----END PUBLIC KEY-----`

func TestECDSASignerVerifier(t *testing.T) {
	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey([]byte(ecdsaPriv), cryptoutils.SkipPassword)
	if err != nil {
		t.Errorf("unexpected error unmarshalling private key: %v", err)
	}
	sv, err := LoadECDSASignerVerifier(privateKey.(*ecdsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Errorf("unexpected error creating signer/verifier: %v", err)
	}

	message := []byte("sign me")
	// created with openssl dgst -sign privKey.pem -sha256
	sig, _ := base64.StdEncoding.DecodeString("MEQCIGvnAsUT6P4PoJoKxP331ZFU2LfzxnuvulK14Rl3zNKIAiBJCSA7NdmAZkLNqxmWnbBp8ntJYVZmUR0Tbmv6ftS8ww==")
	testingSigner(t, sv, "ecdsa", crypto.SHA256, message)
	testingVerifier(t, sv, "ecdsa", crypto.SHA256, sig, message)

	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(ecdsaPub))
	if err != nil {
		t.Errorf("unexpected error unmarshalling public key: %v", err)
	}
	v, err := LoadECDSAVerifier(publicKey.(*ecdsa.PublicKey), crypto.SHA256)
	if err != nil {
		t.Errorf("unexpected error creating verifier: %v", err)
	}
	testingVerifier(t, v, "ecdsa", crypto.SHA256, sig, message)
}

func TestECDSASignerVerifierUnsupportedHash(t *testing.T) {
	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey([]byte(ecdsaPriv), cryptoutils.SkipPassword)
	if err != nil {
		t.Errorf("unexpected error unmarshalling private key: %v", err)
	}
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(ecdsaPub))
	if err != nil {
		t.Errorf("unexpected error unmarshalling public key key: %v", err)
	}

	_, err = LoadECDSASigner(privateKey.(*ecdsa.PrivateKey), crypto.SHA1)
	if !strings.Contains(err.Error(), "invalid hash function specified") {
		t.Errorf("expected error 'invalid hash function specified', got: %v", err.Error())
	}

	_, err = LoadECDSAVerifier(publicKey.(*ecdsa.PublicKey), crypto.SHA1)
	if !strings.Contains(err.Error(), "invalid hash function specified") {
		t.Errorf("expected error 'invalid hash function specified', got: %v", err.Error())
	}
}
