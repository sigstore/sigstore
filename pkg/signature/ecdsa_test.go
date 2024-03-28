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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
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

	// test IEEE P1363 encoded signature
	// created via
	// import "github.com/tink-crypto/tink-go/signature/subtle"
	// subtle.NewECDSASignerFromPrivateKey("SHA256", "IEEE_P1363", privKey.(*ecdsa.PrivateKey))
	ieeeSig, _ := base64.StdEncoding.DecodeString("bmvQGbNZEJyS3HAVPiuXY0/BGFcUq5cl22v3+sttMxBls5LO0W52qR2yk6q0E59wDNs15gvaODeTZ2d6MwH9OQ==")
	testingVerifier(t, v, "ecdsa", crypto.SHA256, ieeeSig, message)
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

func TestECDSALoadVerifierWithoutKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v, err := LoadECDSAVerifier(&key.PublicKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("error creating verifier: %v", err)
	}
	v.publicKey = nil
	if err := v.VerifySignature(nil, nil); err == nil || !strings.Contains(err.Error(), "no public key") {
		t.Fatalf("expected error without public key, got: %v", err)
	}
}

// TestECDSALoadVerifierInvalidCurve tests gracefully handling an invalid curve.
func TestECDSALoadVerifierInvalidCurve(t *testing.T) {
	data := []byte{1}
	x := ecdsa.PrivateKey{}
	z := new(big.Int)
	z.SetBytes(data)
	x.X = z
	x.Y = z
	x.D = z
	x.Curve = elliptic.P256()

	verifier, err := LoadECDSAVerifier(&x.PublicKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("unexpected error loading verifier: %v", err)
	}

	msg := []byte("hello")
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, &x, digest[:])
	if err != nil {
		fmt.Println(err)
	}

	if err := verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)); err == nil || !strings.Contains(err.Error(), "invalid ECDSA public key") {
		t.Fatalf("expected error verifying signature with invalid curve, got %v", err)
	}
}
