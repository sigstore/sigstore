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

package signature

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// Generated with:
// openssl genpkey -algorithm ed25519 -outform PEM -out -
const ed25519phPriv = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFP9CZb6J1DiOLfdIkPfy1bwBOCjEG6KR/cIdhw90J1H
-----END PRIVATE KEY-----`

// Extracted from above with:
// openssl ec -in ec_private.pem -pubout
const ed25519phPub = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9wy4umF4RHQ8UQXo8fzEQNBWE4GsBMkCzQPAfHvkf/s=
-----END PUBLIC KEY-----`

func TestED25519phSignerVerifier(t *testing.T) {
	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey([]byte(ed25519phPriv), cryptoutils.SkipPassword)
	if err != nil {
		t.Fatalf("unexpected error unmarshalling public key: %v", err)
	}
	edPriv, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey")
	}

	sv, err := LoadED25519phSignerVerifier(edPriv)
	if err != nil {
		t.Fatalf("unexpected error creating signer/verifier: %v", err)
	}

	message := []byte("sign me")
	sig, _ := base64.StdEncoding.DecodeString("9D4pA8jutZnbqKy4fFRl+kDsVUCO50qrOD1lxmsiUFk6NX+7OXUK5BCMkE2KYPRDxjkDFBzbDZEQhaFdDV5tDg==")
	testingSigner(t, sv, "ed25519ph", crypto.SHA512, message)
	testingVerifier(t, sv, "ed25519ph", crypto.SHA512, sig, message)
	pub, err := sv.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error from PublicKey(): %v", err)
	}
	assertPublicKeyIsx509Marshalable(t, pub)
}

func TestED25519phVerifier(t *testing.T) {
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(ed25519phPub))
	if err != nil {
		t.Fatalf("unexpected error unmarshalling public key: %v", err)
	}
	edPub, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is not ed25519")
	}

	v, err := LoadED25519phVerifier(edPub)
	if err != nil {
		t.Fatalf("unexpected error creating verifier: %v", err)
	}

	message := []byte("sign me")
	sig, _ := base64.StdEncoding.DecodeString("9D4pA8jutZnbqKy4fFRl+kDsVUCO50qrOD1lxmsiUFk6NX+7OXUK5BCMkE2KYPRDxjkDFBzbDZEQhaFdDV5tDg==")
	testingVerifier(t, v, "ed25519ph", crypto.SHA512, sig, message)
	pub, err := v.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error from PublicKey(): %v", err)
	}
	assertPublicKeyIsx509Marshalable(t, pub)
}
