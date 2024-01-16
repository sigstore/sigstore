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
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestLoadEd25519Signer(t *testing.T) {
	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey([]byte(ed25519Priv), cryptoutils.SkipPassword)
	if err != nil {
		t.Fatalf("unexpected error unmarshalling public key: %v", err)
	}
	edPriv, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey")
	}

	signer, err := LoadSigner(edPriv, crypto.SHA256)
	if err != nil {
		t.Fatalf("unexpected error loading verifier: %v", err)
	}

	msg := []byte("sign me")
	sig, err := signer.SignMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("unexpected error signing message: %v", err)
	}

	expectedSig, _ := base64.StdEncoding.DecodeString("cnafwd8DKq2nQ564eN66ckYV8anVFGFi5vaYiQg2aal7ej/J0/OE0PPdKHLHe9wdzWRMFy5MpurRD/2cGXGLBQ==")
	if !bytes.Equal(sig, expectedSig) {
		t.Fatalf("signature was not as expected")
	}
}

func TestLoadEd25519phSigner(t *testing.T) {
	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey([]byte(ed25519Priv), cryptoutils.SkipPassword)
	if err != nil {
		t.Fatalf("unexpected error unmarshalling public key: %v", err)
	}
	edPriv, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey")
	}

	signer, err := LoadSignerWithOpts(edPriv, WithED25519ph(), WithHash(crypto.SHA512))
	if err != nil {
		t.Fatalf("unexpected error loading verifier: %v", err)
	}

	msg := []byte("sign me")
	sig, err := signer.SignMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("unexpected error signing message: %v", err)
	}

	expectedSig, _ := base64.StdEncoding.DecodeString("9D4pA8jutZnbqKy4fFRl+kDsVUCO50qrOD1lxmsiUFk6NX+7OXUK5BCMkE2KYPRDxjkDFBzbDZEQhaFdDV5tDg==")
	if !bytes.Equal(sig, expectedSig) {
		t.Fatalf("signature was not as expected")
	}
}
