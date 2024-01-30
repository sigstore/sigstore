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
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func TestLoadRSAPSSSignerVerifier(t *testing.T) {
	opts := &rsa.PSSOptions{
		Hash: crypto.SHA256,
	}

	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey([]byte(rsaKey), cryptoutils.SkipPassword)
	if err != nil {
		t.Errorf("unexpected error unmarshalling private key: %v", err)
	}
	sv, err := LoadSignerVerifierWithOpts(privateKey, options.WithHash(crypto.SHA256), options.WithED25519ph(), options.WithRSAPSS(opts))
	if err != nil {
		t.Errorf("unexpected error creating signer/verifier: %v", err)
	}

	message := []byte("sign me")
	sig, err := sv.SignMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatalf("unexpected error signing message: %v", err)
	}
	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message)); err != nil {
		t.Fatalf("unexpected error verifying calculated signature: %v", err)
	}

	expectedSig, _ := base64.StdEncoding.DecodeString("UyouJxmgAKdm/Qfi9YA7aK71/eqyLcytmDN8CQqSCgcbGSln7S5fgIAmrwUfGp1tcxKjuNjLScn11+fqawiG9y66740VEC6GfS1hgElC2k3i/v8ly2mlt+4JYs3euzYxtWnxwQr4csc7Jy2V2cjoeQm6GTxkR4E6TRJM8/UxXvjKtp3rxRD8OuyfuGFkI0lU48vjKLgbuZKQqQdWuNUOnsPvtrHxvGRY/F1C0Ig3b7SoTyAjWSXQG42faKsFT+W1L/UdRK+m73TYdxMleI4uIGtl0k0Weui1/gK7Uh2FUP5+/F1ZoQRYk/DMz0M4QPmPsYLGwc8oduoF6JvNMGKymg==")
	if err := sv.VerifySignature(bytes.NewReader(expectedSig), bytes.NewReader(message)); err != nil {
		t.Fatalf("unexpected error verifying expected signature: %v", err)
	}
}

func TestConvertED25519ph(t *testing.T) {
	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey([]byte(ed25519Priv), cryptoutils.SkipPassword)
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

	newSV, err := sv.ToED25519SignerVerifier()
	if err != nil {
		t.Fatalf("unexpected error converting to ed25519: %v", err)
	}

	message := []byte("sign me")
	sig, _ := base64.StdEncoding.DecodeString("cnafwd8DKq2nQ564eN66ckYV8anVFGFi5vaYiQg2aal7ej/J0/OE0PPdKHLHe9wdzWRMFy5MpurRD/2cGXGLBQ==")
	testingSigner(t, newSV, "ed25519", crypto.SHA256, message)
	testingVerifier(t, newSV, "ed25519", crypto.SHA256, sig, message)
}
