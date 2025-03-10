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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
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

func TestLoadDefaultSignerVerifier(t *testing.T) {
	tts := []struct {
		name         string
		key          func() crypto.PrivateKey
		opts         []LoadOption
		expectedType string
	}{
		{
			name: "rsa-2048",
			key: func() crypto.PrivateKey {
				rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("unexpected error creating rsa key: %v", err)
				}
				return rsaKey
			},
			expectedType: "rsa",
		},
		{
			name: "rsa-2048-pss",
			key: func() crypto.PrivateKey {
				rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("unexpected error creating rsa key: %v", err)
				}
				return rsaKey
			},
			opts: []LoadOption{
				options.WithRSAPSS(&rsa.PSSOptions{
					Hash: crypto.SHA256,
				}),
			},
			expectedType: "rsa-pss",
		},
		{
			name: "ecdsa-p256",
			key: func() crypto.PrivateKey {
				ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("unexpected error creating ecdsa key: %v", err)
				}
				return ecdsaKey
			},
			expectedType: "ecdsa",
		},
		{
			name: "ed25519",
			key: func() crypto.PrivateKey {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("unexpected error creating ed25519 key: %v", err)
				}
				return priv
			},
			expectedType: "ed25519",
		},
		{
			name: "ed25519-ph",
			key: func() crypto.PrivateKey {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("unexpected error creating ed25519 key: %v", err)
				}
				return priv
			},
			opts: []LoadOption{
				options.WithED25519ph(),
			},
			expectedType: "ed25519-ph",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			sv, err := LoadDefaultSignerVerifier(tt.key(), tt.opts...)
			if err != nil {
				t.Fatalf("unexpected error creating signer/verifier: %v", err)
			}

			switch tt.expectedType {
			case "rsa":
				if _, ok := sv.(*RSAPKCS1v15SignerVerifier); !ok {
					t.Fatalf("expected signer/verifier to be an rsa signer/verifier")
				}
			case "rsa-pss":
				if _, ok := sv.(*RSAPSSSignerVerifier); !ok {
					t.Fatalf("expected signer/verifier to be an rsa-pss signer/verifier")
				}
			case "ecdsa":
				if _, ok := sv.(*ECDSASignerVerifier); !ok {
					t.Fatalf("expected signer/verifier to be an ecdsa signer/verifier")
				}
			case "ed25519":
				if _, ok := sv.(*ED25519SignerVerifier); !ok {
					t.Fatalf("expected signer/verifier to be an ed25519 signer/verifier")
				}
			case "ed25519-ph":
				if _, ok := sv.(*ED25519phSignerVerifier); !ok {
					t.Fatalf("expected signer/verifier to be an ed25519-ph signer/verifier")
				}
			}
		})
	}
}
