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

	signer, err := LoadSignerWithOpts(edPriv, options.WithED25519ph(), options.WithHash(crypto.SHA512))
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

func TestLoadDefaultSigner(t *testing.T) {
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
			sv, err := LoadDefaultSigner(tt.key(), tt.opts...)
			if err != nil {
				t.Fatalf("unexpected error creating signer: %v", err)
			}

			switch tt.expectedType {
			case "rsa":
				if _, ok := sv.(*RSAPKCS1v15Signer); !ok {
					t.Fatalf("expected signer to be an rsa signer")
				}
			case "rsa-pss":
				if _, ok := sv.(*RSAPSSSigner); !ok {
					t.Fatalf("expected signer to be an rsa-pss signer")
				}
			case "ecdsa":
				if _, ok := sv.(*ECDSASigner); !ok {
					t.Fatalf("expected signer to be an ecdsa signer")
				}
			case "ed25519":
				if _, ok := sv.(*ED25519Signer); !ok {
					t.Fatalf("expected signer to be an ed25519 signer")
				}
			case "ed25519-ph":
				if _, ok := sv.(*ED25519phSigner); !ok {
					t.Fatalf("expected signer to be an ed25519-ph signer")
				}
			}
		})
	}
}
