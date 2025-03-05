// Copyright 2022 The Sigstore Authors.
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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature/options"
)

func TestLoadUnsafeVerifier(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unexpected error generating key: %v", err)
	}
	verifier, err := LoadUnsafeVerifier(key.Public())
	if err != nil {
		t.Fatalf("unexpected error loading verifier: %v", err)
	}
	pubKey, _ := verifier.PublicKey()
	if !key.PublicKey.Equal(pubKey) {
		t.Fatalf("public keys were not equal")
	}
}

func TestLoadVerifier(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unexpected error generating key: %v", err)
	}
	verifier, err := LoadVerifier(key.Public(), crypto.SHA256)
	if err != nil {
		t.Fatalf("unexpected error loading verifier: %v", err)
	}
	pubKey, _ := verifier.PublicKey()
	if !key.PublicKey.Equal(pubKey) {
		t.Fatalf("public keys were not equal")
	}
}

func TestLoadDefaultVerifier(t *testing.T) {
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
			privKey := tt.key()
			signer, _ := privKey.(crypto.Signer)
			pubKey := signer.Public()
			sv, err := LoadVerifierFromPublicKey(pubKey, tt.opts...)
			if err != nil {
				t.Fatalf("unexpected error creating verifier: %v", err)
			}

			switch tt.expectedType {
			case "rsa":
				if _, ok := sv.(*RSAPKCS1v15Verifier); !ok {
					t.Fatalf("expected verifier to be an rsa verifier")
				}
			case "rsa-pss":
				if _, ok := sv.(*RSAPSSVerifier); !ok {
					t.Fatalf("expected verifier to be an rsa-pss verifier")
				}
			case "ecdsa":
				if _, ok := sv.(*ECDSAVerifier); !ok {
					t.Fatalf("expected verifier to be an ecdsa verifier")
				}
			case "ed25519":
				if _, ok := sv.(*ED25519Verifier); !ok {
					t.Fatalf("expected verifier to be an ed25519 verifier")
				}
			case "ed25519-ph":
				if _, ok := sv.(*ED25519phVerifier); !ok {
					t.Fatalf("expected verifier to be an ed25519-ph verifier")
				}
			}
		})
	}
}
