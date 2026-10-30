// Copyright 2025 The Sigstore Authors.
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

package tink

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/signature"
	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
)

func TestKeyHandleToSignerECDSA(t *testing.T) {
	for _, tc := range []struct {
		name        string
		keyTemplate *tinkpb.KeyTemplate
		h           hash.Hash
	}{
		{
			name:        "ECDSA-P256-SHA256",
			keyTemplate: signature.ECDSAP256KeyWithoutPrefixTemplate(),
			h:           sha256.New(),
		},
		{
			name:        "ECDSA-P384-SHA512",
			keyTemplate: signature.ECDSAP384KeyWithoutPrefixTemplate(),
			h:           sha512.New(),
		},
		{
			name:        "ECDSA-P521-SHA512",
			keyTemplate: signature.ECDSAP521KeyWithoutPrefixTemplate(),
			h:           sha512.New(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kh, err := keyset.NewHandle(tc.keyTemplate)
			if err != nil {
				t.Fatalf("error creating ECDSA key handle: %v", err)
			}
			// convert to crypto.Signer interface
			signer, err := KeyHandleToSigner(kh)
			if err != nil {
				t.Fatalf("error converting ECDSA key handle to signer: %v", err)
			}
			msg := []byte("hello there")

			// sign with key handle, verify with signer public key
			tinkSigner, err := signature.NewSigner(kh)
			if err != nil {
				t.Fatalf("error creating tink signer: %v", err)
			}
			sig, err := tinkSigner.Sign(msg)
			if err != nil {
				t.Fatalf("error signing with tink signer: %v", err)
			}
			tc.h.Write(msg)
			digest := tc.h.Sum(nil)
			publicKey, ok := signer.Public().(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("error asserting ecdsa public key")
			}
			if !ecdsa.VerifyASN1(publicKey, digest, sig) {
				t.Fatalf("signature from tink signer did not match")
			}

			// sign with signer, verify with key handle
			privKey, ok := signer.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("error asserting ecdsa private key")
			}
			sig, err = ecdsa.SignASN1(rand.Reader, privKey, digest)
			if err != nil {
				t.Fatalf("error signing with crypto signer: %v", err)
			}
			pubkh, err := kh.Public()
			if err != nil {
				t.Fatalf("error fetching public key handle: %v", err)
			}
			v, err := signature.NewVerifier(pubkh)
			if err != nil {
				t.Fatalf("error creating tink verifier: %v", err)
			}
			if err := v.Verify(sig, msg); err != nil {
				t.Fatalf("error verifying with tink verifier: %v", err)
			}
		})
	}
}

func TestKeyHandleToSignerED25519(t *testing.T) {
	kh, err := keyset.NewHandle(signature.ED25519KeyWithoutPrefixTemplate())
	if err != nil {
		t.Fatalf("error creating ED25519 key handle: %v", err)
	}
	// convert to crypto.Signer interface
	signer, err := KeyHandleToSigner(kh)
	if err != nil {
		t.Fatalf("error converting ED25519 key handle to signer: %v", err)
	}
	msg := []byte("hello there")

	// sign with key handle, verify with signer public key
	tinkSigner, err := signature.NewSigner(kh)
	if err != nil {
		t.Fatalf("error creating tink signer: %v", err)
	}
	sig, err := tinkSigner.Sign(msg)
	if err != nil {
		t.Fatalf("error signing with tink signer: %v", err)
	}
	publicKey, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("error asserting ed25519 public key")
	}
	if !ed25519.Verify(publicKey, msg, sig) {
		t.Fatalf("signature from tink signer did not match")
	}

	// sign with signer, verify with key handle
	privKey, ok := signer.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("error asserting ed25519 private key")
	}
	sig = ed25519.Sign(privKey, msg)
	pubkh, err := kh.Public()
	if err != nil {
		t.Fatalf("error fetching public key handle: %v", err)
	}
	v, err := signature.NewVerifier(pubkh)
	if err != nil {
		t.Fatalf("error creating tink verifier: %v", err)
	}
	if err := v.Verify(sig, msg); err != nil {
		t.Fatalf("error verifying with tink verifier: %v", err)
	}
}

func TestKeyHandleToSignerMLDSA(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance tinkmldsa.Instance
	}{
		{
			name:     "ML-DSA-44",
			instance: tinkmldsa.MLDSA44,
		},
		{
			name:     "ML-DSA-65",
			instance: tinkmldsa.MLDSA65,
		},
		{
			name:     "ML-DSA-87",
			instance: tinkmldsa.MLDSA87,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := tinkmldsa.NewParameters(tc.instance, tinkmldsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("error creating ML-DSA parameters: %v", err)
			}
			manager := keyset.NewManager()
			keyID, err := manager.AddNewKeyFromParameters(params)
			if err != nil {
				t.Fatalf("error adding ML-DSA key: %v", err)
			}
			if err := manager.SetPrimary(keyID); err != nil {
				t.Fatalf("error setting primary ML-DSA key: %v", err)
			}
			kh, err := manager.Handle()
			if err != nil {
				t.Fatalf("error creating ML-DSA key handle: %v", err)
			}

			// convert to crypto.Signer interface
			signer, err := KeyHandleToSigner(kh)
			if err != nil {
				t.Fatalf("error converting ML-DSA key handle to signer: %v", err)
			}
			msg := []byte("hello there")

			// sign with key handle, verify with signer public key
			tinkSigner, err := signature.NewSigner(kh)
			if err != nil {
				t.Fatalf("error creating tink signer: %v", err)
			}
			sig, err := tinkSigner.Sign(msg)
			if err != nil {
				t.Fatalf("error signing with tink signer: %v", err)
			}
			publicKey, ok := signer.Public().(*mldsa.PublicKey)
			if !ok {
				t.Fatalf("error asserting mldsa public key")
			}
			if err := mldsa.Verify(publicKey, msg, sig, nil); err != nil {
				t.Fatalf("signature from tink signer did not verify: %v", err)
			}

			// sign with signer, verify with key handle
			privKey, ok := signer.(*mldsa.PrivateKey)
			if !ok {
				t.Fatalf("error asserting mldsa private key")
			}
			sig, err = privKey.Sign(rand.Reader, msg, nil)
			if err != nil {
				t.Fatalf("error signing with crypto signer: %v", err)
			}
			pubkh, err := kh.Public()
			if err != nil {
				t.Fatalf("error fetching public key handle: %v", err)
			}
			v, err := signature.NewVerifier(pubkh)
			if err != nil {
				t.Fatalf("error creating tink verifier: %v", err)
			}
			if err := v.Verify(sig, msg); err != nil {
				t.Fatalf("error verifying with tink verifier: %v", err)
			}
		})
	}
}

func TestKeyHandleToSignerFailsWithInvalidKeyType(t *testing.T) {
	kh, err := keyset.NewHandle(signature.RSA_SSA_PKCS1_3072_SHA256_F4_RAW_Key_Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	if _, err := KeyHandleToSigner(kh); err == nil {
		t.Errorf("KeyHandleToSigner(kh) err = nil, want error")
	}
}
