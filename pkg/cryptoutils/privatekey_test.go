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

package cryptoutils

import (
	"crypto/rsa"
	"testing"
)

func verifyRSAKeyPEMs(t *testing.T, privPEM, pubPEM []byte, expectedKeyLengthBits int, testPassFunc PassFunc) {
	priv, err := UnmarshalPEMToPrivateKey(privPEM, testPassFunc)
	if err != nil {
		t.Fatalf("UnmarshalPEMToPrivateKey returned error: %v", err)
	} else if rsaPriv, ok := priv.(*rsa.PrivateKey); !ok {
		t.Errorf("expected unmarshaled key to be of type *rsa.PrivateKey, was %T", priv)
	} else if rsaPriv.Size() != expectedKeyLengthBits/8 {
		t.Errorf("private key size was %d, expected %d", rsaPriv.Size(), expectedKeyLengthBits/8)
	}

	pub, err := UnmarshalPEMToPublicKey(pubPEM)
	if err != nil {
		t.Fatalf("UnmarshalPEMToPublicKey returned error: %v", err)
	} else if rsaPub, ok := pub.(*rsa.PublicKey); !ok {
		t.Errorf("expected unmarshaled public key to be of type *rsa.PublicKey, was %T", priv)
	} else if rsaPub.Size() != expectedKeyLengthBits/8 {
		t.Errorf("public key size was %d, expected %d", rsaPub.Size(), expectedKeyLengthBits/8)
	}
}

func TestGenerateEncryptedRSAKeyPair(t *testing.T) {
	t.Parallel()

	const testKeyBits = 2048
	testPassFunc := StaticPasswordFunc([]byte("TestGenerateEncryptedRSAKeyPair password"))
	privPEM, pubPEM, err := GenerateRSAKeyPair(testKeyBits, testPassFunc)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair returned error: %v", err)
	}

	if priv, err := UnmarshalPEMToPrivateKey(privPEM, SkipPassword); err == nil {
		t.Errorf("should have failed to unmarshal private key without password, got %v", priv)
	}
	verifyRSAKeyPEMs(t, privPEM, pubPEM, testKeyBits, testPassFunc)
}

func TestGenerateUnencryptedRSAKeyPair(t *testing.T) {
	t.Parallel()

	const testKeyBits = 2048
	privPEM, pubPEM, err := GenerateRSAKeyPair(testKeyBits, nil)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair returned error: %v", err)
	}

	if priv, err := UnmarshalPEMToPrivateKey(privPEM, SkipPassword); err != nil {
		t.Errorf("SkipPassword should have worked to unmarshal private key without password, got %v", priv)
	}
	verifyRSAKeyPEMs(t, privPEM, pubPEM, testKeyBits, nil)
}
