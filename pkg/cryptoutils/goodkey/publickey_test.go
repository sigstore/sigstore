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

package goodkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/letsencrypt/boulder/goodkey"
)

func TestValidatePubKeyUnsupported(t *testing.T) {
	// Fails with unexpected key type
	type PublicKey struct{}
	err := ValidatePubKey(PublicKey{})
	if err == nil || err.Error() != "unsupported public key type" {
		t.Errorf("expected unsupported public key type, got %v", err)
	}
}

func TestValidatePubKeyRsa(t *testing.T) {
	// Validate common RSA key sizes
	for _, bits := range []int{2048, 3072, 4096} {
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatalf("rsa.GenerateKey failed: %v", err)
		}
		if err := ValidatePubKey(priv.Public()); err != nil {
			t.Errorf("unexpected error validating public key: %v", err)
		}
	}
	// Fails with small key size
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	if err := ValidatePubKey(priv.Public()); err == nil || err.Error() != "key size not supported: 1024" {
		t.Errorf("expected rsa key size not supported, got %v", err)
	}
	// Fails with large key size
	priv, err = rsa.GenerateKey(rand.Reader, 5000)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	if err := ValidatePubKey(priv.Public()); err == nil || err.Error() != "key size not supported: 5000" {
		t.Errorf("expected rsa key size not supported, got %v", err)
	}
	// Fails with key size that's not a multiple of 8
	priv, err = rsa.GenerateKey(rand.Reader, 4095)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	if err := ValidatePubKey(priv.Public()); err == nil || err.Error() != "key size not supported: 4095" {
		t.Errorf("expected rsa key size not supported, got %v", err)
	}
}

type testCurve struct {
	elliptic.Curve
}

func (t testCurve) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{}
}

func TestValidatePubKeyEcdsa(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey failed: %v", err)
		}
		if err := ValidatePubKey(priv.Public()); err != nil {
			t.Errorf("unexpected error validating public key: %v", err)
		}
		// Should fail with negative coordinates
		priv.X.Neg(priv.X)
		if err := ValidatePubKey(priv.Public()); err == nil {
			t.Errorf("expected error when validating public key")
		}
	}
	// Fails with smalller curve
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	if err := ValidatePubKey(priv.Public()); err == nil || !errors.Is(err, goodkey.ErrBadKey) {
		t.Errorf("expected unsupported curve, got %v", err)
	}
	// Fails with unknown curve
	err = ValidatePubKey(&ecdsa.PublicKey{
		Curve: testCurve{},
	})
	if err == nil || !errors.Is(err, goodkey.ErrBadKey) {
		t.Errorf("expected unexpected curve, got %v", err)
	}
}

func TestValidatePubKeyEd25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	if err := ValidatePubKey(pub); err != nil {
		t.Errorf("unexpected error validating public key: %v", err)
	}
	// Only success, ED25519 keys do not support customization
}
