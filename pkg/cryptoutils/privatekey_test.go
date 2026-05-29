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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/youmark/pkcs8"
)

func verifyRSAKeyPEMs(t *testing.T, privPEM, pubPEM []byte, expectedKeyLengthBits int, testPassFunc PassFunc) {
	t.Helper()

	if priv, err := UnmarshalPEMToPrivateKey(privPEM, testPassFunc); err != nil {
		t.Errorf("UnmarshalPEMToPrivateKey returned error: %v", err)
	} else if rsaPriv, ok := priv.(*rsa.PrivateKey); !ok {
		t.Errorf("expected unmarshaled key to be of type *rsa.PrivateKey, was %T", priv)
	} else if rsaPriv.Size() != expectedKeyLengthBits/8 {
		t.Errorf("private key size was %d, expected %d", rsaPriv.Size(), expectedKeyLengthBits/8)
	}

	if pub, err := UnmarshalPEMToPublicKey(pubPEM); err != nil {
		t.Errorf("UnmarshalPEMToPublicKey returned error: %v", err)
	} else if rsaPub, ok := pub.(*rsa.PublicKey); !ok {
		t.Errorf("expected unmarshaled public key to be of type *rsa.PublicKey, was %T", pub)
	} else if rsaPub.Size() != expectedKeyLengthBits/8 {
		t.Errorf("public key size was %d, expected %d", rsaPub.Size(), expectedKeyLengthBits/8)
	}
}

func TestGeneratePEMEncodedRSAKeyPair(t *testing.T) {
	t.Parallel()

	const testKeyBits = 2048

	testCases := []struct {
		name            string
		initialPassFunc PassFunc
		goodPFs         []PassFunc
		badPFs          []PassFunc
	}{
		{
			name:            "encrypted",
			initialPassFunc: StaticPasswordFunc([]byte("TestGenerateEncryptedRSAKeyPair password")),
			badPFs:          []PassFunc{SkipPassword, nil},
		},
		{
			name:            "nil pass func",
			initialPassFunc: nil,
			goodPFs:         []PassFunc{SkipPassword, nil},
		},
		{
			name:            "SkipPassword func",
			initialPassFunc: SkipPassword,
			goodPFs:         []PassFunc{SkipPassword, nil},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			privPEM, pubPEM, err := GeneratePEMEncodedRSAKeyPair(testKeyBits, tc.initialPassFunc)
			if err != nil {
				t.Fatalf("GeneratePEMEncodedRSAKeyPair returned error: %v", err)
			}

			for _, badPF := range tc.badPFs {
				if priv, err := UnmarshalPEMToPrivateKey(privPEM, SkipPassword); err == nil {
					t.Errorf("UnmarshalPEMToPrivateKey(pf=%v) should have returned error, got: %v", badPF, priv)
				}
			}
			for _, goodPF := range tc.goodPFs {
				if _, err := UnmarshalPEMToPrivateKey(privPEM, goodPF); err != nil {
					t.Errorf("UnmarshalPEMToPrivateKey(pf=%v) returned error: %v", goodPF, err)
				}
			}
			verifyRSAKeyPEMs(t, privPEM, pubPEM, testKeyBits, tc.initialPassFunc)
		})
	}
}

func verifyECDSAKeyPEMs(t *testing.T, privPEM, pubPEM []byte, expectedCurve elliptic.Curve, testPassFunc PassFunc) {
	t.Helper()

	if priv, err := UnmarshalPEMToPrivateKey(privPEM, testPassFunc); err != nil {
		t.Errorf("UnmarshalPEMToPrivateKey returned error: %v", err)
	} else if ecdsaPriv, ok := priv.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected unmarshaled key to be of type *ecdsa.PrivateKey, was %T", priv)
	} else if ecdsaPriv.Curve != expectedCurve {
		t.Errorf("expected elliptic curve %v, got %d", expectedCurve, ecdsaPriv.Curve)
	}

	if pub, err := UnmarshalPEMToPublicKey(pubPEM); err != nil {
		t.Errorf("UnmarshalPEMToPublicKey returned error: %v", err)
	} else if ecdsaPub, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Errorf("expected unmarshaled key to be of type *ecdsa.PublicKey, was %T", pub)
	} else if ecdsaPub.Curve != expectedCurve {
		t.Errorf("expected elliptic curve %v, got %d", expectedCurve, ecdsaPub.Curve)
	}
}

func TestGeneratePEMEncodedECDSAKeyPair(t *testing.T) {
	t.Parallel()

	testCurve := elliptic.P256()

	testCases := []struct {
		name            string
		initialPassFunc PassFunc
		goodPFs         []PassFunc
		badPFs          []PassFunc
	}{
		{
			name:            "encrypted",
			initialPassFunc: StaticPasswordFunc([]byte("TestGenerateEncryptedRSAKeyPair password")),
			badPFs:          []PassFunc{SkipPassword, nil},
		},
		{
			name:            "nil pass func",
			initialPassFunc: nil,
			goodPFs:         []PassFunc{SkipPassword, nil},
		},
		{
			name:            "SkipPassword func",
			initialPassFunc: SkipPassword,
			goodPFs:         []PassFunc{SkipPassword, nil},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			privPEM, pubPEM, err := GeneratePEMEncodedECDSAKeyPair(testCurve, tc.initialPassFunc)
			if err != nil {
				t.Fatalf("GeneratePEMEncodedRSAKeyPair returned error: %v", err)
			}

			for _, badPF := range tc.badPFs {
				if priv, err := UnmarshalPEMToPrivateKey(privPEM, SkipPassword); err == nil {
					t.Errorf("UnmarshalPEMToPrivateKey(pf=%v) should have returned error, got: %v", badPF, priv)
				}
			}
			for _, goodPF := range tc.goodPFs {
				if _, err := UnmarshalPEMToPrivateKey(privPEM, goodPF); err != nil {
					t.Errorf("UnmarshalPEMToPrivateKey(pf=%v) returned error: %v", goodPF, err)
				}
			}
			verifyECDSAKeyPEMs(t, privPEM, pubPEM, testCurve, tc.initialPassFunc)
		})
	}
}

func verifyPrivateKeyPEMRoundtrip(t *testing.T, pub crypto.PrivateKey) {
	t.Helper()
	pemBytes, err := MarshalPrivateKeyToPEM(pub)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyToPEM returned error: %v", err)
	}
	rtPub, err := UnmarshalPEMToPrivateKey(pemBytes, nil)
	if err != nil {
		t.Fatalf("UnmarshalPEMToPrivateKey returned error: %v", err)
	}
	if d := cmp.Diff(pub, rtPub); d != "" {
		t.Errorf("round-tripped public key was malformed (-before +after): %s", d)
	}
}

func TestECDSAPrivateKeyPEMRoundtrip(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	verifyPrivateKeyPEMRoundtrip(t, priv)
}

func TestEd25519PrivateKeyPEMRoundtrip(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	verifyPrivateKeyPEMRoundtrip(t, priv)
}

func TestRSAPrivateKeyPEMRoundtrip(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	verifyPrivateKeyPEMRoundtrip(t, priv)
}

func TestUnmarshalPEMToPrivateKey(t *testing.T) {
	// test PKCS#8 PEM-encoded private keys
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	pkcs8PrivateKey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey failed: %v", err)
	}
	pkcs8PEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8PrivateKey,
	})
	k, err := UnmarshalPEMToPrivateKey(pkcs8PEMBlock, nil)
	if err != nil {
		t.Fatalf("UnmarshalPEMToPrivateKey for PKCS#8 failed: %v", err)
	}
	if !priv.Equal(k) {
		t.Fatalf("private keys for PKCS#8 are not equal")
	}

	// test PKCS#1 PEM-encoded RSA private keys
	priv, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	rsaPrivKey := x509.MarshalPKCS1PrivateKey(priv)
	pkcs1PEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: rsaPrivKey,
	})
	k, err = UnmarshalPEMToPrivateKey(pkcs1PEMBlock, nil)
	if err != nil {
		t.Fatalf("UnmarshalPEMToPrivateKey for PKCS#1 failed: %v", err)
	}
	if !priv.Equal(k) {
		t.Fatalf("private keys for PKCS1 are not equal")
	}

	// test SEC 1 EC private keys
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	ecPrivKey, err := x509.MarshalECPrivateKey(ecdsaKey)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey failed: %v", err)
	}
	ecPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecPrivKey,
	})
	k, err = UnmarshalPEMToPrivateKey(ecPEMBlock, nil)
	if err != nil {
		t.Fatalf("UnmarshalPEMToPrivateKey for SEC 1 failed: %v", err)
	}
	if !ecdsaKey.Equal(k) {
		t.Fatalf("private keys for SEC 1 (EC) are not equal")
	}

	// test Sigstore formatted private keys
	privSigstorePEM, _, err := GeneratePEMEncodedECDSAKeyPair(elliptic.P256(), StaticPasswordFunc([]byte("pw")))
	if err != nil {
		t.Fatalf("GeneratePEMEncodedECDSAKeyPair failed: %v", err)
	}
	_, err = UnmarshalPEMToPrivateKey(privSigstorePEM, StaticPasswordFunc([]byte("pw")))
	if err != nil {
		t.Fatalf("UnmarshalPEMToPrivateKey for Sigstore encoded key failed: %v", err)
	}

	// test other PEM formats return an error
	invalidPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: rsaPrivKey,
	})
	_, err = UnmarshalPEMToPrivateKey(invalidPEMBlock, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown private key PEM file type") {
		t.Fatalf("expected error unmarshalling invalid PEM block, got: %v", err)
	}

	// test legacy encrypted private keys (RSA)
	legacyPassword := []byte("legacy-password")
	encRSABlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", rsaPrivKey, legacyPassword, x509.PEMCipherAES256) //nolint:staticcheck
	if err != nil {
		t.Fatalf("failed to encrypt PEM block: %v", err)
	}
	encRSAPEM := pem.EncodeToMemory(encRSABlock)

	// Decrypting without password should fail
	_, err = UnmarshalPEMToPrivateKey(encRSAPEM, nil)
	if err == nil {
		t.Fatal("expected decryption failure without password function")
	}

	// Decrypting with incorrect password should fail
	_, err = UnmarshalPEMToPrivateKey(encRSAPEM, StaticPasswordFunc([]byte("wrong-password")))
	if err == nil {
		t.Fatal("expected decryption failure with wrong password")
	}

	// Decrypting with correct password should succeed
	decryptedKey, err := UnmarshalPEMToPrivateKey(encRSAPEM, StaticPasswordFunc(legacyPassword))
	if err != nil {
		t.Fatalf("UnmarshalPEMToPrivateKey failed: %v", err)
	}
	if !priv.Equal(decryptedKey) {
		t.Fatal("decrypted private key does not match original key")
	}

	// test standard encrypted private keys using PKCS#8 ("ENCRYPTED PRIVATE KEY")
	pkcs8Password := []byte("pkcs8-password")
	encBytes, err := pkcs8.ConvertPrivateKeyToPKCS8(priv, pkcs8Password)
	if err != nil {
		t.Fatalf("failed to convert private key to encrypted PKCS#8: %v", err)
	}
	encBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encBytes,
	})

	// Decrypting without password should fail
	_, err = UnmarshalPEMToPrivateKey(encBlock, nil)
	if err == nil {
		t.Fatal("expected decryption failure without password function")
	}

	// Decrypting with incorrect password should fail
	_, err = UnmarshalPEMToPrivateKey(encBlock, StaticPasswordFunc([]byte("wrong-password")))
	if err == nil {
		t.Fatal("expected decryption failure with wrong password")
	}

	// Decrypting with correct password should succeed
	decryptedPKCS8Key, err := UnmarshalPEMToPrivateKey(encBlock, StaticPasswordFunc(pkcs8Password))
	if err != nil {
		t.Fatalf("UnmarshalPEMToPrivateKey failed: %v", err)
	}
	if !priv.Equal(decryptedPKCS8Key) {
		t.Fatal("decrypted private key does not match original key")
	}

	// test legacy encrypted ECDSA private key (EC PRIVATE KEY)
	ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	derECDSA, err := x509.MarshalECPrivateKey(ecdsaPrivKey)
	if err != nil {
		t.Fatalf("failed to marshal EC private key: %v", err)
	}
	encECDSABlock, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", derECDSA, legacyPassword, x509.PEMCipherAES256) //nolint:staticcheck
	if err != nil {
		t.Fatalf("failed to encrypt EC PEM block: %v", err)
	}
	encECDSAPEM := pem.EncodeToMemory(encECDSABlock)

	decryptedECDSAKey, err := UnmarshalPEMToPrivateKey(encECDSAPEM, StaticPasswordFunc(legacyPassword))
	if err != nil {
		t.Fatalf("UnmarshalPEMToPrivateKey failed for legacy EC: %v", err)
	}
	if !ecdsaPrivKey.Equal(decryptedECDSAKey) {
		t.Fatal("decrypted legacy EC private key does not match original key")
	}

	// test standard encrypted ECDSA private key using PKCS#8 ("ENCRYPTED PRIVATE KEY")
	encECDSAPBytes, err := pkcs8.ConvertPrivateKeyToPKCS8(ecdsaPrivKey, pkcs8Password)
	if err != nil {
		t.Fatalf("failed to convert EC private key to encrypted PKCS#8: %v", err)
	}
	encECDSABlockPKCS8 := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encECDSAPBytes,
	})

	decryptedECDSAPKCS8Key, err := UnmarshalPEMToPrivateKey(encECDSABlockPKCS8, StaticPasswordFunc(pkcs8Password))
	if err != nil {
		t.Fatalf("UnmarshalPEMToPrivateKey failed for EC PKCS8: %v", err)
	}
	if !ecdsaPrivKey.Equal(decryptedECDSAPKCS8Key) {
		t.Fatal("decrypted EC PKCS8 private key does not match original key")
	}

	// test standard encrypted Ed25519 private key using PKCS#8 ("ENCRYPTED PRIVATE KEY")
	_, ed25519PrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	encEdBytes, err := pkcs8.ConvertPrivateKeyToPKCS8(ed25519PrivKey, pkcs8Password)
	if err != nil {
		t.Fatalf("failed to convert Ed25519 private key to encrypted PKCS#8: %v", err)
	}
	encEdBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encEdBytes,
	})

	decryptedEdKey, err := UnmarshalPEMToPrivateKey(encEdBlock, StaticPasswordFunc(pkcs8Password))
	if err != nil {
		t.Fatalf("UnmarshalPEMToPrivateKey failed for Ed25519: %v", err)
	}
	if !ed25519PrivKey.Equal(decryptedEdKey) {
		t.Fatal("decrypted Ed25519 private key does not match original key")
	}
}
