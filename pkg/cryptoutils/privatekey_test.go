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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"testing"
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
		tc := tc
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
		tc := tc
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

