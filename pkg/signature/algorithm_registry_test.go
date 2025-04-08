//
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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func TestGetAlgorithmDetails(t *testing.T) {
	details, err := GetAlgorithmDetails(v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256)
	if err != nil {
		t.Errorf("unexpected error getting algorithm details: %v", err)
	}
	if details.GetSignatureAlgorithm() != v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256 {
		t.Errorf("unexpected signature algorithm")
	}
	if details.GetKeyType() != ECDSA {
		t.Errorf("unexpected key algorithm")
	}
	if details.GetHashType() != crypto.SHA256 {
		t.Errorf("unexpected hash algorithm")
	}
	if details.GetProtoHashType() != v1.HashAlgorithm_SHA2_256 {
		t.Errorf("unxpected proto hash algorithm")
	}
	curve, err := details.GetECDSACurve()
	if err != nil {
		t.Errorf("unexpected error getting ecdsa curve")
	}
	if (*curve) != elliptic.P256() {
		t.Errorf("unexpected curve")
	}
	_, err = details.GetRSAKeySize()
	if err == nil {
		t.Errorf("unexpected success getting rsa key size")
	}
}

func TestAlgorithmRegistryConfig(t *testing.T) {
	config, err := NewAlgorithmRegistryConfig([]v1.PublicKeyDetails{
		v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
		v1.PublicKeyDetails_PKIX_ED25519,
		v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256,
	})
	if err != nil {
		t.Errorf("unexpected error creating algorithm registry config: %v", err)
	}

	// Test some permitted signature algorithms.
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("unexpected error creating ecdsa key: %v", err)
	}
	isPermitted, err := config.IsAlgorithmPermitted(&ecdsaKey.PublicKey, crypto.SHA256)
	if err != nil {
		t.Errorf("unexpected error checking registry for ecdsa-sha2-256-nistp256: %v", err)
	}
	if !isPermitted {
		t.Errorf("unexpected error permitting ecdsa-sha2-256-nistp256")
	}

	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("unexpected error creating ed25519 key: %v", err)
	}
	isPermitted, err = config.IsAlgorithmPermitted(ed25519PubKey, crypto.Hash(0))
	if err != nil {
		t.Errorf("unexpected error checking registry for ed25519: %v", err)
	}
	if !isPermitted {
		t.Errorf("unexpected error permitting ed25519")
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("unexpected error creating rsa key: %v", err)
	}
	isPermitted, err = config.IsAlgorithmPermitted(&rsaKey.PublicKey, crypto.SHA256)
	if err != nil {
		t.Errorf("unexpected error checking registry for rsa-sign-pkcs1-2048-sha256: %v", err)
	}
	if !isPermitted {
		t.Errorf("unexpected error permitting rsa-sign-pkcs1-2048-sha256")
	}

	// Try some permitted public key algorithms with incorrect hash algorithms.
	isPermitted, err = config.IsAlgorithmPermitted(&ecdsaKey.PublicKey, crypto.SHA512)
	if err != nil {
		t.Errorf("unexpected error checking registry for ecdsa with wrong hash: %v", err)
	}
	if isPermitted {
		t.Errorf("unexpected success permitting ecdsa with wrong hash")
	}
	isPermitted, err = config.IsAlgorithmPermitted(ed25519PubKey, crypto.SHA256)
	if err != nil {
		t.Errorf("unexpected error checking registry for ed25519 with wrong hash: %v", err)
	}
	if isPermitted {
		t.Errorf("unexpected success permitting ed25519 with wrong hash")
	}
	isPermitted, err = config.IsAlgorithmPermitted(&rsaKey.PublicKey, crypto.SHA512)
	if err != nil {
		t.Errorf("unexpected error checking registry for rsa with wrong hash: %v", err)
	}
	if isPermitted {
		t.Errorf("unexpected success permitting rsa with wrong hash")
	}

	// Try an ECDSA key with the wrong curve.
	ecda384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Errorf("unexpected error creating ecdsa p384 key: %v", err)
	}
	isPermitted, err = config.IsAlgorithmPermitted(&ecda384Key.PublicKey, crypto.SHA256)
	if err != nil {
		t.Errorf("unexpected error checking registry for ed25519 with wrong curve")
	}
	if isPermitted {
		t.Errorf("unexpected success permitting ed25519 with wrong curve")
	}

	// Try an RSA key with the wrong size.
	rsa4096Key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Errorf("unexpected error creating rsa key: %v", err)
	}
	isPermitted, err = config.IsAlgorithmPermitted(&rsa4096Key.PublicKey, crypto.SHA256)
	if err != nil {
		t.Errorf("unexpected error checking registry for rsa with wrong size: %v", err)
	}
	if isPermitted {
		t.Errorf("unexpected success permitting rsa with wrong size")
	}
}

func TestSignatureAlgorithmFlagRoundtrip(t *testing.T) {
	expectedEnums := []v1.PublicKeyDetails{
		v1.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512,
		v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256,
		v1.PublicKeyDetails_PKIX_ED25519_PH,
	}

	// Format enums as flags.
	actualFlags := make([]string, 0, len(expectedEnums))
	for _, a := range expectedEnums {
		flag, err := FormatSignatureAlgorithmFlag(a)
		if err != nil {
			t.Errorf("unexpected error formatting signature algorithm flag: %v", err)
		}
		actualFlags = append(actualFlags, flag)
	}

	// Check that the flags look ok.
	expectedFlags := []string{"ecdsa-sha2-512-nistp521", "rsa-sign-pkcs1-2048-sha256", "ed25519-ph"}
	for i, actualFlag := range actualFlags {
		expectedFlag := expectedFlags[i]
		if actualFlag != expectedFlag {
			t.Errorf("unexpected flag, expected %s, got %s", expectedFlag, actualFlag)
		}
	}

	// Convert back to enums.
	actualEnums := make([]v1.PublicKeyDetails, 0, len(expectedEnums))
	for _, actualFlag := range actualFlags {
		actualEnum, err := ParseSignatureAlgorithmFlag(actualFlag)
		if err != nil {
			t.Errorf("unexpected error parsing signature algorithm flag: %s", actualFlag)
		}
		actualEnums = append(actualEnums, actualEnum)
	}

	// Compare with the enum values that we started off with.
	for i, actualAlgorithm := range actualEnums {
		expectedAlgorithm := expectedEnums[i]
		if actualAlgorithm != expectedAlgorithm {
			t.Errorf("unexpected enum, expected %s, got %s", expectedAlgorithm, actualAlgorithm)
		}
	}
}

func TestGetDefaultPublicKeyDetails(t *testing.T) {
	tts := []struct {
		name     string
		key      func() crypto.PublicKey
		opts     []LoadOption
		expected v1.PublicKeyDetails
	}{
		{
			name: "ecdsa-p256",
			key: func() crypto.PublicKey {
				ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Errorf("unexpected error creating ecdsa key: %v", err)
				}
				return &ecdsaKey.PublicKey
			},
			expected: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
		},
		{
			name: "ecdsa-p384",
			key: func() crypto.PublicKey {
				ecdsaKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Errorf("unexpected error creating ecdsa key: %v", err)
				}
				return &ecdsaKey.PublicKey
			},
			expected: v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384,
		},
		{
			name: "rsa-2048",
			key: func() crypto.PublicKey {
				rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Errorf("unexpected error creating rsa key: %v", err)
				}
				return &rsaKey.PublicKey
			},
			expected: v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256,
		},
		{
			name: "ed25519",
			key: func() crypto.PublicKey {
				ed25519Key, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Errorf("unexpected error creating ed25519 key: %v", err)
				}
				return ed25519Key
			},
			expected: v1.PublicKeyDetails_PKIX_ED25519,
		},
		{
			name: "ed25519-ph",
			key: func() crypto.PublicKey {
				ed25519Key, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Errorf("unexpected error creating ed25519 key: %v", err)
				}
				return ed25519Key
			},
			opts:     []LoadOption{options.WithED25519ph()},
			expected: v1.PublicKeyDetails_PKIX_ED25519_PH,
		},
		{
			name: "rsa-2048-pss",
			key: func() crypto.PublicKey {
				rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Errorf("unexpected error creating rsa key: %v", err)
				}
				return &rsaKey.PublicKey
			},
			opts:     []LoadOption{options.WithRSAPSS(&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256})},
			expected: v1.PublicKeyDetails_PKIX_RSA_PSS_2048_SHA256,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			key := tt.key()
			keyDetails, err := GetDefaultPublicKeyDetails(key, tt.opts...)
			if err != nil {
				t.Errorf("unexpected error getting default public key details: %v", err)
			}
			if keyDetails != tt.expected {
				t.Errorf("unexpected signature algorithm")
			}

			algorithmDetails, err := GetDefaultAlgorithmDetails(key, tt.opts...)
			if err != nil {
				t.Errorf("unexpected error getting default algorithm details: %v", err)
			}
			if algorithmDetails.GetSignatureAlgorithm() != keyDetails {
				t.Errorf("unexpected signature algorithm")
			}
		})
	}
}

func TestHashingAlgorithmMatches(t *testing.T) {
	for _, details := range supportedAlgorithms {
		switch details.hashType {
		case crypto.SHA256:
			if details.protoHashType != v1.HashAlgorithm_SHA2_256 {
				t.Errorf("expected SHA256 to match proto SHA2_256 in: %s", details.flagValue)
			}
		case crypto.SHA384:
			if details.protoHashType != v1.HashAlgorithm_SHA2_384 {
				t.Errorf("expected SHA384 to match proto SHA2_384 in: %s", details.flagValue)
			}
		case crypto.SHA512:
			if details.protoHashType != v1.HashAlgorithm_SHA2_512 {
				t.Errorf("expected SHA512 to match proto SHA2_512 in: %s", details.flagValue)
			}
		case crypto.Hash(0):
			if details.protoHashType != v1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
				t.Errorf("expected Hash(0) to match proto HASH_ALGORITHM_UNSPECIFIED in: %s", details.flagValue)
			}
		default:
			t.Errorf("unrecognized hash type: %v", details.hashType)
		}
	}
}
