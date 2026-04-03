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

package cryptoutils

import (
	"bytes"
	"crypto"
	"testing"

	"filippo.io/mldsa"
)

func TestMLDSAParameters(t *testing.T) {
	paramsList := []*mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()}

	for _, params := range paramsList {
		t.Run(params.String(), func(t *testing.T) {
			priv, err := mldsa.GenerateKey(params)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			// Test Private Key Marshaling/Unmarshaling (DER)
			derPriv, err := MarshalPrivateKeyToDER(priv)
			if err != nil {
				t.Fatalf("failed to marshal private key to DER: %v", err)
			}

			unmarshaledPriv, err := UnmarshalMLDSAPrivateKey(derPriv)
			if err != nil {
				t.Fatalf("failed to unmarshal private key from DER: %v", err)
			}

			if !bytes.Equal(priv.Bytes(), unmarshaledPriv.Bytes()) {
				t.Fatalf("unmarshaled private key does not match original")
			}

			// Test Private Key Marshaling/Unmarshaling (PEM)
			pemPriv, err := MarshalPrivateKeyToPEM(priv)
			if err != nil {
				t.Fatalf("failed to marshal private key to PEM: %v", err)
			}

			// Test generic UnmarshalPEMToPrivateKey hooks properly into ML-DSA
			parsedGenericPriv, err := UnmarshalPEMToPrivateKey(pemPriv, nil)
			if err != nil {
				t.Fatalf("failed to parse generic private key PEM: %v", err)
			}
			mldsaParsedPriv, ok := parsedGenericPriv.(*mldsa.PrivateKey)
			if !ok {
				t.Fatalf("parsed key is not an mldsa.PrivateKey")
			}
			if !bytes.Equal(priv.Bytes(), mldsaParsedPriv.Bytes()) {
				t.Fatalf("generic unmarshaled private key does not match original")
			}

			// Test Public Key Marshaling/Unmarshaling (DER)
			pub, ok := priv.Public().(*mldsa.PublicKey)
			if !ok {
				t.Fatalf("public key is not an mldsa.PublicKey")
			}
			derPub, err := MarshalPublicKeyToDER(pub)
			if err != nil {
				t.Fatalf("failed to marshal public key to DER: %v", err)
			}

			unmarshaledPub, err := UnmarshalMLDSAPublicKey(derPub)
			if err != nil {
				t.Fatalf("failed to unmarshal public key from DER: %v", err)
			}

			if !bytes.Equal(pub.Bytes(), unmarshaledPub.Bytes()) {
				t.Fatalf("unmarshaled public key does not match original")
			}

			// Test Public Key Marshaling/Unmarshaling (PEM)
			pemPub, err := MarshalPublicKeyToPEM(pub)
			if err != nil {
				t.Fatalf("failed to marshal public key to PEM: %v", err)
			}

			// Test generic UnmarshalPEMToPublicKey hooks properly into ML-DSA
			parsedGenericPub, err := UnmarshalPEMToPublicKey(pemPub)
			if err != nil {
				t.Fatalf("failed to parse generic public key PEM: %v", err)
			}
			mldsaParsedPub, ok := parsedGenericPub.(*mldsa.PublicKey)
			if !ok {
				t.Fatalf("parsed public key is not an mldsa.PublicKey")
			}
			if !bytes.Equal(pub.Bytes(), mldsaParsedPub.Bytes()) {
				t.Fatalf("generic unmarshaled public key does not match original")
			}

			// Verify EqualKeys correctly uses type switch for ML-DSA
			err = EqualKeys(pub, mldsaParsedPub)
			if err != nil {
				t.Fatalf("EqualKeys evaluated identical ML-DSA keys as unequal: %v", err)
			}

			// Generate another key and ensure EqualKeys fails
			priv2, _ := mldsa.GenerateKey(params)
			err = EqualKeys(pub, priv2.Public())
			if err == nil {
				t.Fatalf("EqualKeys evaluated distinct ML-DSA keys as equal")
			}
		})
	}
}

func TestMLDSANegativeMarshaling(t *testing.T) {
	// Nil key tests
	if _, err := MarshalMLDSAPrivateKey(nil); err == nil {
		t.Errorf("expected error marshaling nil ML-DSA private key")
	}
	if _, err := MarshalMLDSAPublicKey(nil); err == nil {
		t.Errorf("expected error marshaling nil ML-DSA public key")
	}

	// Type casting nil interfaces to generic signature methods
	var priv crypto.PrivateKey = (*mldsa.PrivateKey)(nil)
	if _, err := MarshalPrivateKeyToDER(priv); err == nil {
		t.Errorf("expected error marshaling typed nil interface to private DER")
	}

	var pub crypto.PublicKey = (*mldsa.PublicKey)(nil)
	if _, err := MarshalPublicKeyToDER(pub); err == nil {
		t.Errorf("expected error marshaling typed nil interface to public DER")
	}

	// Corrupted byte unmarshaling
	if _, err := UnmarshalMLDSAPrivateKey([]byte("corrupted")); err == nil {
		t.Errorf("expected error unmarshaling corrupted private key DER")
	}
	if _, err := UnmarshalMLDSAPublicKey([]byte("corrupted")); err == nil {
		t.Errorf("expected error unmarshaling corrupted public key DER")
	}
}
