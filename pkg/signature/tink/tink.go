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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkecdsa "github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	tinked25519 "github.com/tink-crypto/tink-go/v2/signature/ed25519"
	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
)

func curveFromTinkECDSACurveType(curveType tinkecdsa.CurveType) (elliptic.Curve, error) {
	switch curveType {
	case tinkecdsa.NistP256:
		return elliptic.P256(), nil
	case tinkecdsa.NistP384:
		return elliptic.P384(), nil
	case tinkecdsa.NistP521:
		return elliptic.P521(), nil
	default:
		// Should never happen.
		return nil, fmt.Errorf("unsupported curve: %v", curveType)
	}
}

func paramsFromTinkMLDSAInstance(instance tinkmldsa.Instance) (mldsa.Parameters, error) {
	switch instance {
	case tinkmldsa.MLDSA44:
		return mldsa.MLDSA44(), nil
	case tinkmldsa.MLDSA65:
		return mldsa.MLDSA65(), nil
	case tinkmldsa.MLDSA87:
		return mldsa.MLDSA87(), nil
	default:
		// Should never happen.
		return mldsa.Parameters{}, fmt.Errorf("unsupported instance: %v", instance)
	}
}

// KeyHandleToSigner constructs a [crypto.Signer] from a Tink [keyset.Handle]'s
// primary key.
//
// NOTE: Tink validates keys on [keyset.Handle] creation.
func KeyHandleToSigner(kh *keyset.Handle) (crypto.Signer, error) {
	primary, err := kh.Primary()
	if err != nil {
		return nil, err
	}

	switch privateKey := primary.Key().(type) {
	case *tinkecdsa.PrivateKey:
		curveParams, ok := privateKey.Parameters().(*tinkecdsa.Parameters)
		if !ok {
			return nil, fmt.Errorf("error asserting ecdsa parameters")
		}
		curve, err := curveFromTinkECDSACurveType(curveParams.CurveType())
		if err != nil {
			return nil, err
		}

		return ecdsa.ParseRawPrivateKey(curve, privateKey.PrivateKeyValue().Data(insecuresecretdataaccess.Token{}))
	case *tinked25519.PrivateKey:
		return ed25519.NewKeyFromSeed(privateKey.PrivateKeyBytes().Data(insecuresecretdataaccess.Token{})), nil
	case *tinkmldsa.PrivateKey:
		mldsaParams, ok := privateKey.Parameters().(*tinkmldsa.Parameters)
		if !ok {
			return nil, fmt.Errorf("error asserting mldsa parameters")
		}
		params, err := paramsFromTinkMLDSAInstance(mldsaParams.Instance())
		if err != nil {
			return nil, err
		}

		return mldsa.NewPrivateKey(params, privateKey.PrivateKeyBytes().Data(insecuresecretdataaccess.Token{}))
	default:
		return nil, fmt.Errorf("unsupported key type: %T", primary.Key())
	}
}
