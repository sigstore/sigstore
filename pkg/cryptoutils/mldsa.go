//
// Copyright 2026 The Sigstore Authors.
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
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"filippo.io/mldsa"
)

var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// MarshalMLDSAPrivateKey converts an mldsa.PrivateKey into a PKCS8 ASN.1 DER byte slice
func MarshalMLDSAPrivateKey(key *mldsa.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("empty ML-DSA key")
	}

	var oid asn1.ObjectIdentifier
	switch key.PublicKey().Parameters() {
	case mldsa.MLDSA44():
		oid = oidMLDSA44
	case mldsa.MLDSA65():
		oid = oidMLDSA65
	case mldsa.MLDSA87():
		oid = oidMLDSA87
	default:
		return nil, errors.New("unknown ML-DSA parameter set")
	}

	marshaledKeyBytes, err := asn1.MarshalWithParams(key.Bytes(), "tag:0")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ML-DSA private key bytes: %w", err)
	}

	privKey := pkcs8{
		Version: 0,
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		PrivateKey: marshaledKeyBytes,
	}

	return asn1.Marshal(privKey)
}

// UnmarshalMLDSAPrivateKey converts a PKCS8 ASN.1 DER byte slice into an mldsa.PrivateKey
func UnmarshalMLDSAPrivateKey(derBytes []byte) (*mldsa.PrivateKey, error) {
	var privKey pkcs8
	if remain, err := asn1.Unmarshal(derBytes, &privKey); err != nil {
		return nil, err
	} else if len(remain) > 0 {
		return nil, errors.New("trailing data after ML-DSA private key")
	}

	var params *mldsa.Parameters
	switch {
	case privKey.Algo.Algorithm.Equal(oidMLDSA44):
		params = mldsa.MLDSA44()
	case privKey.Algo.Algorithm.Equal(oidMLDSA65):
		params = mldsa.MLDSA65()
	case privKey.Algo.Algorithm.Equal(oidMLDSA87):
		params = mldsa.MLDSA87()
	default:
		return nil, errors.New("unknown or unsupported ML-DSA parameter set OID")
	}

	var keyBytes []byte
	if remain, err := asn1.UnmarshalWithParams(privKey.PrivateKey, &keyBytes, "tag:0"); err != nil {
		return nil, err
	} else if len(remain) > 0 {
		return nil, errors.New("trailing data after ML-DSA private key OCTET STRING")
	}

	return mldsa.NewPrivateKey(params, keyBytes)
}

// MarshalMLDSAPublicKey converts an mldsa.PublicKey into a PKIX ASN.1 DER byte slice
func MarshalMLDSAPublicKey(key *mldsa.PublicKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("empty ML-DSA public key")
	}

	var oid asn1.ObjectIdentifier
	switch key.Parameters() {
	case mldsa.MLDSA44():
		oid = oidMLDSA44
	case mldsa.MLDSA65():
		oid = oidMLDSA65
	case mldsa.MLDSA87():
		oid = oidMLDSA87
	default:
		return nil, errors.New("unknown ML-DSA parameter set")
	}

	pubKey := subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     key.Bytes(),
			BitLength: len(key.Bytes()) * 8,
		},
	}

	return asn1.Marshal(pubKey)
}

// UnmarshalMLDSAPublicKey converts a PKIX ASN.1 DER byte slice into an mldsa.PublicKey
func UnmarshalMLDSAPublicKey(derBytes []byte) (*mldsa.PublicKey, error) {
	var spki subjectPublicKeyInfo
	if remain, err := asn1.Unmarshal(derBytes, &spki); err != nil {
		return nil, err
	} else if len(remain) > 0 {
		return nil, errors.New("trailing data after ML-DSA public key structure")
	}

	var params *mldsa.Parameters
	switch {
	case spki.Algorithm.Algorithm.Equal(oidMLDSA44):
		params = mldsa.MLDSA44()
	case spki.Algorithm.Algorithm.Equal(oidMLDSA65):
		params = mldsa.MLDSA65()
	case spki.Algorithm.Algorithm.Equal(oidMLDSA87):
		params = mldsa.MLDSA87()
	default:
		return nil, errors.New("unknown or unsupported ML-DSA parameter set OID")
	}

	return mldsa.NewPublicKey(params, spki.SubjectPublicKey.Bytes)
}
