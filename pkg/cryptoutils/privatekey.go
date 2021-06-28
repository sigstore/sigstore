//
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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/theupdateframework/go-tuf/encrypted"
)

const (
	PrivateKeyPEMType                PEMType = "PRIVATE KEY"
	EncryptedCosignPrivateKeyPEMType PEMType = "ENCRYPTED COSIGN PRIVATE KEY"
)

func GenerateEncryptedKeyPair(pf PassFunc) ([]byte, []byte, error) {
	priv := &rsa.PrivateKey{}

	derKey, err := MarshalPrivateKeyToDER(priv)
	if err != nil {
		return nil, nil, err
	}

	password, err := pf(true)
	if err != nil {
		return nil, nil, err
	}

	var derBytes []byte
	if password != nil {
		derBytes, err = encrypted.Encrypt(derKey, password)
		if err != nil {
			return nil, nil, err
		}
	} else {
		derBytes = derKey
	}

	privPEM := PEMEncode(EncryptedCosignPrivateKeyPEMType, derBytes)
	pubPEM, err := MarshalPublicKeyToPEM(priv.Public())
	if err != nil {
		return nil, nil, err
	}
	return privPEM, pubPEM, nil
}

// UnmarshalPEMToPrivateKey converts a PEM-encoded byte slice into a crypto.PrivateKey
func UnmarshalPEMToPrivateKey(pemBytes []byte, pf PassFunc) (crypto.PrivateKey, error) {
	derBlock, _ := pem.Decode(pemBytes)
	if derBlock == nil {
		return nil, errors.New("PEM decoding failed")
	}
	switch derBlock.Type {
	case string(PrivateKeyPEMType):
		return x509.ParsePKCS8PrivateKey(derBlock.Bytes)
	case string(EncryptedCosignPrivateKeyPEMType):
		password, err := pf(false)
		if err != nil {
			return nil, err
		}

		keyBytes := derBlock.Bytes
		if password != nil {
			keyBytes, err = encrypted.Decrypt(derBlock.Bytes, password)
			if err != nil {
				return nil, err
			}
		}
		return x509.ParsePKCS8PrivateKey(keyBytes)
	}
	return nil, fmt.Errorf("unknown PEM file type: %v", derBlock.Type)
}

// MarshalPrivateKeyToDER converts a crypto.PrivateKey into a PKCS8 ASN.1 DER byte slice
func MarshalPrivateKeyToDER(priv crypto.PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("empty key")
	}
	return x509.MarshalPKCS8PrivateKey(priv)
}

// MarshalPrivateKeyToPEM converts a crypto.PrivateKey into a PEM-encoded byte slice
func MarshalPrivateKeyToPEM(priv crypto.PrivateKey) ([]byte, error) {
	derBytes, err := MarshalPrivateKeyToDER(priv)
	if err != nil {
		return nil, err
	}
	return PEMEncode(PrivateKeyPEMType, derBytes), nil
}
