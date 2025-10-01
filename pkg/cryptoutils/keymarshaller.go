//
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

package cryptoutils

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
)

// KeyMarshaller provides an interface for key marshalling and unmarshalling operations.
type KeyMarshaller interface {
	// MarshalPublicKeyToPEM converts a crypto.PublicKey to PEM format
	MarshalPublicKeyToPEM(pub crypto.PublicKey) ([]byte, error)

	// UnmarshalPEMToPublicKey converts PEM bytes to crypto.PublicKey
	UnmarshalPEMToPublicKey(pemBytes []byte) (crypto.PublicKey, error)

	// MarshalPublicKeyToDER converts a crypto.PublicKey to DER format
	MarshalPublicKeyToDER(pub crypto.PublicKey) ([]byte, error)

	// UnmarshalDERToPublicKey converts DER bytes to crypto.PublicKey
	UnmarshalDERToPublicKey(derBytes []byte) (crypto.PublicKey, error)

	// MarshalPrivateKeyToPEM converts a crypto.PrivateKey to PEM format
	MarshalPrivateKeyToPEM(priv crypto.PrivateKey) ([]byte, error)

	// UnmarshalPEMToPrivateKey converts PEM bytes to crypto.PrivateKey
	UnmarshalPEMToPrivateKey(pemBytes []byte, pf PassFunc) (crypto.PrivateKey, error)

	// UnmarshalDERToPrivateKey converts DER bytes to crypto.PrivateKey
	UnmarshalDERToPrivateKey(derBytes []byte) (crypto.PrivateKey, error)
}

// defaultKeyMarshaller implements KeyMarshaller using golang x509 functions
type defaultKeyMarshaller struct{}

// MarshalPublicKeyToPEM converts a crypto.PublicKey to PEM format
func (kp *defaultKeyMarshaller) MarshalPublicKeyToPEM(pub crypto.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("empty key")
	}
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}), nil
}

// UnmarshalPEMToPublicKey converts PEM bytes to crypto.PublicKey
func (kp *defaultKeyMarshaller) UnmarshalPEMToPublicKey(pemBytes []byte) (crypto.PublicKey, error) {
	derBlock, _ := pem.Decode(pemBytes)
	if derBlock == nil {
		return nil, errors.New("PEM decoding failed")
	}
	switch derBlock.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(derBlock.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(derBlock.Bytes)
	default:
		return nil, fmt.Errorf("unknown Public key PEM file type: %v. Are you passing the correct public key?", derBlock.Type)
	}
}

// MarshalPublicKeyToDER converts a crypto.PublicKey to DER format
func (kp *defaultKeyMarshaller) MarshalPublicKeyToDER(pub crypto.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("empty key")
	}
	return x509.MarshalPKIXPublicKey(pub)
}

// UnmarshalDERToPublicKey converts DER bytes to crypto.PublicKey
func (kp *defaultKeyMarshaller) UnmarshalDERToPublicKey(derBytes []byte) (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(derBytes)
}

// MarshalPrivateKeyToPEM converts a crypto.PrivateKey to PEM format
func (kp *defaultKeyMarshaller) MarshalPrivateKeyToPEM(priv crypto.PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("empty key")
	}
	derBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}), nil
}

// UnmarshalPEMToPrivateKey converts PEM bytes to crypto.PrivateKey
func (kp *defaultKeyMarshaller) UnmarshalPEMToPrivateKey(pemBytes []byte, pf PassFunc) (crypto.PrivateKey, error) {
	derBlock, _ := pem.Decode(pemBytes)
	if derBlock == nil {
		return nil, errors.New("PEM decoding failed")
	}
	switch derBlock.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(derBlock.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(derBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(derBlock.Bytes)
	case "ENCRYPTED SIGSTORE PRIVATE KEY", "ENCRYPTED COSIGN PRIVATE KEY":
		derBytes := derBlock.Bytes
		if pf != nil {
			password, err := pf(false)
			if err != nil {
				return nil, err
			}
			if password != nil {
				derBytes, err = encrypted.Decrypt(derBytes, password)
				if err != nil {
					return nil, err
				}
			}
		}
		return x509.ParsePKCS8PrivateKey(derBytes)
	default:
		return nil, fmt.Errorf("unknown private key PEM file type: %v", derBlock.Type)
	}
}

// UnmarshalDERToPrivateKey converts DER bytes to crypto.PrivateKey
func (kp *defaultKeyMarshaller) UnmarshalDERToPrivateKey(derBytes []byte) (crypto.PrivateKey, error) {
	return x509.ParsePKCS8PrivateKey(derBytes)
}

// Global key marshaller instance
var keyMarshaller KeyMarshaller = &defaultKeyMarshaller{}

// SetKeyMarshaller sets the global key marshaller
func SetKeyMarshaller(km KeyMarshaller) {
	if km == nil {
		keyMarshaller = &defaultKeyMarshaller{}
	} else {
		keyMarshaller = km
	}
}

// GetKeyMarshaller returns the global key marshaller
func GetKeyMarshaller() KeyMarshaller {
	return keyMarshaller
}
