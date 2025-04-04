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
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

// PublicKeyType represents the public key algorithm for a given signature algorithm.
type PublicKeyType uint

const (
	// RSA public key
	RSA PublicKeyType = iota
	// ECDSA public key
	ECDSA
	// ED25519 public key
	ED25519
)

// From crypto/x509/x509.go
// OIDs for signature algorithms
//
//	pkcs-1 OBJECT IDENTIFIER ::= {
//		iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
//
// RFC 4055 3.1 RSASSA-PSS Public Keys
//
//	id-RSASSA-PSS OBJECT IDENTIFIER ::= { pkcs-1 10 }
//
// RFC 4055 5 PKCS #1 Version 1.5
//
//	sha256WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 11 }
//
// RFC 5758 3.2 ECDSA Signature Algorithm
//
//	ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//		us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
//
//	ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//		us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }
//
//	ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//		us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }
//
// RFC 8410 3 Curve25519 and Curve448 Algorithm Identifiers
//
//	id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
var (
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSignatureEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// RSAKeySize represents the size of an RSA public key in bits.
type RSAKeySize int

// AlgorithmDetails exposes relevant information for a given signature algorithm.
type AlgorithmDetails struct {
	// knownAlgorithm is the signature algorithm that the following details refer to.
	knownAlgorithm v1.PublicKeyDetails

	// keyType is the public key algorithm being used.
	keyType PublicKeyType

	// hashType is the hash algorithm being used.
	hashType crypto.Hash

	// oid is the object identifier for the key algorithm as specified by well-known RFCs
	oid asn1.ObjectIdentifier

	// extraKeyParams contains any extra parameters required to check a given public key against this entry.
	//
	// The underlying type of these parameters is dependent on the keyType.
	// For example, ECDSA algorithms will store an elliptic curve here whereas, RSA keys will store the key size.
	// Algorithms that don't require any extra parameters leave this set to nil.
	extraKeyParams any

	// flagValue is a string representation of the signature algorithm that follows the naming conventions of CLI
	// arguments that are used for Sigstore services.
	flagValue string
}

// GetSignatureAlgorithm returns the PublicKeyDetails associated with the algorithm details.
func (a AlgorithmDetails) GetSignatureAlgorithm() v1.PublicKeyDetails {
	return a.knownAlgorithm
}

// GetKeyType returns the PublicKeyType for the algorithm details.
func (a AlgorithmDetails) GetKeyType() PublicKeyType {
	return a.keyType
}

// GetHashType returns the hash algorithm that should be used with this algorithm.
func (a AlgorithmDetails) GetHashType() crypto.Hash {
	return a.hashType
}

// GetOID returns the RFC-specified OID for this algorithm.
func (a AlgorithmDetails) GetOID() asn1.ObjectIdentifier {
	return a.oid
}

// GetRSAKeySize returns the RSA key size for the algorithm details, if the key type is RSA.
func (a AlgorithmDetails) GetRSAKeySize() (RSAKeySize, error) {
	if a.keyType != RSA {
		return 0, fmt.Errorf("unable to retrieve RSA key size for key type: %T", a.keyType)
	}
	rsaKeySize, ok := a.extraKeyParams.(RSAKeySize)
	if !ok {
		// This should be unreachable.
		return 0, fmt.Errorf("unable to retrieve key size for RSA, malformed algorithm details?: %T", a.keyType)
	}
	return rsaKeySize, nil
}

// GetECDSACurve returns the elliptic curve for the algorithm details, if the key type is ECDSA.
func (a AlgorithmDetails) GetECDSACurve() (*elliptic.Curve, error) {
	if a.keyType != ECDSA {
		return nil, fmt.Errorf("unable to retrieve ECDSA curve for key type: %T", a.keyType)
	}
	ecdsaCurve, ok := a.extraKeyParams.(elliptic.Curve)
	if !ok {
		// This should be unreachable.
		return nil, fmt.Errorf("unable to retrieve curve for ECDSA, malformed algorithm details?: %T", a.keyType)
	}
	return &ecdsaCurve, nil
}

func (a AlgorithmDetails) checkKey(pubKey crypto.PublicKey) (bool, error) {
	switch a.keyType {
	case RSA:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return false, nil
		}
		keySize, err := a.GetRSAKeySize()
		if err != nil {
			return false, err
		}
		return rsaKey.Size()*8 == int(keySize), nil
	case ECDSA:
		ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return false, nil
		}
		curve, err := a.GetECDSACurve()
		if err != nil {
			return false, err
		}
		return ecdsaKey.Curve == *curve, nil
	case ED25519:
		_, ok := pubKey.(ed25519.PublicKey)
		return ok, nil
	}
	return false, fmt.Errorf("unrecognized key type: %T", a.keyType)
}

func (a AlgorithmDetails) checkHash(hashType crypto.Hash) bool {
	return a.hashType == hashType
}

// Note that deprecated options in PublicKeyDetails are not included in this
// list, including PKCS1v1.5 encoded RSA. Refer to the v1.PublicKeyDetails enum
// for more details.
var supportedAlgorithms = []AlgorithmDetails{
	{v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256, RSA, crypto.SHA256, oidSignatureSHA256WithRSA, RSAKeySize(2048), "rsa-sign-pkcs1-2048-sha256"},
	{v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256, RSA, crypto.SHA256, oidSignatureSHA256WithRSA, RSAKeySize(3072), "rsa-sign-pkcs1-3072-sha256"},
	{v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256, RSA, crypto.SHA256, oidSignatureSHA256WithRSA, RSAKeySize(4096), "rsa-sign-pkcs1-4096-sha256"},
	{v1.PublicKeyDetails_PKIX_RSA_PSS_2048_SHA256, RSA, crypto.SHA256, oidSignatureRSAPSS, RSAKeySize(2048), "rsa-sign-pss-2048-sha256"},
	{v1.PublicKeyDetails_PKIX_RSA_PSS_3072_SHA256, RSA, crypto.SHA256, oidSignatureRSAPSS, RSAKeySize(3072), "rsa-sign-pss-3072-sha256"},
	{v1.PublicKeyDetails_PKIX_RSA_PSS_4096_SHA256, RSA, crypto.SHA256, oidSignatureRSAPSS, RSAKeySize(4096), "rsa-sign-pss-4092-sha256"},
	{v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, ECDSA, crypto.SHA256, oidSignatureECDSAWithSHA256, elliptic.P256(), "ecdsa-sha2-256-nistp256"},
	{v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384, ECDSA, crypto.SHA384, oidSignatureECDSAWithSHA384, elliptic.P384(), "ecdsa-sha2-384-nistp384"},
	{v1.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512, ECDSA, crypto.SHA512, oidSignatureECDSAWithSHA512, elliptic.P521(), "ecdsa-sha2-512-nistp521"},
	{v1.PublicKeyDetails_PKIX_ED25519, ED25519, crypto.Hash(0), oidSignatureEd25519, nil, "ed25519"},
	{v1.PublicKeyDetails_PKIX_ED25519_PH, ED25519, crypto.SHA512, oidSignatureEd25519, nil, "ed25519-ph"}, // no well-known OID for ed25519-ph
}

// AlgorithmRegistryConfig represents a set of permitted algorithms for a given Sigstore service or component.
//
// Individual services may wish to restrict what algorithms are allowed to a subset of what is covered in the algorithm
// registry (represented by v1.PublicKeyDetails).
type AlgorithmRegistryConfig struct {
	permittedAlgorithms []AlgorithmDetails
}

// GetAlgorithmDetails retrieves a set of details for a given v1.PublicKeyDetails flag that allows users to
// introspect the public key algorithm, hash algorithm and more.
func GetAlgorithmDetails(knownSignatureAlgorithm v1.PublicKeyDetails) (AlgorithmDetails, error) {
	for _, detail := range supportedAlgorithms {
		if detail.knownAlgorithm == knownSignatureAlgorithm {
			return detail, nil
		}
	}
	return AlgorithmDetails{}, fmt.Errorf("could not find algorithm details for known signature algorithm: %s", knownSignatureAlgorithm)
}

// GetAlgorithmDetailsByOID retrieves a set of details for a OID that allows users to introspect the
// public key algorithm, hash algorithm and more. The public key is provided to differentiate between
// RSA AlgorithmDetails by key size.
func GetAlgorithmDetailsByOID(oid asn1.ObjectIdentifier, pubKey crypto.PublicKey, opts ...LoadOption) (AlgorithmDetails, error) {
	var useED25519ph bool
	for _, o := range opts {
		o.ApplyED25519ph(&useED25519ph)
	}

	for _, detail := range supportedAlgorithms {
		if detail.oid.Equal(oid) {
			// ed25519 and ed25519-ph use the same OID
			if useED25519ph && detail.knownAlgorithm != v1.PublicKeyDetails_PKIX_ED25519_PH {
				continue
			}
			// RSAPSS and RSA-PKCS#1v1.5 use different OIDs, but for each use the same OID regardless of key size
			if detail.keyType == RSA {
				keySize, err := detail.GetRSAKeySize()
				if err != nil {
					return AlgorithmDetails{}, fmt.Errorf("getting RSA key size: %v", err)
				}
				rsaPubKey, ok := pubKey.(*rsa.PublicKey)
				if !ok {
					return AlgorithmDetails{}, fmt.Errorf("error asserting RSA key type")
				}
				if keySize != RSAKeySize(rsaPubKey.Size()*8) {
					continue
				}
			}
			return detail, nil
		}
	}
	return AlgorithmDetails{}, fmt.Errorf("could not find algorithm details for OID %s", oid)
}

// NewAlgorithmRegistryConfig creates a new AlgorithmRegistryConfig for a set of permitted signature algorithms.
func NewAlgorithmRegistryConfig(algorithmConfig []v1.PublicKeyDetails) (*AlgorithmRegistryConfig, error) {
	permittedAlgorithms := make([]AlgorithmDetails, 0, len(supportedAlgorithms))
	for _, algorithm := range algorithmConfig {
		a, err := GetAlgorithmDetails(algorithm)
		if err != nil {
			return nil, err
		}
		permittedAlgorithms = append(permittedAlgorithms, a)
	}
	return &AlgorithmRegistryConfig{permittedAlgorithms: permittedAlgorithms}, nil
}

// IsAlgorithmPermitted checks whether a given public key/hash algorithm combination is permitted by a registry config.
func (registryConfig AlgorithmRegistryConfig) IsAlgorithmPermitted(key crypto.PublicKey, hash crypto.Hash) (bool, error) {
	for _, algorithm := range registryConfig.permittedAlgorithms {
		keyMatch, err := algorithm.checkKey(key)
		if err != nil {
			return false, err
		}
		if keyMatch && algorithm.checkHash(hash) {
			return true, nil
		}
	}
	return false, nil
}

// FormatSignatureAlgorithmFlag formats a v1.PublicKeyDetails to a string that conforms to the naming conventions
// of CLI arguments that are used for Sigstore services.
func FormatSignatureAlgorithmFlag(algorithm v1.PublicKeyDetails) (string, error) {
	for _, a := range supportedAlgorithms {
		if a.knownAlgorithm == algorithm {
			return a.flagValue, nil
		}
	}
	return "", fmt.Errorf("could not find matching flag for signature algorithm: %s", algorithm)
}

// ParseSignatureAlgorithmFlag parses a string produced by FormatSignatureAlgorithmFlag and returns the corresponding
// v1.PublicKeyDetails value.
func ParseSignatureAlgorithmFlag(flag string) (v1.PublicKeyDetails, error) {
	for _, a := range supportedAlgorithms {
		if a.flagValue == flag {
			return a.knownAlgorithm, nil
		}
	}
	return v1.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED, fmt.Errorf("could not find matching signature algorithm for flag: %s", flag)
}

// GetDefaultPublicKeyDetails returns the default public key details for a given key.
//
// RSA 2048 => v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256
// RSA 3072 => v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256
// RSA 4096 => v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256
// ECDSA P256 => v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
// ECDSA P384 => v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384
// ECDSA P521 => v1.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512
// ED25519 => v1.PublicKeyDetails_PKIX_ED25519_PH
//
// This function accepts LoadOptions, which are used to determine the default
// public key details when there may be ambiguities. For example, RSA keys may
// be PSS or PKCS1v1.5 encoded, and ED25519 keys may be used with PureEd25519 or
// with Ed25519ph. The Hash option is ignored if passed, because each of the
// supported algorithms already has a default hash.
func GetDefaultPublicKeyDetails(publicKey crypto.PublicKey, opts ...LoadOption) (v1.PublicKeyDetails, error) {
	var rsaPSSOptions *rsa.PSSOptions
	var useED25519ph bool
	for _, o := range opts {
		o.ApplyED25519ph(&useED25519ph)
		o.ApplyRSAPSS(&rsaPSSOptions)
	}

	switch pk := publicKey.(type) {
	case *rsa.PublicKey:
		if rsaPSSOptions != nil {
			switch pk.Size() * 8 {
			case 2048:
				return v1.PublicKeyDetails_PKIX_RSA_PSS_2048_SHA256, nil
			case 3072:
				return v1.PublicKeyDetails_PKIX_RSA_PSS_3072_SHA256, nil
			case 4096:
				return v1.PublicKeyDetails_PKIX_RSA_PSS_4096_SHA256, nil
			}
		} else {
			switch pk.Size() * 8 {
			case 2048:
				return v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256, nil
			case 3072:
				return v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256, nil
			case 4096:
				return v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256, nil
			}
		}
	case *ecdsa.PublicKey:
		switch pk.Curve {
		case elliptic.P256():
			return v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, nil
		case elliptic.P384():
			return v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384, nil
		case elliptic.P521():
			return v1.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512, nil
		}
	case ed25519.PublicKey:
		if useED25519ph {
			return v1.PublicKeyDetails_PKIX_ED25519_PH, nil
		}
		return v1.PublicKeyDetails_PKIX_ED25519, nil
	}
	return v1.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED, errors.New("unsupported public key type")
}

// GetDefaultAlgorithmDetails returns the default algorithm details for a given
// key, according to GetDefaultPublicKeyDetails.
//
// This function accepts LoadOptions, which are used to determine the default
// algorithm details when there may be ambiguities. For example, RSA keys may be
// PSS or PKCS1v1.5 encoded, and ED25519 keys may be used with PureEd25519 or
// with Ed25519ph. The Hash option is ignored if passed, because each of the
// supported algorithms already has a default hash.
func GetDefaultAlgorithmDetails(publicKey crypto.PublicKey, opts ...LoadOption) (AlgorithmDetails, error) {
	knownAlgorithm, err := GetDefaultPublicKeyDetails(publicKey, opts...)
	if err != nil {
		return AlgorithmDetails{}, err
	}
	return GetAlgorithmDetails(knownAlgorithm)
}
