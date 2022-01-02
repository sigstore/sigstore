//go:build gofuzz
// +build gofuzz

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

package signature

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/sigstore/sigstore/pkg/signature"
)

func FuzzECDSASigner(data []byte) int {
	x := ecdsa.PrivateKey{}
	z := new(big.Int)
	z.SetBytes(data)
	x.X = z
	x.Y = z
	x.D = z
	x.Curve = elliptic.P384()

	signer, err := signature.LoadECDSASignerVerifier(&x, crypto.SHA512)
	if err != nil {
		if signer != nil {
			panic(fmt.Sprintf("key %v is not nil when there is an error %v ", signer, err))
		}
		return 0
	}

	sig, err := signer.SignMessage(bytes.NewReader(data))
	if err != nil {
		if sig != nil {
			panic(fmt.Sprintf("key %v is not nil when there is an error %v ", sig, err))
		}
		return 0
	}

	if err = signer.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data)); err != nil {
		return 0
	}

	return 1
}

func FuzzComputeDigest(data []byte) int {
	hashFuncs := []crypto.Hash{
		crypto.SHA256,
		crypto.SHA512,
		crypto.SHA384,
		crypto.SHA224,
		crypto.SHA1,
	}
	data, _, err := signature.ComputeDigestForSigning(bytes.NewReader(data), crypto.SHA512, hashFuncs)
	if err != nil {
		if data != nil {
			panic(fmt.Sprintf("key %v is not nil when there is an error %v ", data, err))
		}
		return 0
	}
	return 1
}

func FuzzComputeVerifying(data []byte) int {
	hashFuncs := []crypto.Hash{
		crypto.SHA256,
		crypto.SHA512,
		crypto.SHA384,
		crypto.SHA224,
		crypto.SHA1,
	}
	data, _, err := signature.ComputeDigestForVerifying(bytes.NewReader(data), crypto.SHA512, hashFuncs)
	if err != nil {
		if data != nil {
			panic(fmt.Sprintf("key %v is not nil when there is an error %v ", data, err))
		}
		return 0
	}
	return 1
}

func FuzzED25529SignerVerfier(data []byte) int {
	x := ed25519.PrivateKey(data)

	signer, err := signature.LoadED25519SignerVerifier(x)
	if err != nil {
		if signer != nil {
			panic(fmt.Sprintf("key %v is not nil when there is an error %v ", signer, err))
		}
		return 0
	}

	sig, err := signer.SignMessage(bytes.NewReader(data))
	if err != nil {
		if sig != nil {
			panic(fmt.Sprintf("key %v is not nil when there is an error %v ", sig, err))
		}
		return 0
	}

	signer.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	return 1
}

func FuzzRSAPKCS1v15SignerVerfier(data []byte) int {
	f := fuzz.NewConsumer(data)
	x := rsa.PrivateKey{}
	f.GenerateStruct(&x)

	signer, err := signature.LoadRSAPKCS1v15Signer(&x, crypto.SHA512)
	if err != nil {
		if signer != nil {
			panic(fmt.Sprintf("key %v is not nil when there is an error %v ", signer, err))
		}
		return 0
	}

	sig, err := signer.SignMessage(bytes.NewReader(data))
	if err != nil {
		if sig != nil {
			panic(fmt.Sprintf("key %v is not nil when there is an error %v ", sig, err))
		}
		return 0
	}
	if _, err := signer.Sign(bytes.NewReader(data), data, nil); err != nil {
		return 0
	}
	return 1
}

func FuzzRSAPSSSignerVerfier(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	s := string(data)

	// Skip when the data is not a valid RSA PSS signature.
	if strings.TrimSpace(s) == "" {
		return 0
	}

	f := fuzz.NewConsumer(data)
	x := rsa.PrivateKey{}
	f.GenerateStruct(&x)
	signer, err := signature.LoadRSAPSSSignerVerifier(&x, crypto.SHA512, nil)
	if err != nil {
		if signer != nil {
			panic(fmt.Sprintf("key %v is not nil when there is an error %v ", signer, err))
		}
		return 0
	}

	sig, err := signer.SignMessage(bytes.NewReader(data))
	if err != nil {
		if sig != nil {
			panic(fmt.Sprintf("key %v is not nil when there is an error %v ", sig, err))
		}
		return 0
	}
	if _, err := signer.Sign(bytes.NewReader(data), data, nil); err != nil {
		return 0
	}
	return 1
}
