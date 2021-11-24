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
	"fmt"
	"math/big"

	"github.com/sigstore/sigstore/pkg/signature"
)

func FuzzECDSASigner(data []byte) int {
	x := ecdsa.PrivateKey{}
	z := new(big.Int)
	z.SetBytes(data)
	x.X = z
	x.Y = z
	x.D = z

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
		panic(fmt.Sprintf("signature verify failed %v", err))
	}

	return 1
}
