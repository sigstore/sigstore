//
// Copyright 2022 The Sigstore Authors.
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
	"math/big"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/sigstore/sigstore/pkg/signature"
)

func FuzzECDSASigner(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
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
				t.Errorf("key %v is not nil when there is an error %v ", signer, err)
			}
			t.Skip("not valid key")
		}

		sig, err := signer.SignMessage(bytes.NewReader(data))
		if err != nil {
			if sig != nil {
				t.Errorf("key %v is not nil when there is an error %v ", sig, err)
			}
			t.Skip("not valid key")
		}

		if err = signer.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data)); err != nil {
			t.Skip("not valid key")
		}
	})
}

func FuzzComputeDigest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
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
				t.Errorf("key %v is not nil when there is an error %v ", data, err)
			}
			t.Skip("not valid key")
		}
	})
}

func FuzzComputeVerifying(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
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
				t.Errorf("key %v is not nil when there is an error %v ", data, err)
			}
			t.Skip("not valid key")
		}
	})
}

func FuzzED25529SignerVerfier(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		x := ed25519.PrivateKey(data)

		signer, err := signature.LoadED25519SignerVerifier(x)
		if err != nil {
			if signer != nil {
				t.Errorf("key %v is not nil when there is an error %v ", signer, err)
			}
			t.Skip("not valid key")
		}

		sig, err := signer.SignMessage(bytes.NewReader(data))
		if err != nil {
			if sig != nil {
				t.Errorf("key %v is not nil when there is an error %v ", sig, err)
			}
			t.Skip("not valid key")
		}

		signer.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	})
}

func FuzzRSAPKCS1v15SignerVerfier(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		f := fuzz.NewConsumer(data)
		x := rsa.PrivateKey{}
		f.GenerateStruct(&x)

		signer, err := signature.LoadRSAPKCS1v15Signer(&x, crypto.SHA512)
		if err != nil {
			if signer != nil {
				t.Errorf("key %v is not nil when there is an error %v ", signer, err)
			}
			t.Skip("not valid key")
		}

		sig, err := signer.SignMessage(bytes.NewReader(data))
		if err != nil {
			if sig != nil {
				t.Errorf("key %v is not nil when there is an error %v ", sig, err)
			}
			t.Skip("not valid key")
		}
		if _, err := signer.Sign(bytes.NewReader(data), data, nil); err != nil {
			t.Skip("not valid key")
		}
	})
}

func FuzzRSAPSSSignerVerfier(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey(data, cryptoutils.SkipPassword)
		if err != nil {
			t.Skip()
		}
		signer, err := signature.LoadRSAPSSSignerVerifier(privateKey.(*rsa.PrivateKey), crypto.SHA512, nil)
		if err != nil {
			if signer != nil {
				t.Errorf("key %v is not nil when there is an error %v ", signer, err)
			}
			t.Skip("not valid key")
		}

		sig, err := signer.SignMessage(bytes.NewReader(data))
		if err != nil {
			if sig != nil {
				t.Errorf("key %v is not nil when there is an error %v ", sig, err)
			}
			t.Skip("not valid key")
		}
		if _, err := signer.Sign(bytes.NewReader(data), data, nil); err != nil {
			t.Skip("not valid key")
		}
	})
}
