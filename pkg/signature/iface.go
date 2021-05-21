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
	"context"
	"crypto"

	"github.com/pkg/errors"
)

type BaseSignerVeriiferType struct {
	hashFunc  crypto.Hash
	publicKey crypto.PublicKey
}

func (b BaseSignerVeriiferType) ComputeHash(opts crypto.SignerOpts, payload []byte) ([]byte, crypto.Hash, error) {
	hf := b.hashFunc
	if opts != nil {
		hf = opts.HashFunc()
		if hf == crypto.Hash(0) {
			return nil, 0, errors.New("invalid hash function specified")
		}
	}

	hasher := hf.New()
	if _, err := hasher.Write(payload); err != nil {
		return nil, hf, errors.Wrap(err, "hashing payload for signature")
	}
	return hasher.Sum(nil), hf, nil
}

// SignerOpts implements crypto.SignerOpts
type SignerOpts struct {
	Context context.Context
	Hash    crypto.Hash
}

func (s SignerOpts) HashFunc() crypto.Hash {
	return s.Hash
}

type SignerVerifier interface {
	crypto.Signer
	//TODO: add methods to pass io.Reader for payload/signature instead of []byte
	VerifySignature(payload, signature []byte) error // verifies using public key from signer in instance
	VerifySignatureWithKey(publicKey crypto.PublicKey, payload, signature []byte) error
}
