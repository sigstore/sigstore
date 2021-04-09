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
	"crypto/rand"
	"fmt"
)

type GenericSigner struct {
	Signer     crypto.Signer
	SignerOpts crypto.SignerOpts
}

func (s GenericSigner) Sign(_ context.Context, rawPayload []byte) (signature, signed []byte, err error) {
	signed = rawPayload
	if s.SignerOpts != nil {
		preHash := s.SignerOpts.HashFunc()
		if preHash != crypto.Hash(0) {
			h := preHash.New()
			if _, err := h.Write(rawPayload); err != nil {
				return nil, nil, fmt.Errorf("failed to create hash: %v", err)
			}
			signed = h.Sum(nil)
		}
	}
	signature, err = s.Signer.Sign(rand.Reader, signed, s.SignerOpts)
	if err != nil {
		return nil, nil, err
	}
	return signature, signed, nil
}

func (s GenericSigner) PublicKey(_ context.Context) (crypto.PublicKey, error) {
	return s.Signer.Public(), nil
}

var _ Signer = GenericSigner{}
