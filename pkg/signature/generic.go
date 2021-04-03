/*
Copyright 2021 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

func (s GenericSigner) Sign(_ context.Context, payload []byte) (signature []byte, err error) {
	if s.SignerOpts != nil {
		hashFunc := s.SignerOpts.HashFunc()
		if hashFunc != crypto.Hash(0) {
			h := hashFunc.New()
			if _, err := h.Write(payload); err != nil {
				return nil, fmt.Errorf("failed to create hash: %v", err)
			}
			payload = h.Sum(nil)
		}
	}
	return s.Signer.Sign(rand.Reader, payload, s.SignerOpts)
}

func (s GenericSigner) PublicKey(_ context.Context) (crypto.PublicKey, error) {
	return s.Signer.Public(), nil
}

var _ Signer = GenericSigner{}
