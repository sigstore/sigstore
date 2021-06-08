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

package option

import "crypto"

// MessageDigest is an option used to declare that the message passed to Sign or Verify is already in a processed state, and can be directly signed or verified against a signature.
type MessageDigest struct {
	NoOpOptionImpl
	digest     []byte
	cryptoOpts crypto.SignerOpts
}

// ApplyDigest provides an explicit `digest` to sign or verify a signature against.
func (m MessageDigest) ApplyDigest(digest *[]byte) {
	*digest = m.digest
}

// ApplyCryptoSignerOpts explicitly declares the `opts` passed to `crypto.Signer.Sign()`.
func (m MessageDigest) ApplyCryptoSignerOpts(cryptoOpts *crypto.SignerOpts) {
	*cryptoOpts = m.cryptoOpts
}

// ApplyCryptoSignerOpts explicitly declares the `opts` passed to `crypto.Signer.Sign()`.
func (m MessageDigest) ApplyHashAlg(hash *crypto.Hash) {
	*hash = m.cryptoOpts.HashFunc()
}

// WithMessageDigest declares that signatures should be created or verified against an explicit digest, created by the alg specified in `cryptoOpts`.
func WithMessageDigest(digest []byte, cryptoOpts crypto.SignerOpts) MessageDigest {
	return MessageDigest{digest: digest, cryptoOpts: cryptoOpts}
}
