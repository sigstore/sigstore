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
	"crypto/rsa"
)

type loadOpts struct {
	hashFunc      crypto.Hash
	useED25519ph  bool
	rsaPSSOptions *rsa.PSSOptions
}

// LoadOption specifies options to be used when creating a Signer/Verifier
type LoadOption func(*loadOpts)

// WithHash specifies the hash function to be used for the Signer/Verifier
func WithHash(hashFunc crypto.Hash) LoadOption {
	return func(o *loadOpts) {
		o.hashFunc = hashFunc
	}
}

// WithED25519ph specifies that the ED25519ph algorithm should be used when a ED25519 key is used
func WithED25519ph() LoadOption {
	return func(o *loadOpts) {
		o.useED25519ph = true
	}
}

// WithRSAPSS specifies that the RSAPSS algorithm should be used when a RSA key is used
// Note that the RSA PSSOptions contains an hash algorithm, which will override
// the hash function specified with WithHash.
func WithRSAPSS(opts *rsa.PSSOptions) LoadOption {
	return func(o *loadOpts) {
		o.rsaPSSOptions = opts
	}
}

// GetSignerVerifierOptionHash returns the hash function specified in the options
func GetSignerVerifierOptionHash(opts ...LoadOption) crypto.Hash {
	o := makeSignerVerifierOpts(opts...)
	return o.hashFunc
}

func makeSignerVerifierOpts(opts ...LoadOption) *loadOpts {
	o := &loadOpts{
		hashFunc: crypto.SHA256,
	}

	for _, opt := range opts {
		opt(o)
	}
	return o
}
