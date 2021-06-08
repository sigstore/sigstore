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
)

type RPCOption interface {
	// ApplyContext defines the request context for a given signature oprtation, if applicable.
	ApplyContext(*context.Context)
}

type MessageOption interface {
	// ApplyDigest explicitly declares the `digest` to be signed or to verify a signature against.
	ApplyDigest(digest *[]byte)
	// ApplyCryptoSignerOpts explicitly declares the `opts` passed to `crypto.Signer.Sign()` and the hash algorithm applied to the input to a signature verification.
	ApplyCryptoSignerOpts(cryptoOpts *crypto.SignerOpts)
}

type SignerVerifier interface {
	Signer
	Verifier
}
