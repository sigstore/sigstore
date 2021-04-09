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
)

type PublicKeyProvider interface {
	PublicKey(context.Context) (crypto.PublicKey, error)
}

type Verifier interface {
	Verify(ctx context.Context, rawPayload, signature []byte) error
}

type Signer interface {
	PublicKeyProvider

	// Sign takes a raw payload, potentially creating a derivative (e.g. hashed) payload, and returns the signature as well as the actual payload that was signed.
	Sign(ctx context.Context, rawPayload []byte) (signature, signed []byte, err error)
}

type SignerVerifier interface {
	Signer
	Verifier
}
