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
	"crypto"
	"io"
)

type PublicKeyOption interface {
	RPCOption
}

type PublicKeyProvider interface {
	PublicKey(...PublicKeyOption) (crypto.PublicKey, error)
}

type SignOption interface {
	PublicKeyOption
	MessageOption

	// ApplyRand defines the source of randomness for creating a signature.
	ApplyRand(rand *io.Reader)
}

type Signer interface {
	PublicKeyProvider

	// Sign takes a raw message, and returns a `Verify`-able signature for the message.
	Sign(message io.Reader, signerOpts ...SignOption) (signature []byte, err error)
}
