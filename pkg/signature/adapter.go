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
	"io"

	"github.com/sigstore/sigstore/pkg/signature/option"
)

type cryptoSignerAdapter struct {
	Signer
	ctx                   context.Context
	publicKeyErrorHandler func(error)
}

func (sa cryptoSignerAdapter) Public() crypto.PublicKey {
	pk, err := sa.PublicKey(option.WithContext(sa.ctx))
	if err != nil && sa.publicKeyErrorHandler != nil {
		sa.publicKeyErrorHandler(err)
	}
	return pk
}

func (sa cryptoSignerAdapter) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return sa.Signer.Sign(nil, option.WithContext(sa.ctx), option.WithMessageDigest(digest, opts.HashFunc()), option.WithRand(rand))
}

func CryptoSigner(ctx context.Context, signer Signer, pkErrorHandler func(error)) crypto.Signer {
	return cryptoSignerAdapter{Signer: signer, ctx: ctx, publicKeyErrorHandler: pkErrorHandler}
}
