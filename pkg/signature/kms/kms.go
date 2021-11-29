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

package kms

import (
	"context"
	"crypto"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/aws"
	"github.com/sigstore/sigstore/pkg/signature/kms/azure"
	"github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	"github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
)

func init() {
	providersMux.AddProvider(aws.ReferenceScheme, func(ctx context.Context, keyResourceID string, hashFunc crypto.Hash) (SignerVerifier, error) {
		return aws.LoadSignerVerifier(keyResourceID)
	})
	providersMux.AddProvider(azure.ReferenceScheme, func(ctx context.Context, keyResourceID string, hashFunc crypto.Hash) (SignerVerifier, error) {
		return azure.LoadSignerVerifier(ctx, keyResourceID, hashFunc)
	})
	providersMux.AddProvider(gcp.ReferenceScheme, func(ctx context.Context, keyResourceID string, _ crypto.Hash) (SignerVerifier, error) {
		return gcp.LoadSignerVerifier(ctx, keyResourceID)
	})
	providersMux.AddProvider(hashivault.ReferenceScheme, func(ctx context.Context, keyResourceID string, hashFunc crypto.Hash) (SignerVerifier, error) {
		return hashivault.LoadSignerVerifier(keyResourceID, hashFunc)
	})
}

type providerInit func(context.Context, string, crypto.Hash) (SignerVerifier, error)

type providers struct {
	providers map[string]providerInit
}

// AddProvider adds the provider implementation into the local cache
func (p *providers) AddProvider(keyResourceID string, init providerInit) {
	p.providers[keyResourceID] = init
}

var providersMux = &providers{
	providers: map[string]providerInit{},
}

// Get returns a KMS SignerVerifier for the given resource string and hash function
func Get(ctx context.Context, keyResourceID string, hashFunc crypto.Hash) (SignerVerifier, error) {
	for ref, providerInit := range providersMux.providers {
		if strings.HasPrefix(keyResourceID, ref) {
			return providerInit(ctx, keyResourceID, hashFunc)
		}
	}
	return nil, fmt.Errorf("no provider found for that key reference")
}

// SignerVerifier creates and verifies digital signatures over a message using a KMS service
type SignerVerifier interface {
	signature.SignerVerifier
	CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error)
	CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error)
	SupportedAlgorithms() []string
	DefaultAlgorithm() string
}
