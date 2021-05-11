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
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/kms/gcp"
	"github.com/sigstore/sigstore/pkg/kms/hashivault"
	"github.com/sigstore/sigstore/pkg/signature"
)

func init() {
	ProvidersMux().AddProvider(gcp.ReferenceScheme, func(ctx context.Context, keyResourceID string) (KMS, error) {
		if err := gcp.ValidReference(keyResourceID); err != nil {
			return nil, err
		}
		return gcp.NewGCP(ctx, keyResourceID)
	})
	ProvidersMux().AddProvider(hashivault.ReferenceScheme, func(ctx context.Context, keyResourceID string) (KMS, error) {
		if err := hashivault.ValidReference(keyResourceID); err != nil {
			return nil, err
		}
		return hashivault.NewVault(ctx, keyResourceID)
	})
}

type KMS interface {
	signature.Signer
	signature.Verifier

	// CreateKey is responsible for creating an asymmetric key pair
	// with the ECDSA algorithm on the P-256 Curve with a SHA-256 digest
	CreateKey(context.Context) (*ecdsa.PublicKey, error)
}

type ProviderInit func(context.Context, string) (KMS, error)

type Providers struct {
	providers map[string]ProviderInit
}

func (p *Providers) AddProvider(keyResourceID string, init ProviderInit) {
	p.providers[keyResourceID] = init
}

func (p *Providers) Providers() map[string]ProviderInit {
	return p.providers
}

var providersMux = &Providers{
	providers: map[string]ProviderInit{},
}

func ProvidersMux() *Providers {
	return providersMux
}

func Get(ctx context.Context, keyResourceID string) (KMS, error) {
	for ref, providerInit := range providersMux.providers {
		if strings.HasPrefix(keyResourceID, ref) {
			return providerInit(ctx, keyResourceID)
		}
	}
	return nil, fmt.Errorf("no provider found for that key reference")
}
