// Copyright 2022 The Sigstore Authors.
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

package oidc

import (
	"context"
	"errors"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// IDToken is a structured representation of an OIDC IDToken.
type IDToken struct {
	coreoidc.IDToken
}

// IDTokenSource provides `IDTokens`.
type IDTokenSource interface {
	// IDToken returns an ID token or an error.
	IDToken(context.Context) (*IDToken, error)
}

type staticIDTokenSource struct {
	idt *IDToken
}

func (s staticIDTokenSource) IDToken(context.Context) (*IDToken, error) {
	return s.idt, nil
}

// StaticIDTokenSource returns an `IDTokenSource` which always returns the given `IDToken`.
func StaticIDTokenSource(idt *IDToken) IDTokenSource {
	return staticIDTokenSource{idt: idt}
}

// extractAndVerifyIDToken extracts the ID token from the given `oauth2.Token`, then verifies it against the given verifier and nonce.
func extractAndVerifyIDToken(ctx context.Context, t *oauth2.Token, v *coreoidc.IDTokenVerifier, nonce string) (*IDToken, error) {
	// requesting 'openid' scope should ensure an id_token is given when exchanging the code for an access token
	unverifiedIDToken, ok := t.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("id_token not present")
	}

	// verify nonce, client ID, access token hash before using it
	idToken, err := v.Verify(ctx, unverifiedIDToken)
	if err != nil {
		return nil, err
	}
	if idToken.Nonce != nonce {
		return nil, errors.New("nonce does not match value sent")
	}
	if idToken.AccessTokenHash != "" {
		if err := idToken.VerifyAccessToken(t.AccessToken); err != nil {
			return nil, err
		}
	}
	return &IDToken{*idToken}, nil
}
