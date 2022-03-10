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

//go:build e2e
// +build e2e

package oidc

import (
	"context"
	"os"
	"testing"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-rod/rod"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
)

type claims struct {
	Email    string `json:"email"`
	Verified bool   `json:"email_verified"`
	Subject  string `json:"sub"`
}

func identityFromClaims(c claims) (string, error) {
	if c.Email != "" {
		if !c.Verified {
			return "", errors.New("not verified by identity provider")
		}
		return c.Email, nil
	}

	if c.Subject == "" {
		return "", errors.New("no subject found in claims")
	}
	return c.Subject, nil
}

// identityFromIDToken extracts the email or subject claim from an `IDToken``
func identityFromIDToken(tok *IDToken) (string, error) {
	claims := claims{}
	oidcTok := (*coreoidc.IDToken)(tok)
	if err := oidcTok.Claims(&claims); err != nil {
		return "", err
	}
	return identityFromClaims(claims)
}

type InteractiveOIDCSuite struct {
	suite.Suite
}

func (suite *InteractiveOIDCSuite) TestInteractiveIDTokenSource() {
	ctx := context.Background()

	urlCh := make(chan string)
	defer close(urlCh)

	browserOpener := func(input string) error {
		urlCh <- input
		return nil
	}

	provider, err := coreoidc.NewProvider(ctx, os.Getenv("OIDC_ISSUER"))
	require.Nil(suite.T(), err)
	cfg := oauth2.Config{
		ClientID:     os.Getenv("OIDC_ID"),
		ClientSecret: "",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{coreoidc.ScopeOpenID, "email"},
	}

	ts := &interactiveIDTokenSource{
		cfg:     cfg,
		oidp:    provider,
		browser: browserOpener,
	}

	go func() {
		authCodeURL := <-urlCh
		page := rod.New().MustConnect().MustPage(authCodeURL)
		page.MustElement("body > div.dex-container > div > div > div:nth-child(2) > a > button").MustClick()
	}()

	idToken, err := ts.IDToken(ctx)
	require.Nil(suite.T(), err)

	email, err := identityFromIDToken(idToken)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), email)
	require.Equal(suite.T(), "kilgore@kilgore.trout", email)
}

func TestInteractiveOIDCFlow(t *testing.T) {
	suite.Run(t, new(InteractiveOIDCSuite))
}
