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

//go:build e2e
// +build e2e

package oauthflow

import (
	"os"
	"testing"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type OAuthSuite struct {
	suite.Suite
}

func (suite *OAuthSuite) TestOauthFlow() {
	urlCh := make(chan string)

	oldOpener := browserOpener
	browserOpener = func(input string) error {
		urlCh <- input
		return nil
	}
	defer func() { browserOpener = oldOpener }()

	go func() {
		authCodeURL := <-urlCh
		launcher := launcher.New().NoSandbox(true).MustLaunch()
		page := rod.New().ControlURL(launcher).MustConnect().MustPage(authCodeURL)
		page.MustElement("body > div.dex-container > div > div > div:nth-child(2) > a > button").MustClick()
	}()

	idToken, err := OIDConnect(
		os.Getenv("OIDC_ISSUER"),
		os.Getenv("OIDC_ID"),
		"",
		"",
		DefaultIDTokenGetter,
	)

	require.Nil(suite.T(), err)

	email := idToken.Subject
	require.NotNil(suite.T(), email)
	require.Equal(suite.T(), "kilgore@kilgore.trout", email)
}

func TestOAuthFlow(t *testing.T) {
	suite.Run(t, new(OAuthSuite))
}
