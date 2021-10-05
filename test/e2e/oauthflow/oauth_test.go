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

// +build e2e

package oauthflow

import (
	"os"
	"testing"

	"bou.ke/monkey"

	"github.com/go-rod/rod"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/skratchdot/open-golang/open"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type OAuthSuite struct {
	suite.Suite
}

func (suite *OAuthSuite) TestOauthFlow() {
	urlCh := make(chan string)

	monkey.Patch(open.Run, func(input string) error {
		urlCh <- input
		return nil
	})
	defer monkey.UnpatchAll()

	go func() {
		authCodeURL := <-urlCh
		page := rod.New().MustConnect().MustPage(authCodeURL)
		page.MustElement("body > div.dex-container > div > div > div:nth-child(2) > a > button").MustClick()
	}()

	idToken, err := oauthflow.OIDConnect(
		os.Getenv("OIDC_ISSUER"),
		os.Getenv("OIDC_ID"),
		os.Getenv("OIDC_SECRET"),
		oauthflow.DefaultIDTokenGetter,
	)

	require.Nil(suite.T(), err)

	email := idToken.Subject
	require.NotNil(suite.T(), email)
	require.Equal(suite.T(), "kilgore@kilgore.trout", email)
}

func TestOAuthFlow(t *testing.T) {
	suite.Run(t, new(OAuthSuite))
}
