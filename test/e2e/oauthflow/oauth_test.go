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
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"os"
	"testing"
)

type OAuthSuite struct {
	suite.Suite
}

func (suite *OAuthSuite) TestOauthFlow() {
	idToken, err := oauthflow.OIDConnect(
		os.Getenv("OIDC_ISSUER"),
		os.Getenv("OIDC_ID"),
		os.Getenv("OIDC_SECRET"),
		oauthflow.DefaultIDTokenGetter,
	)

	email := idToken.Subject

	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), email)
	require.Equal(suite.T(), "kilgore@kilgore.trout", email)
}

func TestVault(t *testing.T) {
	suite.Run(t, new(OAuthSuite))
}

