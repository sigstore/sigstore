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
	"testing"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

type OAuthSuite struct {
	suite.Suite
}

func (suite *OAuthSuite) TestOauthFlow() {
	idToken, err := oauthflow.OIDConnect(
		"http://127.0.0.1:5556/auth",
		"sigstore",
		"mock-secret",
		oauthflow.DefaultIDTokenGetter,
	)

	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), idToken)
}

func TestVault(t *testing.T) {
	suite.Run(t, new(OAuthSuite))
}

