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

package oauthflow

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const htmlPage = `<html>
<title>Sigstore Auth</title>
<body>
<h1>Sigstore Auth Successful</h1>
<p>You may now close this page.</p>
</body>
</html>
`

type TokenGetter interface {
	GetIDToken(provider *oidc.Provider, config oauth2.Config) (*OIDCIDToken, error)
}

type OIDCIDToken struct {
	RawString   string
	ParsedToken *oidc.IDToken
}

// DefaultIDTokenGetter is the default implementation.
// The HTML page and message printed to the terminal can be customized.
var DefaultIDTokenGetter = &InteractiveIDTokenGetter{
	MessagePrinter: func(url string) { fmt.Fprintf(os.Stderr, "Your browser will now be opened to:\n%s\n", url) },
	HTMLPage:       htmlPage,
}

func OIDConnect(issuer string, id string, secret string, tg TokenGetter) (*OIDCIDToken, string, error) {
	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		return nil, "", err
	}
	config := oauth2.Config{
		ClientID:     id,
		ClientSecret: secret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:5556/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}

	idToken, err := tg.GetIDToken(provider, config)
	if err != nil {
		return nil, "", err
	}

	email, err := emailFromIdToken(idToken.ParsedToken)
	if err != nil {
		return nil, "", err
	}
	return idToken, email, nil
}

func emailFromIdToken(tok *oidc.IDToken) (string, error) {
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := tok.Claims(&claims); err != nil {
		return "", err
	}
	if !claims.Verified {
		return "", errors.New("not verified by identity provider")
	}
	return claims.Email, nil
}
