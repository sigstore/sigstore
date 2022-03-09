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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"github.com/segmentio/ksuid"
	"github.com/sigstore/sigstore/pkg/oauth"
	"golang.org/x/oauth2"
)

const oobRedirectURI = "urn:ietf:wg:oauth:2.0:oob"

type browserOpener func(url string) error

func doOobFlow(cfg *oauth2.Config, stateToken string, opts []oauth2.AuthCodeOption) string {
	cfg.RedirectURL = oobRedirectURI
	authURL := cfg.AuthCodeURL(stateToken, opts...)
	fmt.Fprintln(os.Stderr, "Go to the following link in a browser:\n\n\t", authURL)
	fmt.Fprintf(os.Stderr, "Enter verification code: ")
	var code string
	fmt.Scanln(&code)
	return code
}

func startRedirectListener(state, htmlPage string, doneCh chan string, errCh chan error) (*http.Server, *url.URL, error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, nil, err
	}

	port := listener.Addr().(*net.TCPAddr).Port

	url := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("localhost:%d", port),
		Path:   "/auth/callback",
	}

	m := http.NewServeMux()
	s := &http.Server{
		Addr:    url.Host,
		Handler: m,
	}

	m.HandleFunc(url.Path, func(w http.ResponseWriter, r *http.Request) {
		// even though these are fetched from the FormValue method,
		// these are supplied as query parameters
		if r.FormValue("state") != state {
			errCh <- errors.New("invalid state token")
			return
		}
		doneCh <- r.FormValue("code")
		fmt.Fprint(w, htmlPage)
	})

	go func() {
		if err := s.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	return s, url, nil
}

func getCode(doneCh chan string, errCh chan error) (string, error) {
	timeoutCh := time.NewTimer(120 * time.Second)
	select {
	case code := <-doneCh:
		return code, nil
	case err := <-errCh:
		return "", err
	case <-timeoutCh.C:
		return "", errors.New("timeout")
	}
}

// newKSUID returns a globally unique, base62 (URL-safe) encoded, 27 character string.
func newKSUID() string {
	return ksuid.New().String()
}

func doInteractiveIDTokenFlow(ctx context.Context, cfg oauth2.Config, p *coreoidc.Provider, extraAuthCodeOpts []oauth2.AuthCodeOption, openBrowser browserOpener) (*IDToken, error) {
	// generate random fields and save them for comparison after OAuth2 dance
	stateToken := newKSUID()
	nonce := newKSUID()

	doneCh := make(chan string)
	errCh := make(chan error)
	// starts listener on ephemeral port
	redirectServer, redirectURL, err := startRedirectListener(stateToken, oauth.InteractiveSuccessHTML, doneCh, errCh)
	if err != nil {
		return nil, errors.Wrap(err, "starting redirect listener")
	}
	defer func() {
		go func() {
			_ = redirectServer.Shutdown(context.Background())
		}()
	}()

	cfg.RedirectURL = redirectURL.String()

	// require that OIDC provider support PKCE to provide sufficient security for the CLI
	pkce, err := NewPKCE(p)
	if err != nil {
		return nil, err
	}

	opts := append(pkce.AuthURLOpts(), oauth2.AccessTypeOnline, coreoidc.Nonce(nonce))
	if len(extraAuthCodeOpts) > 0 {
		opts = append(opts, extraAuthCodeOpts...)
	}
	authCodeURL := cfg.AuthCodeURL(stateToken, opts...)
	var code string
	if err := openBrowser(authCodeURL); err != nil {
		// Swap to the out of band flow if we can't open the browser
		fmt.Fprintf(os.Stderr, "error opening browser: %v\n", err)
		code = doOobFlow(&cfg, stateToken, opts)
	} else {
		fmt.Fprintf(os.Stderr, "Your browser will now be opened to:\n%s\n", authCodeURL)
		code, err = getCode(doneCh, errCh)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting code from local server: %v\n", err)
			code = doOobFlow(&cfg, stateToken, opts)
		}
	}
	token, err := cfg.Exchange(ctx, code, append(pkce.TokenURLOpts(), coreoidc.Nonce(nonce))...)
	if err != nil {
		return nil, err
	}

	verifier := p.Verifier(&coreoidc.Config{ClientID: cfg.ClientID})
	return extractAndVerifyIDToken(ctx, token, verifier, nonce)
}

type interactiveIDTokenSource struct {
	cfg               oauth2.Config
	oidp              *coreoidc.Provider
	extraAuthCodeOpts []oauth2.AuthCodeOption
	browser           browserOpener
}

func failBrowser(string) error {
	return errors.New("not opening that browser")
}

func (idts *interactiveIDTokenSource) IDToken(ctx context.Context) (*IDToken, error) {
	return doInteractiveIDTokenFlow(ctx, idts.cfg, idts.oidp, idts.extraAuthCodeOpts, browser.OpenURL)
}

func InteractiveIDTokenSource(cfg oauth2.Config, oidp *coreoidc.Provider, extraAuthCodeOpts []oauth2.AuthCodeOption, allowBrowser bool) IDTokenSource {
	ts := &interactiveIDTokenSource{cfg: cfg, oidp: oidp, extraAuthCodeOpts: extraAuthCodeOpts, browser: failBrowser}
	if allowBrowser {
		ts.browser = browser.OpenURL
	}
	return ts
}
