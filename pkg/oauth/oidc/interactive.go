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

func startRedirectListener(state, htmlPage, redirectURL string, codeCh chan string, errCh chan error) (*http.Server, *url.URL, error) {
	var listener net.Listener
	var urlListener *url.URL
	var err error

	if redirectURL == "" {
		listener, err = net.Listen("tcp", "localhost:0") // ":0" == OS picks
		if err != nil {
			return nil, nil, err
		}

		port := listener.Addr().(*net.TCPAddr).Port
		urlListener = &url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("localhost:%d", port),
			Path:   "/auth/callback",
		}
	} else {
		urlListener, err = url.Parse(redirectURL)
		if err != nil {
			return nil, nil, err
		}
		listener, err = net.Listen("tcp", urlListener.Host)
		if err != nil {
			return nil, nil, err
		}
	}

	m := http.NewServeMux()
	s := &http.Server{
		Addr:    urlListener.Host,
		Handler: m,
	}

	m.HandleFunc(urlListener.Path, func(w http.ResponseWriter, r *http.Request) {
		// even though these are fetched from the FormValue method,
		// these are supplied as query parameters
		if r.FormValue("state") != state {
			errCh <- errors.New("invalid state token")
			return
		}
		codeCh <- r.FormValue("code")
		fmt.Fprint(w, htmlPage)
	})

	go func() {
		if err := s.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	return s, urlListener, nil
}

func getCode(codeCh chan string, errCh chan error) (string, error) {
	select {
	case code := <-codeCh:
		return code, nil
	case err := <-errCh:
		return "", err
	case <-time.After(120 * time.Second):
		return "", errors.New("timeout")
	}
}

// newKSUID returns a globally unique, base62 (URL-safe) encoded, 27 character string.
func newKSUID() string {
	return ksuid.New().String()
}

type interactiveIDTokenSource struct {
	cfg               oauth2.Config
	oidp              *coreoidc.Provider
	extraAuthCodeOpts []oauth2.AuthCodeOption
	browser           browserOpener
}

var errWontOpenBrowser = errors.New("not opening that browser")

func failBrowser(string) error {
	return errWontOpenBrowser
}

func (idts *interactiveIDTokenSource) IDToken(ctx context.Context) (*IDToken, error) {
	cfg := idts.cfg
	p := idts.oidp

	// generate random fields and save them for comparison after OAuth2 dance
	stateToken := newKSUID()
	nonce := newKSUID()

	codeCh := make(chan string)
	errCh := make(chan error)
	// starts listener using the redirect_uri, otherwise starts on ephemeral port
	redirectServer, redirectURL, err := startRedirectListener(stateToken, oauth.InteractiveSuccessHTML, cfg.RedirectURL, codeCh, errCh)
	if err != nil {
		close(codeCh)
		close(errCh)
		return nil, errors.Wrap(err, "starting redirect listener")
	}
	defer func() {
		go func() {
			_ = redirectServer.Shutdown(context.Background())
			close(codeCh)
			close(errCh)
		}()
	}()

	cfg.RedirectURL = redirectURL.String()

	// require that OIDC provider support PKCE to provide sufficient security for the CLI
	pkce, err := NewPKCE(p)
	if err != nil {
		return nil, err
	}

	opts := append(pkce.AuthURLOpts(), oauth2.AccessTypeOnline, coreoidc.Nonce(nonce))
	if len(idts.extraAuthCodeOpts) > 0 {
		opts = append(opts, idts.extraAuthCodeOpts...)
	}
	authCodeURL := cfg.AuthCodeURL(stateToken, opts...)
	var code string
	if err := idts.browser(authCodeURL); err != nil {
		// Swap to the out of band flow if we can't open the browser
		if !errors.Is(err, errWontOpenBrowser) {
			fmt.Fprintf(os.Stderr, "error opening browser: %v\n", err)
		}
		code = doOobFlow(&cfg, stateToken, opts)
	} else {
		fmt.Fprintf(os.Stderr, "Your browser will now be opened to:\n%s\n", authCodeURL)
		code, err = getCode(codeCh, errCh)
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

// InteractiveIDTokenSource returns an `IDTokenSource` which performs an interactive Oauth token flow in order to retrieve an `IDToken`.
func InteractiveIDTokenSource(cfg oauth2.Config, oidp *coreoidc.Provider, extraAuthCodeOpts []oauth2.AuthCodeOption, allowBrowser bool) IDTokenSource {
	ts := &interactiveIDTokenSource{cfg: cfg, oidp: oidp, extraAuthCodeOpts: extraAuthCodeOpts, browser: failBrowser}
	if allowBrowser {
		ts.browser = browser.OpenURL
	}
	return ts
}
