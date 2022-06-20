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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const wellKnownOIDCConfig string = `
{
	"issuer": "ISSUER",
	"authorization_endpoint": "ISSUER/auth",
	"token_endpoint": "ISSUER/token",
	"jwks_uri": "ISSUER/keys",
	"userinfo_endpoint": "ISSUER/userinfo",
	"device_authorization_endpoint": "ISSUER/device/code",
	"grant_types_supported": [
	  "authorization_code",
	  "refresh_token",
	  "urn:ietf:params:oauth:grant-type:device_code"
	],
	"response_types_supported": [
	  "code"
	],
	"subject_types_supported": [
	  "public"
	],
	"id_token_signing_alg_values_supported": [
	  "RS256"
	],
	"code_challenge_methods_supported": [
	  "S256",
	  "plain"
	],
	"scopes_supported": [
	  "openid",
	  "email",
	  "groups",
	  "profile",
	  "offline_access"
	],
	"token_endpoint_auth_methods_supported": [
	  "client_secret_basic",
	  "client_secret_post"
	],
	"claims_supported": [
	  "iss",
	  "sub",
	  "aud",
	  "iat",
	  "exp",
	  "email",
	  "email_verified",
	  "locale",
	  "name",
	  "preferred_username",
	  "at_hash"
	]
  }`

type testDriver struct {
	msgs   []string
	respCh chan interface{}
	t      *testing.T
}

func (td *testDriver) writeMsg(s string) {
	td.msgs = append(td.msgs, s)
}

func (td *testDriver) handler(w http.ResponseWriter, r *http.Request) {
	td.t.Log("got request:", r.URL.Path)
	if r.URL.Path == "/.well-known/openid-configuration" {
		_, _ = w.Write([]byte(strings.ReplaceAll(wellKnownOIDCConfig, "ISSUER", fmt.Sprintf("http://%s", r.Host))))
		return
	}
	nextReply := <-td.respCh
	b, err := json.Marshal(nextReply)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	switch r.URL.Path {
	case "/device/token", "/device/code":
		_, _ = w.Write(b)
	default:
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}

func TestDeviceFlowTokenGetter_deviceFlow(t *testing.T) {
	td := testDriver{
		respCh: make(chan interface{}, 3),
		t:      t,
	}

	ts := httptest.NewServer(http.HandlerFunc(td.handler))
	defer ts.Close()

	dtg := DeviceFlowTokenGetter{
		MessagePrinter: td.writeMsg,
		Sleeper:        func(_ time.Duration) {},
		Issuer:         ts.URL,
		TokenURL:       ts.URL + "/device/token",
		CodeURL:        ts.URL + "/device/code",
	}
	p, pErr := oidc.NewProvider(context.Background(), ts.URL)
	if pErr != nil {
		t.Fatal(pErr)
	}

	tokenCh, errCh := make(chan string), make(chan error)
	go func() {
		token, err := dtg.deviceFlow(p, "sigstore", "")
		tokenCh <- token
		errCh <- err
	}()

	td.respCh <- codeResponse()
	td.respCh <- tokenResponse("mytoken", "")

	token := <-tokenCh
	err := <-errCh

	if err != nil {
		t.Fatal(err)
	}
	if token != "mytoken" {
		t.Fatal("expected mytoken")
	}

	if !strings.Contains(td.msgs[0], "complete-uri") {
		t.Fatal("expected URL to be logged, got:", td.msgs[0])
	}
}

func codeResponse() deviceResp {
	return deviceResp{
		UserCode:                "mysecret",
		DeviceCode:              "foobar",
		Interval:                3,
		VerificationURIComplete: "complete-uri",
	}
}

func tokenResponse(idToken, err string) tokenResp {
	return tokenResp{
		IDToken: idToken,
		Error:   err,
	}
}
