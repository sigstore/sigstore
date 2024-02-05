//
// Copyright 2024 The Sigstore Authors.
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

	"github.com/coreos/go-oidc/v3/oidc"
)

type testccDriver struct {
	respCh chan interface{}
	t      *testing.T
}

func (td *testccDriver) handler(w http.ResponseWriter, r *http.Request) {
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
	case "/token":
		_, _ = w.Write(b)
	default:
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}

func TestClientCredentialsFlowTokenGetter_ccFlow(t *testing.T) {
	td := testccDriver{
		respCh: make(chan interface{}, 3),
		t:      t,
	}

	ts := httptest.NewServer(http.HandlerFunc(td.handler))
	defer ts.Close()

	dtg := DefaultFlowClientCredentials{
		Issuer: ts.URL,
	}
	p, pErr := oidc.NewProvider(context.Background(), ts.URL)
	if pErr != nil {
		t.Fatal(pErr)
	}

	tokenCh, errCh := make(chan string), make(chan error)
	go func() {
		token, err := dtg.clientCredentialsFlow(p, "sigstore", "", "")
		tokenCh <- token
		errCh <- err
	}()

	td.respCh <- tokenResponse("mytoken", "")

	token := <-tokenCh
	err := <-errCh
	if err != nil {
		t.Fatal(err)
	}
	if token != "mytoken" {
		t.Fatal("expected mytoken")
	}
}
