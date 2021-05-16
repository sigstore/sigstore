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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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

	tokenCh, errCh := make(chan string), make(chan error)
	go func() {
		token, err := dtg.deviceFlow("sigstore")
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
