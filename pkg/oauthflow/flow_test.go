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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

func TestGetCodeWorking(t *testing.T) {
	desiredState := "foo"
	desiredCode := "code"
	// We need to start this in the background and send our request to the server

	var gotCode string
	var gotErr error
	doneCh := make(chan string)
	errCh := make(chan error)
	getCodeFinished := make(chan error)
	_, url, _ := startRedirectListener(desiredState, "", "", doneCh, errCh)
	go func() {
		gotCode, gotErr = getCode(doneCh, errCh)
		getCodeFinished <- gotErr
	}()

	sendCodeAndState(t, url, desiredCode, desiredState)

	// block until we're sure getCode has returned
	if getCodeErr := <-getCodeFinished; getCodeErr != nil {
		t.Fatal(gotErr)
	}
	if gotCode != desiredCode {
		t.Errorf("got %s, expected %s", gotCode, desiredCode)
	}
}

func TestGetCodeWrongState(t *testing.T) {
	desiredState := "foo"
	desiredCode := "code"
	// We need to start this in the background and send our request to the server

	var gotErr error
	doneCh := make(chan string)
	errCh := make(chan error)
	getCodeFinished := make(chan error)
	_, u, _ := startRedirectListener(desiredState, "", "", doneCh, errCh)
	go func() {
		_, gotErr = getCode(doneCh, errCh)
		getCodeFinished <- gotErr
	}()

	sendCodeAndState(t, u, desiredCode, "WRONG")

	// block until we're sure getCode has returned
	if getCodeErr := <-getCodeFinished; getCodeErr == nil {
		t.Fatal("expected error, sent wrong state!")
	}
}

func sendCodeAndState(t *testing.T, redirectURL *url.URL, code, state string) {
	t.Helper()
	testURL, _ := url.Parse(fmt.Sprintf("%v?code=%v&state=%v", redirectURL.String(), code, state))
	if _, err := http.Get(testURL.String()); err != nil {
		t.Fatal(err)
	}
}

func TestStaticTokenGetter_GetIDToken(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       priv,
	}
	signer, err := jose.NewSigner(k, nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		payload interface{}
		want    *OIDCIDToken
		wantErr bool
	}{
		{
			name: "no email",
			payload: struct {
				A string
			}{
				A: "foo",
			},
			wantErr: true,
		},
		{
			name: "no verified",
			payload: struct {
				Email string
			}{
				Email: "foobar",
			},
			wantErr: true,
		},
		{
			name: "not verified",
			payload: claims{
				Email:    "foobar",
				Verified: false,
			},
			wantErr: true,
		},
		{
			name: "verified",
			payload: claims{
				Email:    "foobar",
				Verified: true,
			},
			want: &OIDCIDToken{
				Subject: "foobar",
			},
		},
		{
			name: "spiffeid",
			payload: claims{
				Subject: "spiffe://foobar",
			},
			want: &OIDCIDToken{
				Subject: "spiffe://foobar",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(tt.payload)
			if err != nil {
				t.Fatal(err)
			}
			jws, err := signer.Sign(raw)
			if err != nil {
				t.Fatal(err)
			}
			token, err := jws.CompactSerialize()
			if err != nil {
				t.Fatal(err)
			}
			if tt.want != nil {
				tt.want.RawString = token
			}
			stg := &StaticTokenGetter{
				RawToken: token,
			}
			got, err := stg.GetIDToken(nil, oauth2.Config{})
			if (err != nil) != tt.wantErr {
				t.Errorf("StaticTokenGetter.GetIDToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("StaticTokenGetter.GetIDToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubjectFromToken(t *testing.T) {
	tests := map[string]struct {
		Subject         string
		Email           string
		EmailVerified   interface{}
		ExpectedSubject string
		WantErr         bool
	}{
		`Email as subject`: {
			Email:           "kilgore@kilgore.trout",
			EmailVerified:   true,
			Subject:         "foobar",
			ExpectedSubject: "kilgore@kilgore.trout",
			WantErr:         false,
		},
		`Subject as subject`: {
			Subject:         "foobar",
			ExpectedSubject: "foobar",
			WantErr:         false,
		},
		`no email or subject`: {
			WantErr: true,
		},
		`String email_verified value`: {
			Email:           "kilgore@kilgore.trout",
			EmailVerified:   "true",
			ExpectedSubject: "kilgore@kilgore.trout",
			WantErr:         false,
		},
		`Email not verified`: {
			Email:         "kilgore@kilgore.trout",
			EmailVerified: false,
			WantErr:       true,
		},
		`invalid email_verified property`: {
			Email:         "kilgore@kilgore.trout",
			EmailVerified: "foo",
			WantErr:       true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			inputClaims := map[string]interface{}{
				"email": test.Email,
				"sub":   test.Subject,
			}

			if test.EmailVerified != nil {
				inputClaims["email_verified"] = test.EmailVerified
			}

			claims, err := json.Marshal(inputClaims)
			if err != nil {
				t.Fatal(err)
			}

			token := &oidc.IDToken{}

			// reflect hack because "claims" field is unexported by oidc IDToken
			// https://github.com/coreos/go-oidc/pull/329
			val := reflect.Indirect(reflect.ValueOf(token))
			member := val.FieldByName("claims")
			pointer := unsafe.Pointer(member.UnsafeAddr())
			realPointer := (*[]byte)(pointer)
			*realPointer = claims

			subject, err := SubjectFromToken(token)
			if err != nil {
				if !test.WantErr {
					t.Fatal("didn't expect error", err)
				}
			}

			if subject != test.ExpectedSubject {
				t.Errorf("got %v subject and expected %v", subject, test.Subject)
			}
		})
	}
}

func TestSubjectFromUnverifiedToken(t *testing.T) {
	tests := map[string]struct {
		Subject         string
		Email           string
		EmailVerified   interface{}
		ExpectedSubject string
		WantErr         bool
	}{
		`Email as subject`: {
			Email:           "kilgore@kilgore.trout",
			EmailVerified:   true,
			Subject:         "foobar",
			ExpectedSubject: "kilgore@kilgore.trout",
			WantErr:         false,
		},
		`Subject as subject`: {
			Subject:         "foobar",
			ExpectedSubject: "foobar",
			WantErr:         false,
		},
		`no email or subject`: {
			WantErr: true,
		},
		`String email_verified value`: {
			Email:           "kilgore@kilgore.trout",
			EmailVerified:   "true",
			ExpectedSubject: "kilgore@kilgore.trout",
			WantErr:         false,
		},
		`Email not verified`: {
			Email:         "kilgore@kilgore.trout",
			EmailVerified: false,
			WantErr:       true,
		},
		`invalid email_verified property`: {
			Email:         "kilgore@kilgore.trout",
			EmailVerified: "foo",
			WantErr:       true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			inputClaims := map[string]interface{}{
				"email": test.Email,
				"sub":   test.Subject,
			}

			if test.EmailVerified != nil {
				inputClaims["email_verified"] = test.EmailVerified
			}

			token, err := json.Marshal(inputClaims)
			if err != nil {
				t.Fatal(err)
			}

			subject, err := SubjectFromUnverifiedToken(token)
			if err != nil {
				if !test.WantErr {
					t.Fatal("didn't expect error", err)
				}
			}

			if subject != test.ExpectedSubject {
				t.Errorf("got %v subject and expected %v", subject, test.Subject)
			}
		})
	}
}
