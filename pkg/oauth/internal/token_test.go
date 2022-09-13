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

package internal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"
)

func TestParseAccessTokenSuccessResponse(t *testing.T) {
	now := currentTime()
	realCurrentTime := currentTime
	currentTime = func() time.Time { return now }
	defer func() { currentTime = realCurrentTime }()

	testCases := []struct {
		desc            string
		respContentType string
		respBody        []byte

		wantAccessToken  string
		wantRefreshToken string
		wantTokenType    string
		wantExpiry       time.Time
		mustHaveExtras   map[string]interface{}

		wantError error
	}{
		{
			desc: "json",

			respContentType: "application/json",
			respBody: []byte(`{
				"access_token": "json access_token",
				"token_type": "Bearer",
				"refresh_token": "json refresh_token",
				"expires_in": 3600,
				"scope": "foo bar"
			}`),

			wantAccessToken:  "json access_token",
			wantRefreshToken: "json refresh_token",
			wantTokenType:    "Bearer",
			wantExpiry:       now.Add(3600 * time.Second),
			mustHaveExtras: map[string]interface{}{
				"scope": "foo bar",
			},
		},
		{
			desc: "json no access_token",

			respContentType: "application/json",
			respBody:        []byte(`{"token_type":"Bearer","expires_in":3600,"scope":"foo bar"}`),

			wantError: fmt.Errorf(`response did not contain "access_token". Content-Type: %q, Body: %s`, "application/json", `{"token_type":"Bearer","expires_in":3600,"scope":"foo bar"}`),
		},
		{
			desc: "bad json",

			respContentType: "application/json",
			respBody:        []byte(`"token_type":"Bearer","expires_in":3600,"scope":"foo bar"`),

			wantError: errors.New("invalid character ':' after top-level value"),
		},
		{
			desc: "x-www-form-urlencoded",

			respContentType: "application/x-www-form-urlencoded",
			respBody: []byte(url.Values{
				"access_token":  []string{"urlencoded access_token"},
				"token_type":    []string{"MAC"},
				"refresh_token": []string{"urlencoded refresh_token"},
				"expires_in":    []string{"420"},
				"scope":         []string{"bar baz"},
			}.Encode()),

			wantAccessToken:  "urlencoded access_token",
			wantRefreshToken: "urlencoded refresh_token",
			wantTokenType:    "MAC",
			wantExpiry:       now.Add(420 * time.Second),
			mustHaveExtras: map[string]interface{}{
				"scope": "bar baz",
			},
		},
		{
			desc: "expires_in unparsable",

			respContentType: "application/x-www-form-urlencoded",
			respBody: []byte(url.Values{
				"access_token": []string{"urlencoded access_token"},
				"token_type":   []string{"Bearer"},
				"expires_in":   []string{"unparsable"},
			}.Encode()),

			wantError: errors.New("failed to parse \"expires_in\": strconv.Atoi: parsing \"unparsable\": invalid syntax"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			testResp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(tc.respBody)),
			}
			if tc.respContentType != "" {
				testResp.Header = make(http.Header, 1)
				testResp.Header.Set("Content-Type", tc.respContentType)
			}

			token, err := ParseAccessTokenResponse(testResp)
			if err == nil && tc.wantError != nil {
				t.Fatalf("ParseAccessTokenResponse should have returned an error, got %v", token)
			}
			if err != nil {
				if tc.wantError != nil {
					gotErr := err.Error()
					wantErr := tc.wantError.Error()
					if gotErr != wantErr {
						t.Fatalf("ParseAccessTokenResponse should have returned error %q, got %q", wantErr, gotErr)
					}
					return
				}
				t.Fatalf("ParseAccessTokenResponse returned error: %v", err)
			}
			if token.AccessToken != tc.wantAccessToken {
				t.Errorf("Wanted AccessToken %q, got %q", tc.wantAccessToken, token.AccessToken)
			}
			if token.RefreshToken != tc.wantRefreshToken {
				t.Errorf("Wanted RefreshToken %q, got %q", tc.wantRefreshToken, token.RefreshToken)
			}
			if token.TokenType != tc.wantTokenType {
				t.Errorf("Wanted TokenType %q, got %q", tc.wantTokenType, token.TokenType)
			}
			if token.Expiry != tc.wantExpiry {
				t.Errorf("Wanted Expiry %v, got %v", tc.wantExpiry, token.Expiry)
			}
			for k, v := range tc.mustHaveExtras {
				gotVal := token.Extra(k)
				if !reflect.DeepEqual(v, gotVal) {
					t.Errorf("Wanted Extra(%q)=%v, got %v", k, v, gotVal)
				}
			}
		})
	}
}

func TestParseAccessTokenFailResponse(t *testing.T) {
	testCases := []struct {
		desc            string
		respStatusCode  int
		respContentType string
		respBody        []byte

		wantError error
	}{
		{
			desc: "json",

			respStatusCode:  http.StatusBadRequest,
			respContentType: "application/json",
			respBody:        []byte(`{"error":"invalid_request","error_description":"description of error","error_uri":"https://test.example.com/json"}`),

			wantError: &ErrorTokenResponse{
				Code:        "invalid_request",
				Description: "description of error",
				URI:         "https://test.example.com/json",
			},
		},
		{
			desc: "x-www-form-urlencoded",

			respStatusCode:  http.StatusBadRequest,
			respContentType: "application/x-www-form-urlencoded",
			respBody: []byte(url.Values{
				"error":             []string{"invalid_request"},
				"error_description": []string{"description of error"},
				"error_uri":         []string{"https://test.example.com/form-urlencoded"},
			}.Encode()),

			wantError: &ErrorTokenResponse{
				Code:        "invalid_request",
				Description: "description of error",
				URI:         "https://test.example.com/form-urlencoded",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			testResp := &http.Response{
				StatusCode: tc.respStatusCode,
				Body:       io.NopCloser(bytes.NewReader(tc.respBody)),
			}
			if tc.respContentType != "" {
				testResp.Header = make(http.Header, 1)
				testResp.Header.Set("Content-Type", tc.respContentType)
			}

			token, err := ParseAccessTokenResponse(testResp)
			if err == nil {
				t.Fatalf("ParseAccessTokenResponse should have failed, got: %v", token)
			}

			gotErr := err.Error()
			wantErr := tc.wantError.Error()

			if gotErr != wantErr {
				t.Errorf("ParseAccessTokenResponse should have returned error %q, got %q", wantErr, gotErr)
			}
		})
	}
}
