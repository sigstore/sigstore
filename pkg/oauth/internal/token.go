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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/oauth2"
)

// var for testing
var currentTime = time.Now

// tokenRespJSON is the struct representing the JSON form of a RFC6749 access token success response.
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
type tokenRespJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

func parseFormURLEncodedAccessTokenSuccess(body []byte) (token *oauth2.Token, err error) {
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}

	token = &oauth2.Token{
		AccessToken:  vals.Get("access_token"),
		TokenType:    vals.Get("token_type"),
		RefreshToken: vals.Get("refresh_token"),
	}
	ei := vals.Get("expires_in")
	if ei != "" {
		expires, err := strconv.Atoi(ei)
		if err != nil {
			return nil, fmt.Errorf(`failed to parse "expires_in": %w`, err)
		}
		if expires != 0 {
			token.Expiry = currentTime().Add(time.Duration(expires) * time.Second)
		}
	}
	return token.WithExtra(vals), nil
}

func parseJSONAccessTokenSuccess(body []byte) (token *oauth2.Token, err error) {
	var tj tokenRespJSON
	if err = json.Unmarshal(body, &tj); err != nil {
		return nil, err
	}
	token = &oauth2.Token{
		AccessToken:  tj.AccessToken,
		TokenType:    tj.TokenType,
		RefreshToken: tj.RefreshToken,
	}
	if tj.ExpiresIn != 0 {
		token.Expiry = currentTime().Add(time.Duration(tj.ExpiresIn) * time.Second)
	}
	raw := map[string]interface{}{}
	if err = json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	return token.WithExtra(raw), nil
}

func parseAccessTokenSuccess(body []byte, contentType string) (token *oauth2.Token, err error) {
	if contentType == "application/x-www-form-urlencoded" {
		return parseFormURLEncodedAccessTokenSuccess(body)
	}
	return parseJSONAccessTokenSuccess(body)
}

// ErrorTokenResponse represents an RFC6749 access token error response.
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
type ErrorTokenResponse struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
}

// Error implements `error`
func (e *ErrorTokenResponse) Error() string {
	str, _ := json.Marshal(e)
	return string(str)
}

func parseFormURLEncodedAccessTokenError(body []byte) (*ErrorTokenResponse, error) {
	vals, parseErr := url.ParseQuery(string(body))
	if parseErr != nil {
		return nil, parseErr
	}
	return &ErrorTokenResponse{
		Code:        vals.Get("error"),
		Description: vals.Get("error_description"),
		URI:         vals.Get("error_uri"),
	}, nil
}

func parseJSONAccessTokenError(body []byte) (respErr *ErrorTokenResponse, parseErr error) {
	var ej ErrorTokenResponse
	if parseErr = json.Unmarshal(body, &ej); parseErr != nil {
		return nil, parseErr
	}
	return &ej, nil
}

func parseAccessTokenError(body []byte, contentType string) (respErr *ErrorTokenResponse, parseErr error) {
	if contentType == "application/x-www-form-urlencoded" {
		return parseFormURLEncodedAccessTokenError(body)
	}
	return parseJSONAccessTokenError(body)
}

// ParseAccessTokenResponse parses an RFC6749 access token response and returns either an `*oauth2.Token` on success, an `*ErrorTokenResponse` on failure, or any other error if the response cannot be parsed.
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-5
func ParseAccessTokenResponse(tokenResp *http.Response) (token *oauth2.Token, err error) {
	body, err := ioutil.ReadAll(io.LimitReader(tokenResp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	contentType, _, _ := mime.ParseMediaType(tokenResp.Header.Get("Content-Type"))
	if tokenResp.StatusCode != http.StatusOK {
		respErr, parseErr := parseAccessTokenError(body, contentType)
		if parseErr != nil {
			return nil, parseErr
		}
		return nil, respErr
	}
	token, err = parseAccessTokenSuccess(body, contentType)
	if err != nil {
		return nil, err
	}
	if token.AccessToken == "" {
		return nil, fmt.Errorf(`response did not contain "access_token". Content-Type: %q, Body: %s`, contentType, string(body))
	}
	return token, nil
}
