//
// Copyright 2026 The Sigstore Authors.
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

package httpretry

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryServerError(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempt := attempts.Add(1)
		if attempt < 3 {
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	transport := NewTransport(nil)
	transport.WaitMin = 0
	transport.WaitMax = 0
	client := &http.Client{Transport: transport}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
}

func TestNoRetryNotFound(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		http.NotFound(w, nil)
	}))
	defer server.Close()

	transport := NewTransport(nil)
	transport.WaitMin = 0
	transport.WaitMax = 0
	client := &http.Client{Transport: transport}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestRetryRequestError(t *testing.T) {
	var attempts atomic.Int32
	transport := NewTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if attempts.Add(1) == 1 {
			return nil, errors.New("temporary connection error")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}))
	transport.WaitMin = 0
	transport.WaitMax = 0
	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
}

func TestNilRequest(t *testing.T) {
	_, err := NewTransport(nil).RoundTrip(nil)
	if err == nil {
		t.Fatal("expected nil request error")
	}
}

func TestCustomPolicy(t *testing.T) {
	var attempts atomic.Int32
	transport := NewTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts.Add(1)
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Body:       io.NopCloser(strings.NewReader("try again")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}))
	transport.MaxRetries = 1
	transport.CheckRetry = func(_ *http.Request, _ *http.Response, _ error) bool {
		return false
	}
	transport.Backoff = func(_, _ time.Duration, _ int, _ *http.Response) time.Duration {
		t.Fatal("backoff should not be called when CheckRetry returns false")
		return 0
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

func TestNegativeMaxRetries(t *testing.T) {
	var attempts atomic.Int32
	transport := NewTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts.Add(1)
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       io.NopCloser(strings.NewReader("try again")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}))
	transport.MaxRetries = -1
	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

func TestNoRetryNonReplayableBody(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		http.Error(w, "try again", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL, io.NopCloser(strings.NewReader("body")))
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	transport := NewTransport(nil)
	transport.WaitMin = 0
	transport.WaitMax = 0
	client := &http.Client{Transport: transport}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

func TestDefaultRetryPolicy(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)

	tests := []struct {
		name string
		resp *http.Response
		err  error
		want bool
	}{
		{
			name: "request error",
			err:  errors.New("temporary connection error"),
			want: true,
		},
		{
			name: "context canceled",
			err:  context.Canceled,
			want: false,
		},
		{
			name: "deadline exceeded",
			err:  context.DeadlineExceeded,
			want: false,
		},
		{
			name: "unknown authority",
			err:  &url.Error{Err: x509.UnknownAuthorityError{}},
			want: false,
		},
		{
			name: "invalid protocol scheme",
			err:  &url.Error{Err: errors.New("unsupported protocol scheme \"ftp\"")},
			want: false,
		},
		{
			name: "too many redirects",
			err:  &url.Error{Err: errors.New("stopped after 10 redirects")},
			want: false,
		},
		{
			name: "too many requests",
			resp: &http.Response{StatusCode: http.StatusTooManyRequests},
			want: true,
		},
		{
			name: "internal server error",
			resp: &http.Response{StatusCode: http.StatusInternalServerError},
			want: true,
		},
		{
			name: "not implemented",
			resp: &http.Response{StatusCode: http.StatusNotImplemented},
			want: false,
		},
		{
			name: "not found",
			resp: &http.Response{StatusCode: http.StatusNotFound},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := DefaultRetryPolicy(req, test.resp, test.err); got != test.want {
				t.Fatalf("DefaultRetryPolicy() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestDefaultBackoff(t *testing.T) {
	if got := DefaultBackoff(time.Second, 30*time.Second, 2, nil); got < time.Second || got >= 4*time.Second {
		t.Fatalf("backoff = %s, want within [1s, 4s)", got)
	}

	if got := DefaultBackoff(time.Second, 3*time.Second, 3, nil); got != 3*time.Second {
		t.Fatalf("backoff = %s, want 3s", got)
	}

	resp := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Retry-After": []string{"2"}},
	}
	if got := DefaultBackoff(time.Second, 30*time.Second, 0, resp); got != 2*time.Second {
		t.Fatalf("backoff = %s, want 2s", got)
	}

	resp.Header.Set("Retry-After", "60")
	if got := DefaultBackoff(time.Second, 30*time.Second, 0, resp); got != 30*time.Second {
		t.Fatalf("backoff = %s, want 30s", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
