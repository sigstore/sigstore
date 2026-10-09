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

package tuf

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestInitializeWithHTTPClientRetainsClient(t *testing.T) {
	for _, noCache := range []bool{false, true} {
		t.Run("no-cache="+strconv.FormatBool(noCache), func(t *testing.T) {
			directory, root, update := newHTTPClientTestRepository(t)
			t.Setenv(SigstoreNoCache, strconv.FormatBool(noCache))
			server := httptest.NewServer(http.FileServer(http.Dir(directory)))
			defer server.Close()
			transport := &http.Transport{}
			defer transport.CloseIdleConnections()
			var metadataRequests, targetRequests atomic.Int64
			var rejectRequests atomic.Bool
			requestError := errors.New("request rejected by the configured transport")
			httpClient := &http.Client{Transport: tufHTTPRoundTripper(func(req *http.Request) (*http.Response, error) {
				if rejectRequests.Load() {
					return nil, requestError
				}
				if req.URL.Host != strings.TrimPrefix(server.URL, "http://") {
					t.Errorf("request used another mirror: %s", req.URL)
					return nil, errors.New("unexpected mirror")
				}
				if strings.HasPrefix(req.URL.Path, "/targets/") {
					targetRequests.Add(1)
				} else {
					metadataRequests.Add(1)
				}
				return transport.RoundTrip(req)
			})}
			defaultClient, defaultTransport := http.DefaultClient, http.DefaultTransport
			defaultClientTransport := http.DefaultClient.Transport
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := InitializeWithHTTPClient(ctx, server.URL, root, httpClient); err != nil {
				t.Fatal(err)
			}
			assertHTTPClientTarget(t, "foo")
			if metadataRequests.Load() == 0 || targetRequests.Load() == 0 {
				t.Fatal("injected transport did not fetch both metadata and targets")
			}

			// A legacy forced refresh retains both the first mirror and its client,
			// even after the original initialization context has been canceled.
			cancel()
			update("forced refresh")
			before := targetRequests.Load()
			if err := Initialize(context.Background(), "https://another-mirror.invalid", nil); err != nil {
				t.Fatal(err)
			}
			assertHTTPClientTarget(t, "forced refresh")
			if targetRequests.Load() <= before {
				t.Fatal("legacy Initialize did not retain the injected transport")
			}

			// NewFromEnv also retains the client when its cached timestamp expires.
			update("expired cache refresh")
			forceExpirationVersion(t, 2)
			before = targetRequests.Load()
			assertHTTPClientTarget(t, "expired cache refresh")
			if targetRequests.Load() <= before {
				t.Fatal("expired-cache refresh did not retain the injected transport")
			}

			// A failed refresh does not replace or permanently disable the client.
			rejectRequests.Store(true)
			if err := InitializeWithHTTPClient(context.Background(), server.URL, root, httpClient); err == nil || !strings.Contains(err.Error(), requestError.Error()) {
				t.Fatalf("expected injected transport error, got %v", err)
			}
			rejectRequests.Store(false)
			update("retried refresh")
			if err := InitializeWithHTTPClient(context.Background(), server.URL, root, httpClient); err != nil {
				t.Fatal(err)
			}
			assertHTTPClientTarget(t, "retried refresh")
			if http.DefaultClient != defaultClient || http.DefaultTransport != defaultTransport || http.DefaultClient.Transport != defaultClientTransport {
				t.Fatal("initialization changed a global HTTP client or transport")
			}
		})
	}
}

func TestInitializeWithHTTPClientHonorsRedirectPolicy(t *testing.T) {
	for _, targetRedirect := range []bool{false, true} {
		t.Run("target="+strconv.FormatBool(targetRedirect), func(t *testing.T) {
			directory, root, _ := newHTTPClientTestRepository(t)
			var destinationRequests atomic.Int64
			destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				destinationRequests.Add(1)
			}))
			defer destination.Close()
			files := http.FileServer(http.Dir(directory))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if strings.HasPrefix(req.URL.Path, "/targets/") == targetRedirect {
					http.Redirect(w, req, destination.URL+req.URL.Path, http.StatusFound)
					return
				}
				files.ServeHTTP(w, req)
			}))
			defer server.Close()
			redirectError := errors.New("redirect rejected by configured client")
			var redirects atomic.Int64
			httpClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
				redirects.Add(1)
				return redirectError
			}}
			if err := InitializeWithHTTPClient(context.Background(), server.URL, root, httpClient); err == nil || !strings.Contains(err.Error(), redirectError.Error()) {
				t.Fatalf("expected configured redirect error, got %v", err)
			}
			if redirects.Load() == 0 || destinationRequests.Load() != 0 {
				t.Fatalf("redirect policy calls=%d, destination requests=%d", redirects.Load(), destinationRequests.Load())
			}
		})
	}
}

func TestInitializeWithHTTPClientRejectsClientChanges(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run("legacy="+strconv.FormatBool(legacy), func(t *testing.T) {
			directory, root, _ := newHTTPClientTestRepository(t)
			files := http.FileServer(http.Dir(directory))
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests.Add(1)
				files.ServeHTTP(w, req)
			}))
			defer server.Close()
			if legacy {
				if err := Initialize(context.Background(), server.URL, root); err != nil {
					t.Fatal(err)
				}
			} else if err := InitializeWithHTTPClient(context.Background(), server.URL, root, &http.Client{}); err != nil {
				t.Fatal(err)
			}
			before := requests.Load()
			var replacementRequests atomic.Int64
			replacement := &http.Client{Transport: tufHTTPRoundTripper(func(*http.Request) (*http.Response, error) {
				replacementRequests.Add(1)
				return nil, errors.New("replacement client must not be used")
			})}
			if err := InitializeWithHTTPClient(context.Background(), "https://another-mirror.invalid", root, replacement); !errors.Is(err, ErrHTTPClientMismatch) {
				t.Fatalf("expected client mismatch, got %v", err)
			}
			if requests.Load() != before || replacementRequests.Load() != 0 {
				t.Fatal("client mismatch triggered a network request")
			}
			assertHTTPClientTarget(t, "foo")
		})
	}
}

func TestInitializeWithHTTPClientRejectsNil(t *testing.T) {
	directory, root, _ := newHTTPClientTestRepository(t)
	if err := InitializeWithHTTPClient(context.Background(), "https://unused.invalid", root, nil); err == nil {
		t.Fatal("expected a nil-client error")
	}
	// Rejecting a nil client must not consume the singleton's first initialization.
	server := httptest.NewServer(http.FileServer(http.Dir(directory)))
	defer server.Close()
	if err := Initialize(context.Background(), server.URL, root); err != nil {
		t.Fatal(err)
	}
	assertHTTPClientTarget(t, "foo")
}

func TestInitializeWithHTTPClientPreservesFileMirrors(t *testing.T) {
	directory, root, _ := newHTTPClientTestRepository(t)
	var requests atomic.Int64
	httpClient := &http.Client{Transport: tufHTTPRoundTripper(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("file mirror must not use HTTP")
	})}
	if err := InitializeWithHTTPClient(context.Background(), "file://"+filepath.ToSlash(directory), root, httpClient); err != nil {
		t.Fatal(err)
	}
	assertHTTPClientTarget(t, "foo")
	if requests.Load() != 0 {
		t.Fatal("file mirror used the HTTP client")
	}
}

func TestInitializeWithHTTPClientPreservesMirrorAliases(t *testing.T) {
	for mirror, expected := range map[string]string{
		DefaultRemoteRoot:         DefaultRemoteRoot,
		defaultRemoteGCSBucket:    DefaultRemoteRoot,
		defaultRemoteRootNoCDN:    DefaultRemoteRoot,
		defaultRemoteRootNoCDNAlt: DefaultRemoteRoot,
		"another-tuf-bucket":     "https://another-tuf-bucket.storage.googleapis.com",
	} {
		t.Run(mirror, func(t *testing.T) {
			directory, root, _ := newHTTPClientTestRepository(t)
			server := httptest.NewServer(http.FileServer(http.Dir(directory)))
			defer server.Close()
			localURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{}
			defer transport.CloseIdleConnections()
			var requests atomic.Int64
			httpClient := &http.Client{Transport: tufHTTPRoundTripper(func(req *http.Request) (*http.Response, error) {
				requests.Add(1)
				if req.URL.Scheme+"://"+req.URL.Host != expected {
					t.Errorf("mirror resolved to %s, want %s", req.URL, expected)
					return nil, errors.New("unexpected mirror")
				}
				// Route every request to the local signed fixture, never the internet.
				local := req.Clone(req.Context())
				local.URL.Scheme, local.URL.Host = localURL.Scheme, localURL.Host
				return transport.RoundTrip(local)
			})}
			if err := InitializeWithHTTPClient(context.Background(), mirror, root, httpClient); err != nil {
				t.Fatal(err)
			}
			assertHTTPClientTarget(t, "foo")
			if requests.Load() == 0 {
				t.Fatal("mirror did not use the injected HTTP client")
			}
		})
	}
}

func newHTTPClientTestRepository(t *testing.T) (string, []byte, func(string)) {
	t.Helper()
	resetForTests()
	t.Cleanup(resetForTests)
	t.Setenv(TufRootEnv, t.TempDir())
	t.Setenv(SigstoreNoCache, "false")
	directory := t.TempDir()
	store, repository := newTufRepo(t, directory, "foo")
	metadata, err := store.GetMeta()
	if err != nil {
		t.Fatal(err)
	}
	root, ok := metadata["root.json"]
	if !ok {
		t.Fatal("fixture is missing root metadata")
	}
	return filepath.Join(directory, "repository"), root, func(target string) {
		updateTufRepo(t, directory, repository, target)
	}
}

func assertHTTPClientTarget(t *testing.T, expected string) {
	t.Helper()
	client, err := NewFromEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	target, err := client.GetTarget("foo.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(target, []byte(expected)) {
		t.Fatalf("target = %q, want %q", target, expected)
	}
}

type tufHTTPRoundTripper func(*http.Request) (*http.Response, error)

func (f tufHTTPRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
