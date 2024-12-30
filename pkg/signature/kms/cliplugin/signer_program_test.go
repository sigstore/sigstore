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

// Package cliplugin implements the plugin functionality.

//go:build signer_program
// +build signer_program

package cliplugin

import (
	"context"
	"crypto"
	"flag"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/sigstore/pkg/signature/kms"
)

// This file tests the PluginClient against a pre-built plugin programs.
// It is skipped during normal `go test ./...` invocations. It can be invoked like
// `go test -tags=signer_program -count=1 ./... -key-resource-id [my-kms]://[my-key-ref]`
// See ./README.md for plugin program usage.

var (
	inputKeyResourceID = flag.String("key-resource-id", "", "key resource ID for the KMS, defaults to 'testkms://testkey'")
	testHashFunc       = crypto.SHA512
)

// getPluginClient parses the build flags for the KeyResourceID and returns a PluginClient.
func getPluginClient(t *testing.T) kms.SignerVerifier {
	t.Helper()
	pluginClient, err := LoadSignerVerifier(context.TODO(), *inputKeyResourceID, testHashFunc)
	if err != nil {
		t.Fatal(err)
	}
	return pluginClient
}

// TestDefaultAlgorithm invokes DefaultAlgorithm against the compiled plugin program.
// Since implementations can vary, it merely checks that some non-empty value is returned.
func TestDefaultAlgorithm(t *testing.T) {
	t.Parallel()

	pluginClient := getPluginClient(t)

	if defaultAlgorithm := pluginClient.DefaultAlgorithm(); defaultAlgorithm == "" {
		t.Error("expected non-empty default algorithm")
	}
}

// TestCreateKey invokes CreateKey against the compiled plugin program.
// Since implementations can vary, it merely checks that some public key is returned,
// and that the ctx argument's deadline is respected.
func TestCreateKey(t *testing.T) {
	t.Parallel()

	pluginClient := getPluginClient(t)

	defaultAlgorithm := pluginClient.DefaultAlgorithm()

	noDeadlineContext := context.TODO()
	duration := time.Minute * 3
	futureDeadlineContext, _ := context.WithDeadline(noDeadlineContext, time.Now().Add(duration))
	expiredDeadlineContext, _ := context.WithDeadline(noDeadlineContext, time.Now().Add(-duration))
	canceledContext, cancel := context.WithCancel(noDeadlineContext)
	cancel()

	// TODO: test cases with varying context deadline really should be test cases against invokePlugin(),
	// not CreateKey(). But this would require some monkey-patching against the Command used.
	tests := []struct {
		name      string
		ctx       context.Context
		algorithm string
		err       error
	}{
		{
			name:      "success: default algorithm, no deadline",
			ctx:       noDeadlineContext,
			algorithm: defaultAlgorithm,
			err:       nil,
		},
		{
			name:      "failure: unsupported algorithm, no deadline",
			ctx:       noDeadlineContext,
			algorithm: "any-algorithm",
			err:       ErrorPluginReturnError,
		},
		{
			name:      "success: default algorithm, future deadline",
			ctx:       futureDeadlineContext,
			algorithm: defaultAlgorithm,
			err:       nil,
		},
		{
			name:      "failuire: default algorithm, expired deadline",
			ctx:       expiredDeadlineContext,
			algorithm: defaultAlgorithm,
			err:       ErrorExecutingPlugin,
		},
		{
			name:      "failuire: default algorithm, canceled context",
			ctx:       canceledContext,
			algorithm: defaultAlgorithm,
			err:       ErrorExecutingPlugin,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			publicKey, err := pluginClient.CreateKey(tc.ctx, tc.algorithm)

			if diff := cmp.Diff(tc.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("unexpected error (-want +got): \n%s", diff)
			}

			if err != nil {
				if diff := cmp.Diff(nil, publicKey, cmpopts.EquateComparable()); diff != "" {
					t.Errorf("expected nil publicKey (-want +got): \n%s", diff)
				}
			} else {
				if publicKey == nil {
					t.Error("unexpected non-nil publicKey")
				}
			}
		})
	}
}
