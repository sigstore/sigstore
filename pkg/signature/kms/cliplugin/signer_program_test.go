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
	"bytes"
	"context"
	"crypto"
	"flag"
	"io"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/options"
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
func getPluginClient(t *testing.T) *PluginClient {
	t.Helper()
	signerVerifier, err := LoadSignerVerifier(context.TODO(), *inputKeyResourceID, testHashFunc)
	if err != nil {
		t.Fatal(err)
	}
	pluginClient := signerVerifier.(*PluginClient)
	return pluginClient
}

// TestInvokePlugin ensures that ctx deadline is respected by Command, and that errors are correctly handled.
func TestInvokePlugin(t *testing.T) {
	t.Parallel()

	pluginClient := getPluginClient(t)
	noDeadlineContext := context.TODO()
	duration := time.Minute * 3
	futureDeadlineContext, _ := context.WithDeadline(noDeadlineContext, time.Now().Add(duration))
	expiredDeadlineContext, _ := context.WithDeadline(noDeadlineContext, time.Now().Add(-duration))
	canceledContext, cancel := context.WithCancel(noDeadlineContext)
	cancel()

	tests := []struct {
		name       string
		ctx        context.Context
		methodName string
		err        error
	}{
		{
			name:       "success: no deadline",
			ctx:        noDeadlineContext,
			methodName: common.DefaultAlgorithmMethodName,
			err:        nil,
		},
		{
			name:       "success: future deadline",
			ctx:        futureDeadlineContext,
			methodName: common.DefaultAlgorithmMethodName,
			err:        nil,
		},
		{
			name:       "failure: expired deadline",
			ctx:        expiredDeadlineContext,
			methodName: common.DefaultAlgorithmMethodName,
			err:        ErrorExecutingPlugin,
		},
		{
			name:       "failure: canceled context",
			ctx:        canceledContext,
			methodName: common.DefaultAlgorithmMethodName,
			err:        ErrorExecutingPlugin,
		},
		{
			name: "failure: unknown method",
			ctx:  noDeadlineContext,
			err:  ErrorPluginReturnError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stdin := bytes.NewReader([]byte(``))
			methodArgs := &common.MethodArgs{
				MethodName: tc.methodName,
			}
			_, err := pluginClient.invokePlugin(tc.ctx, stdin, methodArgs)
			if diff := cmp.Diff(tc.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("unexpected error (-want +got): \n%s", diff)
			}
		})
	}
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
	ctx := context.Background()
	defaultAlgorithm := pluginClient.DefaultAlgorithm()

	tests := []struct {
		name      string
		algorithm string
		err       error
	}{
		{
			name:      "success: default algorithm",
			algorithm: defaultAlgorithm,
			err:       nil,
		},
		{
			name:      "failure: unsupported algorithm",
			algorithm: "any-algorithm",
			err:       ErrorPluginReturnError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			publicKey, err := pluginClient.CreateKey(ctx, tc.algorithm)

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

// TestCreateKey invokes SignMessage against the compiled plugin program,
// with combinations of empty or non-empty messages, and digests.
// Since implementations can vary, it merely checks that non-empty signature is returned.
func TestSignMessage(t *testing.T) {
	t.Parallel()

	pluginClient := getPluginClient(t)

	testMessageBytes := []byte("any message")
	hasher := testHashFunc.New()
	if _, err := hasher.Write(testMessageBytes); err != nil {
		t.Fatal(err)
	}
	testDigest := hasher.Sum(nil)
	testEmptyBytes := []byte(``)
	testBadDigest := []byte("bad digest")

	ctx := context.Background()
	defaultAlgorithm := pluginClient.DefaultAlgorithm()
	_, err := pluginClient.CreateKey(ctx, defaultAlgorithm)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		message io.Reader
		digest  *[]byte
		err     error
	}{
		{
			name:    "message only, no digest",
			message: bytes.NewReader(testMessageBytes),
		},
		{
			name:    "digest only, empty message",
			message: bytes.NewReader(testEmptyBytes),
			digest:  &testDigest,
		},
		{
			name:    "message and digest",
			message: bytes.NewReader(testMessageBytes),
			digest:  &testDigest,
		},
		{
			name:    "failure: bad digest, empty message",
			message: bytes.NewReader(testEmptyBytes),
			digest:  &testBadDigest,
			err:     ErrorPluginReturnError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := []signature.SignOption{}
			if tc.digest != nil {
				opts = append(opts, options.WithDigest(*tc.digest))
			}
			signature, err := pluginClient.SignMessage(tc.message, opts...)
			if diff := cmp.Diff(tc.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("unexpected error (-want +got): \n%s", diff)
			}
			if err == nil && len(signature) == 0 {
				t.Error("expected non-empty signature")
			}
		})
	}
}
