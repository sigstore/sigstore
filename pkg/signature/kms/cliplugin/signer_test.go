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

// Package cliplugin implements the plugin functioanlity.
package cliplugin

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"
)

// testCommand mocks a command.
type testCommand struct {
	// command
	output []byte
	err    error
}

// testExitError mocks an exitError.
type testExitError struct {
	exitCode int
}

// ExitCode returns the exitCode.
func (e testExitError) ExitCode() int {
	return e.exitCode
}

// Error returns the error message.
func (e testExitError) Error() string {
	return "test exit error"
}

// Output returns the
func (c testCommand) Output() ([]byte, error) {
	return c.output, c.err
}

// Test_invokePlugin ensures that invokePlugin passes the correct CLI arguments,
// and handles various eror situations as expected.
func Test_invokePlugin(t *testing.T) {
	goodOutput := `{"supportedAlgorithms":{"supportedAlgorithms":["alg1", "alg2"]}}`
	goodResp := &common.PluginResp{
		SupportedAlgorithms: &common.SupportedAlgorithmsResp{
			SupportedAlgorithms: []string{"alg1", "alg2"},
		},
	}
	pluginArgsEnc, err := json.Marshal(common.PluginArgs{
		InitOptions: &common.InitOptions{},
		MethodArgs: &common.MethodArgs{
			MethodName:          common.SupportedAlgorithmsMethodName,
			SupportedAlgorithms: &common.SupportedAlgorithmsArgs{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name             string
		cmdOutput        string
		resp             *common.PluginResp
		err              error
		errContent       string
		commandOutputErr error
	}{
		{
			name:      "success",
			cmdOutput: goodOutput,
			resp:      goodResp,
			err:       nil,
		},
		{
			name:      "success: expected stdin",
			cmdOutput: goodOutput,
			resp:      goodResp,
			err:       nil,
		},
		{
			name:             "success: continue if command exits non-zero",
			cmdOutput:        goodOutput,
			resp:             goodResp,
			err:              nil,
			commandOutputErr: &testExitError{exitCode: 1},
		},
		{
			name:             "failure: command eror, even if command exits 0",
			cmdOutput:        goodOutput,
			resp:             nil,
			err:              ErrorExecutingPlugin,
			commandOutputErr: &testExitError{exitCode: 0},
		},
		{
			name:             "failure: ExitError.ExitStatus() is -1",
			cmdOutput:        goodOutput,
			resp:             nil,
			err:              ErrorExecutingPlugin,
			commandOutputErr: &testExitError{exitCode: -1},
		},
		{
			name:             "failure: any other exec error",
			cmdOutput:        goodOutput,
			resp:             nil,
			err:              ErrorExecutingPlugin,
			commandOutputErr: errors.New("exec-error"),
		},
		{
			name:       "error: plugin program error",
			cmdOutput:  `{"errorMessage": "any-error"}`,
			err:        ErrorPluginReturnError,
			errContent: "any-error",
		},
		{
			name:      "error: empty resp",
			cmdOutput: "",
			err:       ErrorResponseParseError,
		},
		{
			name:      "error: invalid json resp",
			cmdOutput: "abc",
			err:       ErrorResponseParseError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			makeCommandFunc := func(ctx context.Context, stdin io.Reader, stderr io.Writer, name string, args ...string) command {
				if name != "sigstore-kms-test" {
					t.Fatalf("unexpected executable name: %s", name)
				}
				if args[0] != common.ProtocolVersion {
					t.Fatalf("unexpected protocol version: %s", args[0])
				}
				if args[1] != string(pluginArgsEnc) {
					t.Fatalf("unexpected args: %s", args[1])
				}
				return testCommand{
					output: []byte(tc.cmdOutput),
					err:    tc.commandOutputErr,
				}
			}
			testPluginClient := newPluginClient(
				"sigstore-kms-test",
				&common.InitOptions{},
				makeCommandFunc,
			)
			resp, err := testPluginClient.invokePlugin(context.TODO(), nil, &common.MethodArgs{
				MethodName:          common.SupportedAlgorithmsMethodName,
				SupportedAlgorithms: &common.SupportedAlgorithmsArgs{},
			})
			if errorDiff := cmp.Diff(tc.err, err, cmpopts.EquateErrors()); errorDiff != "" {
				t.Errorf("unexpected error (-want +got):\n%s", errorDiff)
			}
			if respDiff := cmp.Diff(tc.resp, resp); respDiff != "" {
				t.Errorf("unexpected resp (-want +got):\n%s", respDiff)
			}
			if err != nil && !strings.Contains(err.Error(), tc.errContent) {
				t.Errorf("error content does not contain expecrted substring (-want +got): \n-%s\n+%s", tc.errContent, err.Error())
			}
		})
	}
}

// TestSignerVerifierImpl is a mock implemention of SignerVerifier.
type TestSignerVerifierImpl struct {
	kms.SignerVerifier
	t             *testing.T
	wantedErr     error
	wantedMessage []byte
	// TODO: use extracted values from signature.RPCOption, and signature.SignOption.
	wantedSignature []byte
}

// SignMessage is a mock implementation of SignMessage,
// where received arguments are compared against the saved expected values.
func (s TestSignerVerifierImpl) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	slog.Info("ImplSignMessage", "opts", opts)
	messageBytes, err := io.ReadAll(message)
	if err != nil {
		s.t.Fatal(err)
	}
	if diff := cmp.Diff(s.wantedMessage, messageBytes); diff != "" {
		s.t.Errorf("message mismatch (-want +got):\n%s", diff)
	}
	var KeyVersion string
	var cryptoSignerOpts crypto.SignerOpts
	for _, opt := range opts {
		opt.ApplyKeyVersion(&KeyVersion)
		opt.ApplyCryptoSignerOpts(&cryptoSignerOpts)
	}
	return s.wantedSignature, s.wantedErr
}

// Test_SignMessage ensures that both the client and plugin send and receive the expected values.
func Test_SignMessage(t *testing.T) {
	tests := []struct {
		name    string
		message []byte
		// TODO: use extracted values from signature.RPCOption, and signature.SignOption.
		implSig []byte
		implErr error
		err     error
	}{
		{
			name:    "success",
			message: []byte(`my-message`),
			implSig: []byte(`my-signature`),
			implErr: nil,
			err:     nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			makeCommandFunc := func(ctx context.Context, stdin io.Reader, stderr io.Writer, name string, args ...string) command {
				osArgs := append([]string{name}, args...)
				pluginArgs, err := handler.GetPluginArgs(osArgs)
				if err != nil {
					t.Fatal(err)
				}
				if pluginArgs.MethodName != common.SignMessageMethodName {
					t.Fatalf("unexpected method: %s", pluginArgs.MethodName)
				}
				var respBuffer bytes.Buffer
				_, err = handler.Dispatch(&respBuffer, stdin, pluginArgs, TestSignerVerifierImpl{
					t:               t,
					wantedErr:       tc.implErr,
					wantedMessage:   tc.message,
					wantedSignature: tc.implSig,
				})
				if err != nil {
					t.Fatal(err)
				}
				return testCommand{
					output: respBuffer.Bytes(),
					err:    err,
				}
			}
			testPluginClient := newPluginClient(
				"sigstore-kms-test",
				&common.InitOptions{},
				makeCommandFunc,
			)
			signature, err := testPluginClient.SignMessage(bytes.NewReader(tc.message))
			if errorDiff := cmp.Diff(tc.err, err, cmpopts.EquateErrors()); errorDiff != "" {
				t.Errorf("unexpected error (-want +got):\n%s", errorDiff)
			}
			if diff := cmp.Diff(tc.implSig, signature); diff != "" {
				t.Errorf("signature mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
