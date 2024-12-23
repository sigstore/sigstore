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
package cliplugin

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"
)

var (
	testExecutable         = "sigstore-kms-test"
	testPluginErrorMessage = "404: not found"
	testContextDeadline    = time.Now().Add(time.Minute * 47)
	testDefaultAlgorithm   = "alg1"
	testPublicKey          crypto.PublicKey
)

type testCommand struct {
	output []byte
	err    error
}

type testExitError struct {
	exitCode int
}

func (e testExitError) ExitCode() int {
	return e.exitCode
}

func (e testExitError) Error() string {
	return "test exit error"
}

func (c testCommand) Output() ([]byte, error) {
	return c.output, c.err
}

func TestMain(m *testing.M) {
	// Perform global setup here

	// prepare testPublicKey
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("rsa.GenerateKey failed: %v", err))
	}
	testPublicKey = priv.Public()

	exitCode := m.Run() // Run all tests
	os.Exit(exitCode)
}

func TestInvokePlugin(t *testing.T) {
	goodPluginArgsEnc, err := json.Marshal(common.PluginArgs{
		InitOptions: &common.InitOptions{},
		MethodArgs: &common.MethodArgs{
			MethodName:       common.DefaultAlgorithmMethodName,
			DefaultAlgorithm: &common.DefaultAlgorithmArgs{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	goodResp := &common.PluginResp{
		DefaultAlgorithm: &common.DefaultAlgorithmResp{
			DefaultAlgorithm: testDefaultAlgorithm,
		},
	}
	goodOutput, err := json.Marshal(goodResp)
	if err != nil {
		t.Fatal(err)
	}
	errorResp := &common.PluginResp{
		ErrorMessage: testPluginErrorMessage,
	}
	errorOutput, err := json.Marshal(errorResp)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name                  string
		cmdOutputBytes        []byte
		commandOutputErr      error
		resp                  *common.PluginResp
		err                   error
		errorMessageSubstring string
	}{
		{
			name:           "success",
			cmdOutputBytes: goodOutput,
			resp:           goodResp,
		},
		{
			name:           "success: expected stdin",
			cmdOutputBytes: goodOutput,
			resp:           goodResp,
		},
		{
			name:             "success: continue if command exits non-zero",
			cmdOutputBytes:   goodOutput,
			commandOutputErr: &testExitError{exitCode: 1},
			resp:             goodResp,
		},
		{
			name:             "failure: command eror, even if command exits 0",
			cmdOutputBytes:   goodOutput,
			commandOutputErr: &testExitError{exitCode: 0},
			err:              ErrorExecutingPlugin,
		},
		{
			name:             "failure: ExitError.ExitStatus() is -1",
			cmdOutputBytes:   goodOutput,
			commandOutputErr: &testExitError{exitCode: -1},
			err:              ErrorExecutingPlugin,
		},
		{
			name:             "failure: any other exec error",
			cmdOutputBytes:   goodOutput,
			commandOutputErr: errors.New("exec-error"),
			err:              ErrorExecutingPlugin,
		},
		{
			name:                  "error: plugin program error",
			cmdOutputBytes:        errorOutput,
			err:                   ErrorPluginReturnError,
			errorMessageSubstring: testPluginErrorMessage,
		},
		{
			name:           "error: empty resp",
			cmdOutputBytes: []byte(""),
			err:            ErrorResponseParse,
		},
		{
			name:           "error: invalid json resp",
			cmdOutputBytes: []byte("abc"),
			err:            ErrorResponseParse,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// mock the behavior of Command.
			makeCommandFunc := func(ctx context.Context, stdin io.Reader, stderr io.Writer, name string, args ...string) command {
				t.Helper()
				if name != testExecutable {
					t.Fatalf("unexpected executable name: %s", name)
				}
				if args[0] != common.ProtocolVersion {
					t.Fatalf("unexpected protocol version: %s", args[0])
				}
				if args[1] != string(goodPluginArgsEnc) {
					t.Fatalf("unexpected args: %s", args[1])
				}
				return testCommand{
					output: tc.cmdOutputBytes,
					err:    tc.commandOutputErr,
				}
			}
			// client with our mocked Command
			testPluginClient := newPluginClient(
				testExecutable,
				&common.InitOptions{},
				makeCommandFunc,
			)
			// invokePlugin
			resp, err := testPluginClient.invokePlugin(context.TODO(), nil, &common.MethodArgs{
				MethodName:       common.DefaultAlgorithmMethodName,
				DefaultAlgorithm: &common.DefaultAlgorithmArgs{},
			})
			// compare results
			if respDiff := cmp.Diff(tc.resp, resp); respDiff != "" {
				t.Errorf("unexpected resp (-want +got):\n%s", respDiff)
			}
			if errorDiff := cmp.Diff(tc.err, err, cmpopts.EquateErrors()); errorDiff != "" {
				t.Errorf("unexpected error (-want +got):\n%s", errorDiff)
			}
			if err != nil && !strings.Contains(err.Error(), tc.errorMessageSubstring) {
				t.Errorf("error content does not contain expecrted substring (-want +got): \n-%s\n+%s", tc.errorMessageSubstring, err.Error())
			}
		})
	}
}

// TestSignerVerifierImpl is a mock implementation that asserts that the
// expected values are both sent and received through the encoding and decoding processes
// for each method. Each method should invoke `s.t.Helper()` for easier debug outputs.
type TestSignerVerifierImpl struct {
	// TODO: remove this embedding after all methods are implemented.
	kms.SignerVerifier
	t *testing.T
}

// DefaultAlgorithm accepts no arguments, but returns an expected value.
func (s TestSignerVerifierImpl) DefaultAlgorithm() string {
	s.t.Helper()
	return testDefaultAlgorithm
}

// CreateKey accepts checks the expected context deadline and algorithm, and returns the expected public key.
func (s TestSignerVerifierImpl) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	s.t.Helper()
	if diff := cmp.Diff(testDefaultAlgorithm, algorithm); diff != "" {
		s.t.Errorf("unexpected algorithm (-want +got):\n%s", diff)
	}
	ctxDeadline, ok := ctx.Deadline()
	if !ok {
		s.t.Errorf("expected a deadline")
	}
	if diff := cmp.Diff(testContextDeadline, ctxDeadline); diff != "" {
		s.t.Errorf("unexpected context deadline (-want +got):\n%s", diff)
	}
	return testPublicKey, nil
}

// makeTestCommandFunc returns a makeCommandFunc with the testing.T. It simulates a real plugin program by
// calling the helper handler functions `GetPluginArgs()` and `Dispatch()`, passing along the stdin stdout, and args.
func makeTestCommandFunc(t *testing.T) makeCommandFunc {
	t.Helper()
	makeCommandFunc := func(ctx context.Context, stdin io.Reader, stderr io.Writer, name string, args ...string) command {
		t.Helper()
		if name != testExecutable {
			t.Fatalf("unexpected executable name: %s", name)
		}
		if args[0] != common.ProtocolVersion {
			t.Fatalf("unexpected protocol version: %s", args[0])
		}
		// Use the helpfer functions in the handler package.
		osArgs := append([]string{name}, args...)
		pluginArgs, err := handler.GetPluginArgs(osArgs)
		if err != nil {
			t.Fatal(err)
		}
		var stdout bytes.Buffer
		_, err = handler.Dispatch(&stdout, stdin, pluginArgs, TestSignerVerifierImpl{
			t: t,
		})
		if err != nil {
			t.Fatal(err)
		}
		return testCommand{
			output: stdout.Bytes(),
			err:    err,
		}
	}
	return makeCommandFunc
}

func TestDefaultAlgorithm(t *testing.T) {
	tests := []struct {
		name             string
		defaultAlgorithm string
	}{
		{
			name:             "success",
			defaultAlgorithm: testDefaultAlgorithm,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Mock the behavior of Command.
			makeCommandFunc := makeTestCommandFunc(t)
			// Invoke the method.
			testPluginClient := newPluginClient(
				testExecutable,
				&common.InitOptions{},
				makeCommandFunc,
			)
			defaultAlgorithm := testPluginClient.DefaultAlgorithm()
			if diff := cmp.Diff(tc.defaultAlgorithm, defaultAlgorithm); diff != "" {
				t.Errorf("Default algorithm mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCreateKey(t *testing.T) {
	testContext, _ := context.WithDeadline(context.TODO(), testContextDeadline)
	tests := []struct {
		name      string
		ctx       context.Context
		algorithm string
		publicKey crypto.PublicKey
		err       error
	}{
		{
			name:      "success",
			ctx:       testContext,
			algorithm: testDefaultAlgorithm,
			publicKey: testPublicKey,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Mock the behavior of Command.
			makeCommandFunc := makeTestCommandFunc(t)
			// Invoke the method.
			testPluginClient := newPluginClient(
				testExecutable,
				&common.InitOptions{},
				makeCommandFunc,
			)
			publicKey, err := testPluginClient.CreateKey(tc.ctx, tc.algorithm)
			if diff := cmp.Diff(tc.publicKey, publicKey); diff != "" {
				t.Errorf("Public key mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.err, err); diff != "" {
				t.Errorf("Error mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
