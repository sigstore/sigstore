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
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"
)

var (
	testExecutable         = "sigstore-kms-test"
	testPluginErrorMessage = "404: not found"
	testKeyResourceID      = "testkms://testkey"
	testContextDeadline    = time.Date(2025, 4, 1, 2, 47, 0, 0, time.UTC)
	testDefaultAlgorithm   = "alg1"
	testPublicKey          crypto.PublicKey
	testHashFunction       = crypto.SHA512
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
	var err error
	testPublicKey, err = cryptoutils.UnmarshalPEMToPublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcCPm8ay9sb2hrueFvuwL8pGjQBnd
HrgLLNu5Gj06Y2S8vvR3MBWbChpOIKGh1YrDoa4lt/XfjaNcHq7vcuYXwg==
-----END PUBLIC KEY-----`))
	if err != nil {
		panic(err)
	}

	exitCode := m.Run() // Run all tests
	os.Exit(exitCode)
}

// TestInvokePlugin ensures invokePlugin returns an error in the correct situations by mocking the Command function.
func TestInvokePlugin(t *testing.T) {
	testStdinBytes := []byte("my-stdin")
	testMethodArgs := &common.MethodArgs{
		MethodName:       common.DefaultAlgorithmMethodName,
		DefaultAlgorithm: &common.DefaultAlgorithmArgs{},
	}
	testInitOptions := &common.InitOptions{
		ProtocolVersion: common.ProtocolVersion,
		KeyResourceID:   testKeyResourceID,
		HashFunc:        testHashFunction,
	}
	testPluginArgs := &common.PluginArgs{
		InitOptions: testInitOptions,
		MethodArgs:  testMethodArgs,
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

	// A serialized error by the plugin program in stdout.
	testErrorOutput, err := json.Marshal(&common.PluginResp{
		ErrorMessage: testPluginErrorMessage,
	})
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
		// command and plugin error handling
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
			cmdOutputBytes:        testErrorOutput,
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
				if diff := cmp.Diff(testExecutable, name); diff != "" {
					t.Errorf("unexpected executable name (-want +got):\n%s", diff)
				}
				if diff := cmp.Diff(common.ProtocolVersion, args[0]); diff != "" {
					t.Errorf("unexpected protocol version (-want +got):\n%s", diff)
				}
				if stdinBytes, err := io.ReadAll(stdin); err != nil {
					t.Errorf("reading stdin: %v", err)
				} else if diff := cmp.Diff(testStdinBytes, stdinBytes); diff != "" {
					t.Errorf("unexpected stdin bytes (-want +got):\n%s", diff)
				}
				osArgs := append([]string{name}, args...)
				if pluginArgs, err := handler.GetPluginArgs(osArgs); err != nil {
					t.Error(err)
				} else if diff := cmp.Diff(testPluginArgs, pluginArgs); diff != "" {
					t.Errorf("parsing plugin args (-want +got):\n%s", diff)
				}
				return testCommand{
					output: tc.cmdOutputBytes,
					err:    tc.commandOutputErr,
				}
			}
			// client with our mocked Command
			testPluginClient := newPluginClient(testExecutable, testInitOptions, makeCommandFunc)
			// invokePlugin
			testContext := context.TODO()
			testStdin := bytes.NewBuffer(testStdinBytes)
			resp, err := testPluginClient.invokePlugin(testContext, testStdin, testMethodArgs)
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

// testSignerVerifierImpl is a mock implementation that asserts that the
// expected values are both sent and received through the encoding and decoding processes
type testSignerVerifierImpl struct {
	// TODO: remove this embedding after all methods are implemented.
	kms.SignerVerifier
	t *testing.T
}

// DefaultAlgorithm accepts no arguments, but returns an expected value.
func (s testSignerVerifierImpl) DefaultAlgorithm() string {
	return testDefaultAlgorithm
}

// CreateKey checks the expected context deadline and algorithm, and returns the expected public key.
func (s testSignerVerifierImpl) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
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

// TestPluginClient tests each of PluginClient's methods for correct encoding and decoding between a simulated plugin program,
// by mocking the Command function and using TestSignerVerifierImpl to both check and return expected values.
func TestPluginClient(t *testing.T) {
	t.Parallel()

	// Mock the behavior of Command to simulates a real plugin program by
	// calling the helper handler functions `GetPluginArgs()` and `Dispatch()`, passing along the stdin stdout, and args.
	makeCommandFunc := func(ctx context.Context, stdin io.Reader, stderr io.Writer, name string, args ...string) command {
		// Use the helpfer functions in the handler package.
		osArgs := append([]string{name}, args...)
		pluginArgs, err := handler.GetPluginArgs(osArgs)
		if err != nil {
			t.Error(err)
		}
		var stdout bytes.Buffer
		_, err = handler.Dispatch(&stdout, stdin, pluginArgs, testSignerVerifierImpl{
			t: t,
		})
		if err != nil {
			t.Error(err)
		}
		return testCommand{
			output: stdout.Bytes(),
			err:    err,
		}
	}
	testPluginClient := newPluginClient(
		testExecutable,
		&common.InitOptions{},
		makeCommandFunc,
	)
	testContext, _ := context.WithDeadline(context.TODO(), testContextDeadline)
	var testErr error = nil

	t.Run("DefaultAlgorithm", func(t *testing.T) {
		t.Parallel()

		defaultAlgorithm := testPluginClient.DefaultAlgorithm()
		if diff := cmp.Diff(testDefaultAlgorithm, defaultAlgorithm); diff != "" {
			t.Errorf("default algorithm mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("CreateKey", func(t *testing.T) {
		t.Parallel()

		publicKey, err := testPluginClient.CreateKey(testContext, testDefaultAlgorithm)
		if diff := cmp.Diff(testPublicKey, publicKey); diff != "" {
			t.Errorf("public key mismatch (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(testErr, err); diff != "" {
			t.Errorf("error mismatch (-want +got):\n%s", diff)
		}
	})
}
