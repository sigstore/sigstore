//
// Copyright 2025 The Sigstore Authors.
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
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/encoding"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

var (
	testExecutable         = "sigstore-kms-test"
	testPluginErrorMessage = "404: not found"
	testKeyResourceID      = "testkms://testkey"
	testContextDeadline    = time.Date(2025, 4, 1, 2, 47, 0, 0, time.UTC)
	testDefaultAlgorithm   = "alg1"
	testPublicKey          crypto.PublicKey
	testMessageBytes       = []byte(`my-message`)
	testSignatureBytes     = []byte(`my-signature`)
	testHashFunction       = crypto.SHA512
	testKeyVersion         = "my-key-version"
	testRemoteVerification = true
	testDigest             = []byte("my-digest")
)

type testCmd struct {
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

func (c testCmd) Output() ([]byte, error) {
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

// TestInvokePlugin ensures invokePlugin returns an error in the correct situations by mocking the Cmd function.
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
		cmdOutputErr          error
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
			name:           "success: continue if command exits non-zero",
			cmdOutputBytes: goodOutput,
			cmdOutputErr:   &testExitError{exitCode: 1},
			resp:           goodResp,
		},
		{
			name:           "failure: command eror, even if command exits 0",
			cmdOutputBytes: goodOutput,
			cmdOutputErr:   &testExitError{exitCode: 0},
			err:            ErrorExecutingPlugin,
		},
		{
			name:           "failure: ExitError.ExitStatus() is -1",
			cmdOutputBytes: goodOutput,
			cmdOutputErr:   &testExitError{exitCode: -1},
			err:            ErrorExecutingPlugin,
		},
		{
			name:           "failure: any other exec error",
			cmdOutputBytes: goodOutput,
			cmdOutputErr:   errors.New("exec-error"),
			err:            ErrorExecutingPlugin,
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
			// mock the behavior of Cmd, simulating a plugin program.
			makeCmdFunc := func(ctx context.Context, stdin io.Reader, stderr io.Writer, name string, args ...string) cmd {
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
				return testCmd{
					output: tc.cmdOutputBytes,
					err:    tc.cmdOutputErr,
				}
			}
			// client with our mocked Cmd
			testPluginClient := newPluginClient(testExecutable, testInitOptions, makeCmdFunc)
			// invokePlugin
			testContext := context.Background()
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
// expected values are both sent and received through the encoding and decoding processes.
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

// SignMessage checsk the expected message and opts, and returns the epxtected signature.
func (s testSignerVerifierImpl) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	messageBytes, err := io.ReadAll(message)
	if err != nil {
		return nil, err
	}
	if diff := cmp.Diff(testMessageBytes, messageBytes); diff != "" {
		s.t.Errorf("unexpected message (-want +got):\n%s", diff)
	}
	signOptions := encoding.PackSignOptions(opts)
	// we use a common.SignOptions{} so that we can use one cmp.Diff() call to check all the expected values.
	wantedSignOptions := &common.SignOptions{
		RPCOptions: common.RPCOptions{
			CtxDeadline:        &testContextDeadline,
			KeyVersion:         &testKeyVersion,
			RemoteVerification: &testRemoteVerification,
		},
		MessageOptions: common.MessageOptions{
			Digest:   &testDigest,
			HashFunc: &testHashFunction,
		},
	}
	if diff := cmp.Diff(wantedSignOptions, signOptions); diff != "" {
		s.t.Errorf("unexpected sign options (-want +got):\n%s", diff)
	}
	return testSignatureBytes, nil
}

// VerifySignature checks the expected message and opts.
func (s testSignerVerifierImpl) VerifySignature(signature io.Reader, message io.Reader, opts ...signature.VerifyOption) error {
	signatureBytes, err := io.ReadAll(signature)
	if err != nil {
		return err
	}
	if diff := cmp.Diff(testSignatureBytes, signatureBytes); diff != "" {
		s.t.Errorf("unexpected signature (-want +got):\n%s", diff)
	}
	messageBytes, err := io.ReadAll(message)
	if err != nil {
		return err
	}
	if diff := cmp.Diff(testMessageBytes, messageBytes); diff != "" {
		s.t.Errorf("unexpected message (-want +got):\n%s", diff)
	}
	signOptions := encoding.PackVerifyOptions(opts)
	// we use a common.VerifyOptions{} so that we can use one cmp.Diff() call to check all the expected values.
	wantedSignOptions := &common.VerifyOptions{
		RPCOptions: common.RPCOptions{
			CtxDeadline:        &testContextDeadline,
			KeyVersion:         &testKeyVersion,
			RemoteVerification: &testRemoteVerification,
		},
		MessageOptions: common.MessageOptions{
			Digest:   &testDigest,
			HashFunc: &testHashFunction,
		},
	}
	if diff := cmp.Diff(wantedSignOptions, signOptions); diff != "" {
		s.t.Errorf("unexpected verify options (-want +got):\n%s", diff)
	}
	return nil
}

// TestPluginClient tests each of PluginClient's methods for correct encoding and decoding between a simulated plugin program,
// by mocking the makeCmdFunc function and using TestSignerVerifierImpl to both check and return expected values.
func TestPluginClient(t *testing.T) {
	t.Parallel()

	// Mock the behavior of Cmd to simulates a real plugin program by
	// calling the helper handler functions `GetPluginArgs()` and `Dispatch()`, passing along the stdin, stdout, and args.
	makeCmdFunc := func(ctx context.Context, stdin io.Reader, stderr io.Writer, name string, args ...string) cmd {
		// Use the helper functions in the handler package.
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
		return testCmd{
			output: stdout.Bytes(),
			err:    err,
		}
	}
	testPluginClient := newPluginClient(
		testExecutable,
		&common.InitOptions{},
		makeCmdFunc,
	)
	testContext, _ := context.WithDeadline(context.Background(), testContextDeadline)
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
			t.Errorf("eerror mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("SignMessage", func(t *testing.T) {
		t.Parallel()

		testContext, _ := context.WithDeadline(context.Background(), testContextDeadline)
		testOpts := []signature.SignOption{
			options.WithContext(testContext),
			options.WithKeyVersion(testKeyVersion),
			options.WithRemoteVerification(testRemoteVerification),
			options.WithDigest(testDigest),
			options.WithCryptoSignerOpts(testHashFunction),
		}
		signature, err := testPluginClient.SignMessage(bytes.NewReader(testMessageBytes), testOpts...)

		if diff := cmp.Diff(testSignatureBytes, signature); diff != "" {
			t.Errorf("signature mismatch (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(testErr, err); diff != "" {
			t.Errorf("error mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("VerifySignature", func(t *testing.T) {
		t.Parallel()

		testContext, _ := context.WithDeadline(context.Background(), testContextDeadline)
		testOpts := []signature.VerifyOption{
			options.WithContext(testContext),
			options.WithKeyVersion(testKeyVersion),
			options.WithRemoteVerification(testRemoteVerification),
			options.WithDigest(testDigest),
			options.WithCryptoSignerOpts(testHashFunction),
		}
		err := testPluginClient.VerifySignature(bytes.NewReader(testSignatureBytes), bytes.NewReader(testMessageBytes), testOpts...)

		if diff := cmp.Diff(testErr, err); diff != "" {
			t.Errorf("error mismatch (-want +got):\n%s", diff)
		}
	})
}
