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
	"github.com/sigstore/sigstore/pkg/signature/options"
)

type testCommand struct {
	// command
	outputFunc func() ([]byte, error)
	err        error
}

type testExitError struct {
	// *exec.ExitError
	exitCode int
}

func (e testExitError) ExitCode() int {
	return e.exitCode
}

func (e testExitError) Error() string {
	return "test exit error"
}

func (c testCommand) Output() ([]byte, error) {
	return c.outputFunc()
}
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
			MethodName:         common.SupportedAlgorithmsMethodName,
			SuportedAlgorithms: &common.SupportedAlgorithmsArgs{},
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
					outputFunc: func() ([]byte, error) {
						return []byte(tc.cmdOutput), tc.commandOutputErr
					},
					err: tc.commandOutputErr,
				}
			}
			testPluginClient := newPluginClient(
				context.TODO(),
				"sigstore-kms-test",
				&common.InitOptions{},
				makeCommandFunc,
			)
			resp, err := testPluginClient.invokePlugin(context.TODO(), nil, &common.SupportedAlgorithmsArgs{})
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

type TestSignerVerifierImpl struct {
	kms.SignerVerifier
	t                      *testing.T
	wantedErr              error
	wantedMessage          []byte
	wantedcryptoSignerOpts crypto.SignerOpts
	wantedKeyVersion       string
	wantedSignature        []byte
}

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
	if diff := cmp.Diff(s.wantedKeyVersion, KeyVersion); diff != "" {
		s.t.Errorf("KeyVersion mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(s.wantedcryptoSignerOpts, cryptoSignerOpts); diff != "" {
		s.t.Errorf("cryptoSignerOpts mismatch (-want +got):\n%s", diff)
	}
	return s.wantedSignature, s.wantedErr
}

func Test_SignMessage(t *testing.T) {
	tests := []struct {
		name             string
		message          []byte
		keyVersion       string
		cryptoSignerOpts crypto.SignerOpts
		implSig          []byte
		implErr          error
		err              error
	}{
		{
			name:             "success",
			message:          []byte(`my-message`),
			keyVersion:       "1",
			cryptoSignerOpts: crypto.SHA384,
			implSig:          []byte(`my-signatureXXXXXXX000000`),
			implErr:          nil,
			err:              nil,
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
				if *pluginArgs.SignMessage.SignOptions.KeyVersion != tc.keyVersion {
					t.Fatalf("unexpected key version: %s", *pluginArgs.SignMessage.SignOptions.KeyVersion)
				}
				if *pluginArgs.SignMessage.SignOptions.HashFunc != tc.cryptoSignerOpts.HashFunc() {
					t.Fatalf("unexpected hash func: %s", *pluginArgs.SignMessage.SignOptions.HashFunc)
				}
				var respBuffer bytes.Buffer
				_, err = handler.Dispatch(&respBuffer, stdin, pluginArgs, TestSignerVerifierImpl{
					t:                      t,
					wantedErr:              tc.implErr,
					wantedKeyVersion:       tc.keyVersion,
					wantedcryptoSignerOpts: tc.cryptoSignerOpts,
					wantedMessage:          tc.message,
					wantedSignature:        tc.implSig,
				})
				if err != nil {
					t.Fatal(err)
				}
				return testCommand{
					outputFunc: func() ([]byte, error) {
						return respBuffer.Bytes(), err
					},
					err: err,
				}
			}
			testPluginClient := newPluginClient(
				context.TODO(),
				"sigstore-kms-test",
				&common.InitOptions{},
				makeCommandFunc,
			)
			opts := []signature.SignOption{
				options.WithKeyVersion(tc.keyVersion),
				options.WithCryptoSignerOpts(tc.cryptoSignerOpts),
			}
			signature, err := testPluginClient.SignMessage(bytes.NewReader(tc.message), opts...)
			if errorDiff := cmp.Diff(tc.err, err, cmpopts.EquateErrors()); errorDiff != "" {
				t.Errorf("unexpected error (-want +got):\n%s", errorDiff)
			}
			if diff := cmp.Diff(tc.implSig, signature); diff != "" {
				t.Errorf("signature mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
