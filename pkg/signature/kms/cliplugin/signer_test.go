package cliplugin

import (
	"bytes"
	"context"
	"crypto"
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
	command
	outputFunc func() ([]byte, error)
	err        error
}

func (c testCommand) Output() ([]byte, error) {
	return c.outputFunc()
}
func Test_invokePlugin(t *testing.T) {
	tests := []struct {
		name                   string
		cmdOutput              string
		resp                   *common.PluginResp
		invokePluginErrType    error
		invokePluginErrContent string
		commandErrType         error
	}{
		{
			name:      "success",
			cmdOutput: `{"supportedAlgorithms":{"supportedAlgorithms":["alg1", "alg2"]}}`,
			resp: &common.PluginResp{
				SupportedAlgorithms: &common.SupportedAlgorithmsResp{
					SupportedAlgorithms: []string{"alg1", "alg2"},
				},
			},
			invokePluginErrType: nil,
		},
		{
			name:      "success: expected stdin",
			cmdOutput: `{"supportedAlgorithms":{"supportedAlgorithms":["alg1", "alg2"]}}`,
			resp: &common.PluginResp{
				SupportedAlgorithms: &common.SupportedAlgorithmsResp{
					SupportedAlgorithms: []string{"alg1", "alg2"},
				},
			},
			invokePluginErrType: nil,
		},
		{
			name:      "success: continue if command exits 1",
			cmdOutput: `{"supportedAlgorithms":{"supportedAlgorithms":["alg1", "alg2"]}}`,
			resp: &common.PluginResp{
				SupportedAlgorithms: &common.SupportedAlgorithmsResp{
					SupportedAlgorithms: []string{"alg1", "alg2"},
				},
			},
			invokePluginErrType: nil,
			commandErrType:      errors.New("command-error"),
		},
		{
			name:                   "error: plugin program error",
			cmdOutput:              `{"errorMessage": "any-error"}`,
			invokePluginErrType:    ErrorPluginReturnError,
			invokePluginErrContent: "any-error",
		},
		{
			name:                "error: empty resp",
			cmdOutput:           "",
			invokePluginErrType: ErrorResponseParseError,
		},
		{
			name:                "error: invalid json resp",
			cmdOutput:           "abc",
			invokePluginErrType: ErrorResponseParseError,
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
				if args[1] != `{"method":"any-method","initOptions":{"protocolVersion":"","keyResourceID":"","hashFunc":0}}` {
					t.Fatalf("unexpected args: %s", args[1])
				}
				return testCommand{
					outputFunc: func() ([]byte, error) {
						return []byte(tc.cmdOutput), tc.commandErrType
					},
					err: tc.commandErrType,
				}
			}
			testPluginClient := newPluginClient(
				context.TODO(),
				"sigstore-kms-test",
				&common.InitOptions{},
				makeCommandFunc,
			)
			resp, err := testPluginClient.invokePlugin(context.TODO(), nil, &common.PluginArgs{
				Method: "any-method",
			})
			if errorDiff := cmp.Diff(tc.invokePluginErrType, err, cmpopts.EquateErrors()); errorDiff != "" {
				t.Errorf("unexpected error (-want +got):\n%s", errorDiff)
			}
			if respDiff := cmp.Diff(tc.resp, resp); respDiff != "" {
				t.Errorf("unexpected resp (-want +got):\n%s", respDiff)
			}
			if err != nil && !strings.Contains(err.Error(), tc.invokePluginErrContent) {
				t.Errorf("error content does not contain expecrted substring (-want +got): \n-%s\n+%s", tc.invokePluginErrContent, err.Error())
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
			cryptoSignerOpts: crypto.SHA256,
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
				if pluginArgs.Method != common.SignMessageMethodName {
					t.Fatalf("unexpected method: %s", pluginArgs.Method)
				}
				if pluginArgs.SignMessage.KeyVersion != "1" {
					t.Fatalf("unexpected key version: %s", pluginArgs.SignMessage.KeyVersion)
				}
				if pluginArgs.SignMessage.HashFunc != crypto.SHA256 {
					t.Fatalf("unexpected hash func: %s", pluginArgs.SignMessage.HashFunc)
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
			signature, err := testPluginClient.SignMessage(bytes.NewReader(tc.message), []signature.SignOption{
				options.WithKeyVersion(tc.keyVersion),
				options.WithCryptoSignerOpts(tc.cryptoSignerOpts),
			}...)
			if errorDiff := cmp.Diff(tc.err, err, cmpopts.EquateErrors()); errorDiff != "" {
				t.Errorf("unexpected error (-want +got):\n%s", errorDiff)
			}
			if diff := cmp.Diff(tc.implSig, signature); diff != "" {
				t.Errorf("signature mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
