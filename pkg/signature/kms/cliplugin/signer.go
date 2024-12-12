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

// Package cliplugin implements the plugin functionality.
package cliplugin

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
)

var (
	ErrorExecutingPlugin    = errors.New("error executing plugin program")
	ErrorResponseParseError = errors.New("parsing plugin response")
	ErrorPluginReturnError  = errors.New("plugin returned error")
	ErrorParsingPluginName  = errors.New("parsing plugin name")
	ErrorUnsupportedMethod  = errors.New("unsupported methodArgs")
)

// PluginClient implements kms.SignerVerifier with calls to our plugin program.
type PluginClient struct {
	kms.SignerVerifier
	executable  string
	initOptions common.InitOptions
}

// newPluginClient creates a new PluginClient.
func newPluginClient(executable string, initOptions *common.InitOptions) *PluginClient {
	pluginClient := &PluginClient{
		executable:  executable,
		initOptions: *initOptions,
	}
	return pluginClient
}

// invokePlugin invokes the plugin program and parses its response.
func (c PluginClient) invokePlugin(ctx context.Context, stdin io.Reader, methodArgs *common.MethodArgs) (*common.PluginResp, error) {
	pluginArgs := &common.PluginArgs{
		InitOptions: &c.initOptions,
		MethodArgs:  methodArgs,
	}
	argsEnc, err := json.Marshal(pluginArgs)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, c.executable, common.ProtocolVersion, string(argsEnc))
	cmd.Stdin = stdin
	cmd.Stderr = os.Stderr
	// We won't look at the program's non-zero exit code, but we will respect any other
	// error, and cases when exec.ExitError.ExitCode() is 0 or -1:
	//   * (0) the program finished successfuly or
	//   * (-1) there was some other problem not due to the program itself.
	// The only debugging is to either parse the the returned error in stdout,
	// or for the user to examine the sterr logs.
	// See https://pkg.go.dev/os#ProcessState.ExitCode.
	stdout, err := cmd.Output()
	var exitError exec.ExitError
	if err != nil && (!errors.As(err, &exitError) || exitError.ExitCode() < 1) {
		return nil, fmt.Errorf("%w: %w", ErrorExecutingPlugin, err)
	}
	var resp common.PluginResp
	if unmarshallErr := json.Unmarshal(stdout, &resp); unmarshallErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrorResponseParseError, unmarshallErr)
	}
	if resp.ErrorMessage != "" {
		return nil, fmt.Errorf("%w: %s", ErrorPluginReturnError, resp.ErrorMessage)
	}
	return &resp, nil
}

// TODO: Additonal methods to be implemented

func (c PluginClient) DefaultAlgorithm() string {
	args := &common.MethodArgs{
		MethodName:       common.DefaultAlgorithmMethodName,
		DefaultAlgorithm: &common.DefaultAlgorithmArgs{},
	}
	resp, err := c.invokePlugin(context.TODO(), nil, args)
	if err != nil {
		log.Fatal(err)
	}
	return resp.DefaultAlgorithm.DefaultAlgorithm
}

func (c PluginClient) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	args := &common.MethodArgs{
		MethodName: common.CreateKeyMethodName,
		CreateKey: &common.CreateKeyArgs{
			Algorithm: algorithm,
		},
	}
	resp, err := c.invokePlugin(context.TODO(), nil, args)
	if err != nil {
		return nil, err
	}
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey(resp.CreateKey.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}
