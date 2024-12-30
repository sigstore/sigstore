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

// Package handler implements helper functions for plugins written in go.
package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
)

var (
	ErrorPluginArgsParse   = errors.New("error parsing plign args")
	ErrorUnsupportedMethod = errors.New("unsupported methodArgs")
)

// GetPluginArgs parses the PluginArgs from the os args.
func GetPluginArgs(osArgs []string) (*common.PluginArgs, error) {
	if len(osArgs) < 3 {
		return nil, fmt.Errorf("%w: expected at least 3 args, got %d", ErrorPluginArgsParse, len(osArgs))
	}
	argsStr := osArgs[2]
	var args common.PluginArgs
	if err := json.Unmarshal([]byte(argsStr), &args); err != nil {
		return nil, err
	}
	return &args, nil
}

// WriteResponse writes JSON-serialized PluginResp to the output.
func WriteResponse(stdout io.Writer, resp *common.PluginResp) error {
	enc, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	fmt.Fprint(stdout, string(enc))
	return nil
}

// WriteErrorResponse writes a response with only an error message to the output.
func WriteErrorResponse(stdout io.Writer, err error) error {
	resp := &common.PluginResp{
		ErrorMessage: err.Error(),
	}
	return WriteResponse(stdout, resp)
}

// Dispatch routes to handler functions based on the PluginArgs.
// If there is an error to be returned, it will also call WriteResponse with the error.
func Dispatch(stdout io.Writer, stdin io.Reader, pluginArgs *common.PluginArgs, impl kms.SignerVerifier) (*common.PluginResp, error) {
	var resp common.PluginResp
	var err error
	switch pluginArgs.MethodName {
	case common.DefaultAlgorithmMethodName:
		resp.DefaultAlgorithm, err = DefaultAlgorithm(stdin, pluginArgs.DefaultAlgorithm, impl)
	case common.CreateKeyMethodName:
		resp.CreateKey, err = CreateKey(stdin, pluginArgs.CreateKey, impl)
	case common.SignMessageMethodName:
		resp.SignMessage, err = SignMessage(stdin, pluginArgs.SignMessage, impl)
	// TODO: Additonal methods to be implemented
	default:
		err = fmt.Errorf("%w: %s", ErrorUnsupportedMethod, pluginArgs.MethodName)
	}
	if err != nil {
		resp.ErrorMessage = err.Error()
	}
	WriteResponse(stdout, &resp)
	return &resp, err
}
