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

// Package handler implements helper functions for plugins written in go.
package handler

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
)

// GetPluginArgs parses the PluginArgs from the os args.
func GetPluginArgs(osArgs []string) (*common.PluginArgs, error) {
	argsStr := osArgs[2]
	var args common.PluginArgs
	if err := json.Unmarshal([]byte(argsStr), &args); err != nil {
		return nil, err
	}
	return &args, nil
}

// WriteResponse writes JSON-serialized PluginResp to the outoput.
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
func Dispatch(stdout io.Writer, stdin io.Reader, pluginArgs *common.PluginArgs, impl kms.SignerVerifier) (*common.PluginResp, error) {
	var resp common.PluginResp
	var err error
	switch pluginArgs.MethodName {
	case common.DefaultAlgorithmMethodName:
		resp.DefaultAlgorithm, err = DefaultAlgorithm(stdin, pluginArgs.DefaultAlgorithm, impl)
	case common.CreateKeyMethodName:
		resp.CreateKey, err = CreateKey(stdin, pluginArgs.CreateKey, impl)
	// TODO: Additonal methods to be implemented
	default:
		err = fmt.Errorf("unsupported method: %s", pluginArgs.MethodName)
	}
	if err != nil {
		resp.ErrorMessage = err.Error()
	}
	WriteResponse(stdout, &resp)
	return &resp, err
}
