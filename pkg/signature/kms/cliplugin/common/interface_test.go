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

// Package common defines the JSON schema for plugin arguments and return values.

//go:build !signer_program
// +build !signer_program

package common

import (
	"crypto"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// TestPluginArgs ensures that the values of the PluginArgs survive json encoding and decoding.
func TestPluginArgs(t *testing.T) {
	t.Parallel()

	testCtxDeadline := time.Date(2025, 4, 1, 2, 47, 0, 0, time.UTC)
	testPluginArgs := &PluginArgs{
		InitOptions: &InitOptions{
			ProtocolVersion: ProtocolVersion,
			KeyResourceID:   "testkms://testkey",
			HashFunc:        crypto.BLAKE2b_256,
		},
		MethodArgs: &MethodArgs{
			MethodName:       "anyMethod",
			DefaultAlgorithm: &DefaultAlgorithmArgs{},
			CreateKey: &CreateKeyArgs{
				CtxDeadline: &testCtxDeadline,
				Algorithm:   "anyAlgorithm",
			},
		},
	}

	encdodedPluginArgs, err := json.Marshal(testPluginArgs)
	if err != nil {
		t.Errorf("encoding pluginArgs: %v", err)
	}

	var decodedPluginArgs PluginArgs
	if err := json.Unmarshal(encdodedPluginArgs, &decodedPluginArgs); err != nil {
		t.Errorf("decoding pluginArgs error: %v", err)
	}

	if diff := cmp.Diff(testPluginArgs, &decodedPluginArgs); diff != "" {
		t.Errorf("unexpected resp (-want +got):\n%s", diff)
	}
}

// TestPluginResp ensures that the values of the PluginResp survive json encoding and decoding.
func TestPluginResp(t *testing.T) {
	t.Parallel()

	testPluginResp := &PluginResp{
		ErrorMessage:     "any error message",
		DefaultAlgorithm: &DefaultAlgorithmResp{DefaultAlgorithm: "anyDefaultAlgorithm"},
		CreateKey:        &CreateKeyResp{PublicKeyPEM: []byte("anyPublicKeyPEM")},
	}

	encdodedPluginResp, err := json.Marshal(testPluginResp)
	if err != nil {
		t.Errorf("encoding pluginArgs: %v", err)
	}

	var decodedPluginResp PluginResp
	if err := json.Unmarshal(encdodedPluginResp, &decodedPluginResp); err != nil {
		t.Errorf("decoding pluginResp error: %v", err)
	}

	if diff := cmp.Diff(testPluginResp, &decodedPluginResp); diff != "" {
		t.Errorf("unexpected resp (-want +got):\n%s", diff)
	}
}
