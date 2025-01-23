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

// Package common defines the JSON schema for plugin arguments and return values.
package common

import (
	"crypto"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

var (
	testContextDeadline    = time.Date(2025, 4, 1, 2, 47, 0, 0, time.UTC)
	testKeyResourceID      = "testkms://testkey"
	testHashFunc           = crypto.BLAKE2b_256
	testDigest             = []byte("anyDigest")
	testKeyVersion         = "my-key-version"
	testRemoteVerification = true
)

// TestPluginArgsJSON ensures that the JSON serialization of PluginArgs is the expected form.
func TestPluginArgsJSON(t *testing.T) {
	testPluginArgs := &PluginArgs{
		InitOptions: &InitOptions{
			CtxDeadline:     &testContextDeadline,
			ProtocolVersion: ProtocolVersion,
			KeyResourceID:   testKeyResourceID,
			HashFunc:        testHashFunc,
		},
		MethodArgs: &MethodArgs{
			MethodName:       "anyMethod",
			DefaultAlgorithm: &DefaultAlgorithmArgs{},
			CreateKey: &CreateKeyArgs{
				CtxDeadline: &testContextDeadline,
				Algorithm:   "anyAlgorithm",
			},
			SignMessage: &SignMessageArgs{
				SignOptions: &SignOptions{
					RPCMessageOptions: &RPCMessageOptions{
						RPCOptions: &RPCOptions{
							CtxDeadline:        &testContextDeadline,
							KeyVersion:         &testKeyVersion,
							RemoteVerification: &testRemoteVerification,
						},
						MessageOptions: &MessageOptions{
							Digest:   &testDigest,
							HashFunc: &testHashFunc,
						},
					},
				},
			},
		},
	}
	gotJSONBytes, err := json.MarshalIndent(testPluginArgs, "", "	")
	if err != nil {
		t.Fatalf("serializing PluginArgs: %v", err)
		return
	}
	// split to string slices so we can get a line-by-line diff.
	gotJSONLines := strings.Split(string(gotJSONBytes), "\n")
	wantedJSONLines := strings.Split(`{
	"initOptions": {
		"ctxDeadline": "2025-04-01T02:47:00Z",
		"protocolVersion": "1",
		"keyResourceID": "testkms://testkey",
		"hashFunc": 17
	},
	"methodName": "anyMethod",
	"defaultAlgorithm": {},
	"createKey": {
		"ctxDeadline": "2025-04-01T02:47:00Z",
		"algorithm": "anyAlgorithm"
	},
	"signMessage": {
		"signOptions": {
			"ctxDeadline": "2025-04-01T02:47:00Z",
			"keyVersion": "my-key-version",
			"remoteVerification": true,
			"digest": "YW55RGlnZXN0",
			"hashFunc": 17
		}
	}
}`, "\n")
	if diff := cmp.Diff(wantedJSONLines, gotJSONLines); diff != "" {
		t.Errorf("unexpected JSON (-want +got): \n%s", diff)
	}
}

// TestPluginRespJSON ensures that the JSON serialization of PluginResp is the expected form.

func TestPluginRespJSON(t *testing.T) {
	testPluginResp := &PluginResp{
		ErrorMessage:     "any error message",
		DefaultAlgorithm: &DefaultAlgorithmResp{DefaultAlgorithm: "any-algo"},
		CreateKey:        &CreateKeyResp{PublicKeyPEM: []byte("mypem")},
		SignMessage:      &SignMessageResp{Signature: []byte("any-signature")},
	}
	gotJSONBytes, err := json.MarshalIndent(testPluginResp, "", "	")
	if err != nil {
		t.Fatalf("serializing PluginArgs: %v", err)
		return
	}
	// split to string slices so we can get a line-by-line diff.
	gotJSONLines := strings.Split(string(gotJSONBytes), "\n")
	wantedJSONLines := strings.Split(`{
	"errorMessage": "any error message",
	"defaultAlgorithm": {
		"defaultAlgorithm": "any-algo"
	},
	"createKey": {
		"publicKeyPEM": "bXlwZW0="
	},
	"signMessage": {
		"signature": "YW55LXNpZ25hdHVyZQ=="
	}
}`, "\n")
	if diff := cmp.Diff(wantedJSONLines, gotJSONLines); diff != "" {
		t.Errorf("unexpected JSON (-want +got): \n%s", diff)
	}
}
