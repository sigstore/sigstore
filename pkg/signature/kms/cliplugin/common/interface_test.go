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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

var (
	testContextDeadline    = time.Date(2025, 4, 1, 2, 47, 0, 0, time.UTC)
	testAlgorithm          = "anyAlgorithm"
	testPEM                = []byte("mypem")
	testKeyResourceID      = "testkms://testkey"
	testHashFunc           = crypto.BLAKE2b_256
	testDigest             = []byte("anyDigest")
	testKeyVersion         = "my-key-version"
	testRemoteVerification = true
	testSignature          = []byte("any-signature")
)

// TestPluginArgsJSON ensures that the JSON serialization of PluginArgs is the expected form.
func TestPluginArgsJSON(t *testing.T) {
	// Although a normal invocation would only have a single method's arguments filled,
	// we fill them here for simpler testing.
	testPluginArgs := &PluginArgs{
		InitOptions: &InitOptions{
			CtxDeadline:     &testContextDeadline,
			ProtocolVersion: ProtocolVersion,
			KeyResourceID:   testKeyResourceID,
			HashFunc:        testHashFunc,
			RPCOptions: &RPCOptions{
				CtxDeadline:        &testContextDeadline,
				KeyVersion:         &testKeyVersion,
				RemoteVerification: &testRemoteVerification,
			},
		},
		MethodArgs: &MethodArgs{
			MethodName:          "anyMethod",
			DefaultAlgorithm:    &DefaultAlgorithmArgs{},
			SupportedAlgorithms: &SupportedAlgorithmsArgs{},
			CreateKey: &CreateKeyArgs{
				CtxDeadline: &testContextDeadline,
				Algorithm:   testAlgorithm,
			},
			PublicKey: &PublicKeyArgs{
				PublicKeyOptions: &PublicKeyOptions{
					RPCOptions: RPCOptions{
						CtxDeadline:        &testContextDeadline,
						KeyVersion:         &testKeyVersion,
						RemoteVerification: &testRemoteVerification,
					},
				},
			},
			SignMessage: &SignMessageArgs{
				SignOptions: &SignOptions{
					RPCOptions: RPCOptions{
						CtxDeadline:        &testContextDeadline,
						KeyVersion:         &testKeyVersion,
						RemoteVerification: &testRemoteVerification,
					},
					MessageOptions: MessageOptions{
						Digest:   &testDigest,
						HashFunc: &testHashFunc,
					},
				},
			},
			VerifySignature: &VerifySignatureArgs{
				Signature: testSignature,
				VerifyOptions: &VerifyOptions{
					RPCOptions: RPCOptions{
						CtxDeadline:        &testContextDeadline,
						KeyVersion:         &testKeyVersion,
						RemoteVerification: &testRemoteVerification,
					},
					MessageOptions: MessageOptions{
						Digest:   &testDigest,
						HashFunc: &testHashFunc,
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
		"protocolVersion": "v1.0.0",
		"keyResourceID": "testkms://testkey",
		"hashFunc": 17,
		"rpcOptions": {
			"ctxDeadline": "2025-04-01T02:47:00Z",
			"keyVersion": "my-key-version",
			"remoteVerification": true
		}
	},
	"methodName": "anyMethod",
	"defaultAlgorithm": {},
	"supportedAlgorithms": {},
	"createKey": {
		"ctxDeadline": "2025-04-01T02:47:00Z",
		"algorithm": "anyAlgorithm"
	},
	"publicKey": {
		"publicKeyOptions": {
			"rpcOptions": {
				"ctxDeadline": "2025-04-01T02:47:00Z",
				"keyVersion": "my-key-version",
				"remoteVerification": true
			}
		}
	},
	"signMessage": {
		"signOptions": {
			"rpcOptions": {
				"ctxDeadline": "2025-04-01T02:47:00Z",
				"keyVersion": "my-key-version",
				"remoteVerification": true
			},
			"messageOptions": {
				"digest": "YW55RGlnZXN0",
				"hashFunc": 17
			}
		}
	},
	"verifySignature": {
		"signature": "YW55LXNpZ25hdHVyZQ==",
		"verifyOptions": {
			"rpcOptions": {
				"ctxDeadline": "2025-04-01T02:47:00Z",
				"keyVersion": "my-key-version",
				"remoteVerification": true
			},
			"messageOptions": {
				"digest": "YW55RGlnZXN0",
				"hashFunc": 17
			}
		}
	}
}`, "\n")
	if diff := cmp.Diff(wantedJSONLines, gotJSONLines); diff != "" {
		t.Errorf("unexpected JSON (-want +got): \n%s", diff)
	}
}

// TestPluginRespJSON ensures that the JSON serialization of PluginResp is the expected form.

func TestPluginRespJSON(t *testing.T) {
	// Although a normal invocation would only have a single method's response filled,
	// we fill them here for simpler testing.
	testPluginResp := &PluginResp{
		ErrorMessage:     "any error message",
		DefaultAlgorithm: &DefaultAlgorithmResp{DefaultAlgorithm: testAlgorithm},
		SupportedAlgorithms: &SupportedAlgorithmsResp{
			SupportedAlgorithms: []string{testAlgorithm, "anotherAlgorithm"},
		},
		CreateKey:       &CreateKeyResp{PublicKeyPEM: testPEM},
		PublicKey:       &PublicKeyResp{PublicKeyPEM: testPEM},
		SignMessage:     &SignMessageResp{Signature: testSignature},
		VerifySignature: &VerifySignatureResp{},
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
		"defaultAlgorithm": "anyAlgorithm"
	},
	"supportedAlgorithms": {
		"supportedAlgorithms": [
			"anyAlgorithm",
			"anotherAlgorithm"
		]
	},
	"createKey": {
		"publicKeyPEM": "bXlwZW0="
	},
	"publicKey": {
		"publicKeyPEM": "bXlwZW0="
	},
	"signMessage": {
		"signature": "YW55LXNpZ25hdHVyZQ=="
	},
	"verifySignature": {}
}`, "\n")
	if diff := cmp.Diff(wantedJSONLines, gotJSONLines); diff != "" {
		t.Errorf("unexpected JSON (-want +got): \n%s", diff)
	}
}

// TestHashFuncJSON ensures that some of our well-known hashfuncs consistently encode to known int values.
// just in case the order of thoe iota changes in the future. If this test fails, then we likely need a new protocol version.
// See iota values at https://pkg.go.dev/crypto@go1.23.5#Hash.
func TestHashFuncJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		hash    crypto.Hash
		wantInt int
	}{
		// all know  crypto.HASH
		{
			crypto.MD4,
			1,
		},
		{
			crypto.MD5,
			2,
		},
		{
			crypto.SHA1,
			3,
		},
		{
			crypto.SHA224,
			4,
		},
		{
			crypto.SHA256,
			5,
		},
		{
			crypto.SHA384,
			6,
		},
		{
			crypto.SHA512,
			7,
		},
		{
			crypto.MD5SHA1,
			8,
		},
		{
			crypto.RIPEMD160,
			9,
		},
		{
			crypto.SHA3_224,
			10,
		},
		{
			crypto.SHA3_256,
			11,
		},
		{
			crypto.SHA3_384,
			12,
		},
		{
			crypto.SHA3_512,
			13,
		},
		{
			crypto.SHA512_224,
			14,
		},
		{
			crypto.SHA512_256,
			15,
		},
		{
			crypto.BLAKE2s_256,
			16,
		},
		{
			crypto.BLAKE2b_256,
			17,
		},
		{
			crypto.BLAKE2b_384,
			18,
		},
		{
			crypto.BLAKE2b_512,
			19,
		},
	}
	for _, tc := range tests {
		t.Run(tc.hash.String(), func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(tc.hash)
			if err != nil {
				t.Errorf("marshaling hash %s: %v", tc.hash.String(), err)
			}
			want := []byte(strconv.Itoa(tc.wantInt))
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("unexpected JSON (-want +got): \n%s", diff)
			}
		})
	}
}
