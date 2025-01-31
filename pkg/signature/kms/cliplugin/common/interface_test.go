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
	t.Parallel()

	testInitOptions := &InitOptions{
		CtxDeadline:     &testContextDeadline,
		ProtocolVersion: ProtocolVersion,
		KeyResourceID:   testKeyResourceID,
		HashFunc:        testHashFunc,
		RPCOptions: &RPCOptions{
			CtxDeadline:        &testContextDeadline,
			KeyVersion:         &testKeyVersion,
			RemoteVerification: &testRemoteVerification,
		},
	}

	tests := []struct {
		name       string
		pluginArgs *PluginArgs
		want       string
	}{
		{
			name: "defaultAlgorithm",
			pluginArgs: &PluginArgs{
				InitOptions: testInitOptions,
				MethodArgs: &MethodArgs{
					MethodName:       DefaultAlgorithmMethodName,
					DefaultAlgorithm: &DefaultAlgorithmArgs{},
				},
			},
			want: `{
	"initOptions": {
		"ctxDeadline": "2025-04-01T02:47:00Z",
		"protocolVersion": "1",
		"keyResourceID": "testkms://testkey",
		"hashFunc": 17,
		"rpcOptions": {
			"ctxDeadline": "2025-04-01T02:47:00Z",
			"keyVersion": "my-key-version",
			"remoteVerification": true
		}
	},
	"methodName": "defaultAlgorithm",
	"defaultAlgorithm": {}
}`,
		},
		{
			name: "supportedAlgorithms",
			pluginArgs: &PluginArgs{
				InitOptions: testInitOptions,
				MethodArgs: &MethodArgs{
					MethodName:          SupportedAlgorithmsMethodName,
					SupportedAlgorithms: &SupportedAlgorithmsArgs{},
				},
			},
			want: `{
	"initOptions": {
		"ctxDeadline": "2025-04-01T02:47:00Z",
		"protocolVersion": "1",
		"keyResourceID": "testkms://testkey",
		"hashFunc": 17,
		"rpcOptions": {
			"ctxDeadline": "2025-04-01T02:47:00Z",
			"keyVersion": "my-key-version",
			"remoteVerification": true
		}
	},
	"methodName": "supportedAlgorithms",
	"supportedAlgorithms": {}
}`,
		},
		{
			name: "createKey",
			pluginArgs: &PluginArgs{
				InitOptions: testInitOptions,
				MethodArgs: &MethodArgs{
					MethodName: CreateKeyMethodName,
					CreateKey: &CreateKeyArgs{
						CtxDeadline: &testContextDeadline,
						Algorithm:   testAlgorithm,
					},
				},
			},
			want: `{
	"initOptions": {
		"ctxDeadline": "2025-04-01T02:47:00Z",
		"protocolVersion": "1",
		"keyResourceID": "testkms://testkey",
		"hashFunc": 17,
		"rpcOptions": {
			"ctxDeadline": "2025-04-01T02:47:00Z",
			"keyVersion": "my-key-version",
			"remoteVerification": true
		}
	},
	"methodName": "createKey",
	"createKey": {
		"ctxDeadline": "2025-04-01T02:47:00Z",
		"algorithm": "anyAlgorithm"
	}
}`,
		},
		{
			name: "publicKey",
			pluginArgs: &PluginArgs{
				InitOptions: testInitOptions,
				MethodArgs: &MethodArgs{
					MethodName: PublicKeyMethodName,
					PublicKey: &PublicKeyArgs{
						PublicKeyOptions: &PublicKeyOptions{
							RPCOptions: RPCOptions{
								CtxDeadline:        &testContextDeadline,
								KeyVersion:         &testKeyVersion,
								RemoteVerification: &testRemoteVerification,
							},
						},
					},
				},
			},
			want: `{
	"initOptions": {
		"ctxDeadline": "2025-04-01T02:47:00Z",
		"protocolVersion": "1",
		"keyResourceID": "testkms://testkey",
		"hashFunc": 17,
		"rpcOptions": {
			"ctxDeadline": "2025-04-01T02:47:00Z",
			"keyVersion": "my-key-version",
			"remoteVerification": true
		}
	},
	"methodName": "publicKey",
	"publicKey": {
		"publicKeyOptions": {
			"rpcOptions": {
				"ctxDeadline": "2025-04-01T02:47:00Z",
				"keyVersion": "my-key-version",
				"remoteVerification": true
			}
		}
	}
}`,
		},
		{
			name: "signMessage",
			pluginArgs: &PluginArgs{
				InitOptions: testInitOptions,
				MethodArgs: &MethodArgs{
					MethodName: SignMessageMethodName,
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
				},
			},
			want: `{
	"initOptions": {
		"ctxDeadline": "2025-04-01T02:47:00Z",
		"protocolVersion": "1",
		"keyResourceID": "testkms://testkey",
		"hashFunc": 17,
		"rpcOptions": {
			"ctxDeadline": "2025-04-01T02:47:00Z",
			"keyVersion": "my-key-version",
			"remoteVerification": true
		}
	},
	"methodName": "signMessage",
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
	}
}`,
		},
		{
			name: "verifySignature",
			pluginArgs: &PluginArgs{
				InitOptions: testInitOptions,
				MethodArgs: &MethodArgs{
					MethodName: VerifySignatureMethodName,
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
			},
			want: `{
	"initOptions": {
		"ctxDeadline": "2025-04-01T02:47:00Z",
		"protocolVersion": "1",
		"keyResourceID": "testkms://testkey",
		"hashFunc": 17,
		"rpcOptions": {
			"ctxDeadline": "2025-04-01T02:47:00Z",
			"keyVersion": "my-key-version",
			"remoteVerification": true
		}
	},
	"methodName": "verifySignature",
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
}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotJSONBytes, err := json.MarshalIndent(tc.pluginArgs, "", "	")
			if err != nil {
				t.Fatalf("serializing PluginArgs: %v", err)
				return
			}
			gotJSONLines := strings.Split(string(gotJSONBytes), "\n")
			wantedJSONLines := strings.Split(tc.want, "\n")
			if diff := cmp.Diff(wantedJSONLines, gotJSONLines); diff != "" {
				t.Errorf("unexpected JSON (-want +got): \n%s", diff)
			}
		})
	}
}

// TestPluginRespJSON ensures that the JSON serialization of PluginResp is the expected form.

func TestPluginRespJSON(t *testing.T) {
	t.Parallel()

	// some methods don't return an error.
	testErrorMessage := "possibly empty error message"

	tests := []struct {
		name       string
		pluginResp *PluginResp
		want       string
	}{
		{
			name: "defaultAlgorithm",
			pluginResp: &PluginResp{
				DefaultAlgorithm: &DefaultAlgorithmResp{
					DefaultAlgorithm: testAlgorithm,
				},
			},
			want: `{
	"defaultAlgorithm": {
		"defaultAlgorithm": "anyAlgorithm"
	}
}`,
		},
		{
			name: "supportedAlgorithms",
			pluginResp: &PluginResp{
				SupportedAlgorithms: &SupportedAlgorithmsResp{
					SupportedAlgorithms: []string{testAlgorithm, "anotherAlgorithm"},
				},
			},
			want: `{
	"supportedAlgorithms": {
		"supportedAlgorithms": [
			"anyAlgorithm",
			"anotherAlgorithm"
		]
	}
}`,
		},
		{
			name: "createKey",
			pluginResp: &PluginResp{
				ErrorMessage: testErrorMessage,
				CreateKey: &CreateKeyResp{
					PublicKeyPEM: testPEM,
				},
			},
			want: `{
	"errorMessage": "possibly empty error message",
	"createKey": {
		"publicKeyPEM": "bXlwZW0="
	}
}`,
		},
		{
			name: "publicKey",
			pluginResp: &PluginResp{
				ErrorMessage: testErrorMessage,
				PublicKey: &PublicKeyResp{
					PublicKeyPEM: testPEM,
				},
			},
			want: `{
	"errorMessage": "possibly empty error message",
	"publicKey": {
		"publicKeyPEM": "bXlwZW0="
	}
}`,
		},
		{
			name: "signMessage",
			pluginResp: &PluginResp{
				ErrorMessage: testErrorMessage,
				SignMessage: &SignMessageResp{
					Signature: testSignature,
				},
			},
			want: `{
	"errorMessage": "possibly empty error message",
	"signMessage": {
		"signature": "YW55LXNpZ25hdHVyZQ=="
	}
}`,
		},
		{
			name: "verifySignature",
			pluginResp: &PluginResp{
				ErrorMessage:    testErrorMessage,
				VerifySignature: &VerifySignatureResp{},
			},
			want: `{
	"errorMessage": "possibly empty error message",
	"verifySignature": {}
}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotJSONBytes, err := json.MarshalIndent(tc.pluginResp, "", "	")
			if err != nil {
				t.Fatalf("serializing PluginArgs: %v", err)
				return
			}
			gotJSONLines := strings.Split(string(gotJSONBytes), "\n")
			wantedJSONLines := strings.Split(tc.want, "\n")
			if diff := cmp.Diff(wantedJSONLines, gotJSONLines); diff != "" {
				t.Errorf("unexpected JSON (-want +got): \n%s", diff)
			}
		})
	}
}
