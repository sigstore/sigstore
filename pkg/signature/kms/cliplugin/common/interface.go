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

// Package common defines the JSON schema for plugin arguments and return values.
package common

import (
	"crypto"
)

const (
	// ProtocolVersion is the version of the schema and communication protocol for the plugin system.
	// Breaking changes to the PluginClient and this schema necessarily mean major version bumps of
	// this ProtocolVersion and the sigstore version.
	// Plugin authors may choose to be backwards compatible with older versions.
	ProtocolVersion               = "1"
	SupportedAlgorithmsMethodName = "supportedAlgorithms"
	SignMessageMethodName         = "signMessage"
	// TODO: Additonal methods to be implemented
)

// PluginArgs contains all the initialization and method arguments to be sent to the plugin as a CLI argument.
type PluginArgs struct {
	*MethodArgs
	InitOptions *InitOptions `json:"initOptions"`
}

// InitOptions contains the initial arguments when calling cliplugin.LoadSignerVerifier().
type InitOptions struct {
	ProtocolVersion string      `json:"protocolVersion"`
	KeyResourceID   string      `json:"keyResourceID"`
	HashFunc        crypto.Hash `json:"hashFunc"`
	// TODO: extracted values from signature.RPCOption from LoadSignerVerifier().
}

// MethodArgs contains the method arguments. MethodName must be specified,
// while any one of the other fields describing method arguments must also be specified.
type MethodArgs struct {
	// MethodName specifies which method is intended to be called.
	MethodName          string                   `json:"methodName"`
	SupportedAlgorithms *SupportedAlgorithmsArgs `json:"supportedAlgorithms,omitempty"`
	SignMessage         *SignMessageArgs         `json:"signMessage,omitempty"`
	// TODO: Additonal methods to be implemented
}

// PluginResp contains the serialized plugin method return values.
type PluginResp struct {
	ErrorMessage        string                   `json:"errorMessage,omitempty"`
	SupportedAlgorithms *SupportedAlgorithmsResp `json:"supportedAlgorithms,omitempty"`
	SignMessage         *SignMessageResp         `json:"signMessage,omitempty"`
	// TODO: Additonal methods to be implemented
}

// SupportedAlgorithmsArgs containts the values for arguments of SupportedAlgorithms().
type SupportedAlgorithmsArgs struct {
}

// SupportedAlgorithmsResp containts the values for returns values of SupportedAlgorithms().
type SupportedAlgorithmsResp struct {
	SupportedAlgorithms []string
}

// SignMessageArgs containts the values for arguments of SignMessage().
type SignMessageArgs struct {
	// TODO: use extracted values from signature.RPCOption, and signature.SignOption.
}

// SignMessageResp containts the values for returns values of SignMessage().
type SignMessageResp struct {
	Signature []byte `json:"signature"`
}
