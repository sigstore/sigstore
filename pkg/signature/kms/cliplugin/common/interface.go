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
package common

import (
	"crypto"
	"time"
)

const (
	// ProtocolVersion is the version of the schema and communication protocol for the plugin system.
	// Breaking changes to the PluginClient and this schema necessarily mean major version bumps of
	// this ProtocolVersion and the sigstore version.
	// Plugin authors may choose to be backwards compatible with older versions.
	ProtocolVersion            = "1"
	DefaultAlgorithmMethodName = "defaultAlgorithm"
	CreateKeyMethodName        = "createKey"
	SignMessageMethodName      = "signMessage"
	// TODO: Additonal methods to be implemented
)

// PluginArgs contains all the initialization and method arguments to be sent to the plugin as a CLI argument.
type PluginArgs struct {
	InitOptions *InitOptions `json:"initOptions"`
	*MethodArgs
}

// InitOptions contains the initial arguments when calling cliplugin.LoadSignerVerifier().
type InitOptions struct {
	// CtxDeadline serializes to RFC 3339. See https://pkg.go.dev/time@go1.23.5#Time.MarshalJSON. e.g, 2025-04-01T02:47:00Z.
	CtxDeadline     *time.Time `json:"ctxDeadline,omitempty"`
	ProtocolVersion string     `json:"protocolVersion"`
	KeyResourceID   string     `json:"keyResourceID"`
	// HashFunc will serialize to ints according to https://pkg.go.dev/crypto@go1.23.5#Hash. e.g., crypto.SHA256 serializes to 5.
	HashFunc crypto.Hash `json:"hashFunc"`
	// TODO: extracted values from signature.RPCOption from LoadSignerVerifier().
}

// MethodArgs contains the method arguments. MethodName must be specified,
// while any one of the other fields describing method arguments must also be specified.
// Arguments that are io.Readers, like `message` in `SignMessage()` will be sent over stdin.
type MethodArgs struct {
	// MethodName specifies which method is intended to be called.
	MethodName       string                `json:"methodName"`
	DefaultAlgorithm *DefaultAlgorithmArgs `json:"defaultAlgorithm,omitempty"`
	CreateKey        *CreateKeyArgs        `json:"createKey,omitempty"`
	SignMessage      *SignMessageArgs      `json:"signMessage,omitempty"`
	// TODO: Additonal methods to be implemented
}

// PluginResp contains the serialized plugin method return values.
type PluginResp struct {
	ErrorMessage     string                `json:"errorMessage,omitempty"`
	DefaultAlgorithm *DefaultAlgorithmResp `json:"defaultAlgorithm,omitempty"`
	CreateKey        *CreateKeyResp        `json:"createKey,omitempty"`
	SignMessage      *SignMessageResp      `json:"signMessage,omitempty"`
	// TODO: Additonal methods to be implemented
}

// DefaultAlgorithmArgs contains the serialized arguments for `DefaultAlgorithm()`.
type DefaultAlgorithmArgs struct {
}

// DefaultAlgorithmResp contains the serialized response for `DefaultAlgorithm()`.
type DefaultAlgorithmResp struct {
	DefaultAlgorithm string `json:"defaultAlgorithm"`
}

// CreateKeyArgs contains the serialized arguments for `CreateKeyArgs()`.
type CreateKeyArgs struct {
	// CtxDeadline serializes to RFC 3339. See https://pkg.go.dev/time@go1.23.5#Time.MarshalJSON. e.g, 2025-04-01T02:47:00Z.
	CtxDeadline *time.Time `json:"ctxDeadline,omitempty"`
	Algorithm   string     `json:"algorithm"`
}

// CreateKeyResp contains the serialized response for `CreateKeyResp()`.
type CreateKeyResp struct {
	// PublicKeyPEM is a base64 encoding of the Public Key PEM bytes. e.g, []byte("mypem") serializes to "bXlwZW0=".
	PublicKeyPEM []byte `json:"publicKeyPEM"`
}

// SignMessageArgs contains the serialized arguments for `SignMessage()`.
type SignMessageArgs struct {
	SignOptions *SignOptions `json:"signOptions"`
}

// SignMessageResp contains the serialized response for `SignMessage()`.
type SignMessageResp struct {
	// Signature is a base64 encoding of the signature bytes. e.g, []byte("any-signature") serializes to "W55LXNpZ25hdHVyZQ==".
	Signature []byte `json:"signature"`
}
