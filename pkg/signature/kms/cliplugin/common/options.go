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

// SignOptions contains the values for signature.SignOption.
type SignOptions struct {
	*RPCOptions
	*MessageOptions
}

// RPCOptions contains the values for signature.RPCOption.
// We do not use RPCOptions.RPCAuth to avoid sending secrets over CLI to the plugin program.
// The pluign program should instead read secrets with env variables.
type RPCOptions struct {
	CtxDeadline        *time.Time `json:"ctxDeadline,omitempty"`
	KeyVersion         *string    `json:"keyVersion,omitempty"`
	RemoteVerification *bool      `json:"remoteVerification,omitempty"`
}

// MessageOptions contains the values for signature.MessageOption.
type MessageOptions struct {
	Digest   *[]byte      `json:"digest,omitempty"`
	HashFunc *crypto.Hash `json:"hashFunc,omitempty"`
}
