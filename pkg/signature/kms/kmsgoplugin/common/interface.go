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

// Package common has common code between sigstore and your plugin.
// using the github.com/hashicorp/go-plugin framework.
package common

import (
	"net/rpc"

	"github.com/hashicorp/go-plugin"
)

// Some of our interface functions don't return an error, but our communication to the plugin may still error,
// so we panic instead of returning the error.

func init() {
	// gob.Register(ecdsa.PublicKey{})
	// gob.Register(elliptic.P256())
}

const (
	DefaultPluginBinaryRelativePath = "./sigstore-kms-go-plugin"
	PluginPathEnvKey                = "SIGSTORE_GO_PLUGIN_PATH"
	KMSPluginName                   = "sigstore-kms-plugin"
)

var (
	// HandshakeConfig is the configuration for a proper handshake between client and server of the plugin.
	// This is not authentication, but identification.
	HandshakeConfig = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "SIGSTORE_KMS_PLUGIN",
		MagicCookieValue: "sigstore",
	}

	_ SignerVerifier = &SignerVerifierRPC{}
	// _ kms.SignerVerifier = (*SignerVerifierRPC)(nil)
)

type SignerVerifierPlugin struct {
	Impl SignerVerifier
}

func (p *SignerVerifierPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return &SignerVerifierRPCServer{Impl: p.Impl}, nil
}

func (SignerVerifierPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &SignerVerifierRPC{client: c}, nil
}
