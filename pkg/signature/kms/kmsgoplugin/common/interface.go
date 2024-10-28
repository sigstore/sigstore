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
	"context"
	"crypto"
	"net/rpc"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	kmsproto "github.com/sigstore/sigstore/pkg/signature/kms/kmsgoplugin/common/proto"
	"google.golang.org/grpc"
)

const (
	ReferenceScheme                 = "plugin://"
	DefaultPluginBinaryRelativePath = "./sigstore-kms-go-plugin"
	PluginPathEnvKey                = "SIGSTORE_KMS_GO_PLUGIN_PATH"
	KMSPluginName                   = "sigstore-kms-plugin"
	KeyResourceIDEnvKey             = "SIGSTORE_KMS_GO_PLUGIN_KEY_RESOURCE_ID"
	HashFuncEnvKey                  = "SIGSTORE_KMS_GO_PLUGIN_HASH_FUNC"
	PluginProtocolVersion           = 1
)

var (
	// HandshakeConfig is the configuration for a proper handshake between client and server of the plugin.
	// This is not authentication, but identification.
	HandshakeConfig = plugin.HandshakeConfig{
		// ProtocolVersion:  2,
		MagicCookieKey:   "SIGSTORE_KMS_PLUGIN",
		MagicCookieValue: "sigstore",
	}
	PluginMap = map[string]plugin.Plugin{
		KMSPluginName: &SignerVerifierRPCPlugin{},
	}
)

// KMSGoPluginSignerVerifier wraps around kms.KMSGoPluginSignerVerifier
type KMSGoPluginSignerVerifier interface {
	kms.SignerVerifier
	SetState(state *KMSGoPluginState)
}

type KMSGoPluginState struct {
	KeyResourceID string
	HashFunc      crypto.Hash
}

type SignerVerifierRPCPlugin struct {
	plugin.Plugin
	Impl KMSGoPluginSignerVerifier
}

func (p *SignerVerifierRPCPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return &SignerVerifierRPCServer{Impl: p.Impl}, nil
}

func (SignerVerifierRPCPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &SignerVerifierRPC{client: c}, nil
}

// GetKeyResourceIDFromEnv gets the key resource id (plugin://my-key-resource) set by the host process' into an env variable.
func GetKeyResourceIDFromEnv() string {
	return os.Getenv(KeyResourceIDEnvKey)
}

// GetHashFuncFromEnvgets a crypto.Hash from the vale in HashFuncEnvKey.
func GetHashFuncFromEnv() crypto.Hash {
	hashName := os.Getenv(HashFuncEnvKey)
	switch hashName {
	case "SHA256", "sha256":
		return crypto.SHA256
	case "SHA384", "sha384":
		return crypto.SHA384
	case "SHA512", "sha512":
		return crypto.SHA512
	// Add more cases as needed for other hash functions
	default:
		return crypto.SHA256
	}
}

// ServePlugin is a helper function to begins serving your concrete imlementation of the interface.
// This is meant to be imported and called from the plugin program.
// You may optionally provide a hclog.Logger to be used by the server.
func ServePlugin(version int, impl KMSGoPluginSignerVerifier, logger hclog.Logger) {
	var pluginMap = map[string]plugin.Plugin{
		KMSPluginName: &SignerVerifierRPCPlugin{Impl: impl},
		// KMSPluginName: &SignerVerifierGRPCPlugin{Impl: impl},
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		// Plugins:         pluginMap,
		VersionedPlugins: map[int]plugin.PluginSet{
			version: pluginMap,
		},
		// GRPCServer:      plugin.DefaultGRPCServer,
		Logger: logger,
	})
}

func ServeVersionedPlugins(versionedPlugins map[int]plugin.PluginSet, logger hclog.Logger) {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig:  HandshakeConfig,
		VersionedPlugins: versionedPlugins,
		// GRPCServer:      plugin.DefaultGRPCServer,
		Logger: logger,
	})
}

// type KMSService interface {
// 	DefaultAgorithm(ctx context.Context, req *DefaultAlgorithmArgs) (*DefaultAlgorithmResp, error)
// 	SuuportedAlgorithms(ctx context.Context, req *SupportedAlgorithmsArgs) (*SupportedAlgorithmsResp, error)
// 	PublicKey(ctx context.Context, req *PublicKeyArgs) (*PublicKeyResp, error)
// 	CreateKey(ctx context.Context, req *CreateKeyArgs) (*CreateKeyResp, error)
// 	SignMessage(ctx context.Context, req *SignMessageArgs) (*SignMessageResp, error)
// 	VerifySignature(ctx context.Context, req *VerifySignatureArgs) (*VerifySignatureResp, error)
// 	CryptoSigner(ctx context.Context, req *CryptoSignerArgs) (*CryptoSignerResp, error)
// }

// Here is the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	// KMSService
	kmsproto.KMSServiceServer
	// This is the real implementation
	Impl KMSGoPluginSignerVerifier
}

// This is the implementation of plugin.GRPCPlugin so we can serve/consume this.
type SignerVerifierGRPCPlugin struct {
	// GRPCPlugin must still implement the Plugin interface
	plugin.Plugin
	// Concrete implementation, written in Go. This is only used for plugins
	// that are written in Go.
	Impl KMSGoPluginSignerVerifier
}

func (p *SignerVerifierGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	kmsproto.RegisterKMSServiceServer(s, &GRPCServer{Impl: p.Impl})
	return nil
}

func (p *SignerVerifierGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: kmsproto.NewKMSServiceClient(c)}, nil
}

// func (p *SignerVerifierGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
// 	kmsproto.RegisterKMSServiceServer(s, &GRPCServer{Impl: p.Impl})
// 	return nil
// }

// func (p *SignerVerifierGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
// 	return &GRPCClient{client: kmsproto.NewKMSServiceClient(c)}, nil
// }
