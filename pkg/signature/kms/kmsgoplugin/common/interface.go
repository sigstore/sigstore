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
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	kmsproto "github.com/sigstore/sigstore/pkg/signature/kms/kmsgoplugin/common/proto"
)

const (
	DefaultPluginBinaryRelativePath = "./sigstore-kms-go-plugin"
	PluginPathEnvKey                = "SIGSTORE_GO_PLUGIN_PATH"
	KMSPluginName                   = "sigstore-kms-plugin"
	KeyResourceIDEnvKey             = "KMS_PLUGIN_KEY_RESOURCE_ID"
)

var (
	// HandshakeConfig is the configuration for a proper handshake between client and server of the plugin.
	// This is not authentication, but identification.
	HandshakeConfig = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "SIGSTORE_KMS_PLUGIN",
		MagicCookieValue: "sigstore",
	}
)

// SignerVerifier wraps around kms.SignerVerifier
type SignerVerifier interface {
	kms.SignerVerifier
}

type SignerVerifierRPCPlugin struct {
	plugin.Plugin
	Impl SignerVerifier
}

func (p *SignerVerifierRPCPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return &SignerVerifierRPCServer{Impl: p.Impl}, nil
}

func (SignerVerifierRPCPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &SignerVerifierRPC{client: c}, nil
}

// GRPCClient is an implementation of Greeter that talks over RPC.
type GRPCClient struct {
	SignerVerifier
	client kmsproto.KMSServiceClient
}

// GetKeyResourceID gets the key reosurce id (plugin://my-key-resource) set by the host process' into an env variable.
func GetKeyResourceID() string {
	return os.Getenv(KeyResourceIDEnvKey)
}

// ServePlugin is a helper function to begins serving your concrete imlementation of the interface.
// You may optionally provide a hclog.Logger to be used by the server.
func ServePlugin(impl SignerVerifier, logger hclog.Logger) {
	var pluginMap = map[string]plugin.Plugin{
		KMSPluginName: &SignerVerifierRPCPlugin{Impl: impl},
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins:         pluginMap,
		Logger:          logger,
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

// // Here is the gRPC server that GRPCClient talks to.
// type GRPCServer struct {
// 	// KMSService
// 	// This is the real implementation
// 	Impl SignerVerifier
// }

// // This is the implementation of plugin.GRPCPlugin so we can serve/consume this.
// type SignerVerifierGRPCPlugin struct {
// 	// GRPCPlugin must still implement the Plugin interface
// 	plugin.Plugin
// 	// Concrete implementation, written in Go. This is only used for plugins
// 	// that are written in Go.
// 	Impl SignerVerifier
// }

// func (p *SignerVerifierGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
// 	kmsproto.RegisterKMSServiceServer(s, &GRPCServer{Impl: p.Impl})
// 	return nil
// }

// func (p *SignerVerifierGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
// 	return &GRPCClient{client: kmsproto.NewKMSServiceClient(c)}, nil
// }

// func (p *SignerVerifierGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
// 	kmsproto.RegisterKMSServiceServer(s, &GRPCServer{Impl: p.Impl})
// 	return nil
// }

// func (p *SignerVerifierGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
// 	return &GRPCClient{client: kmsproto.NewKMSServiceClient(c)}, nil
// }
