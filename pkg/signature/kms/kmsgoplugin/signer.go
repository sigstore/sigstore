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

// Package kmsgoplugin implements the interface to access various kms services
// using the github.com/hashicorp/go-plugin framework.
package kmsgoplugin

import (
	"context"
	"crypto"
	"os"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/sigstore/sigstore/pkg/signature"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/kmsgoplugin/common"
)

const (
	// ReferenceScheme is a scheme for fake KMS keys. Do not use in production.
	ReferenceScheme = common.ReferenceScheme
)

var ()

func init() {
	sigkms.AddProvider(ReferenceScheme, func(ctx context.Context, keyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		os.Setenv(common.KeyResourceIDEnvKey, keyResourceID)
		os.Setenv(common.HashFuncEnvKey, hashFunc.String())
		return LoadSignerVerifier(ctx, keyResourceID)
	})
}

// CleanupClients calls plugin.CleanupClients to kill the plugin programs.
func CleanupClients() {
	plugin.CleanupClients()
}

// LoadSignerVerifier loads a SignerVerifier that uses the plugin.
func LoadSignerVerifier(ctx context.Context, referenceStr string) (common.KMSGoPluginSignerVerifier, error) {
	// kmsPluginName := common.KMSPluginNameRPC
	version := common.PluginProtocolVersion
	version += 1

	kmsPluginName := common.KMSPluginNameRPC
	pluginMap := common.RPCPluginMap
	if version == common.PluginProtocolVersion+1 {
		kmsPluginName = common.KMSPluginNameGRPC
		pluginMap = common.GRPCPluginMap
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Name:  kmsPluginName,
		Level: hclog.Debug,
	})

	pluginPath := getPluginPath()
	client := plugin.NewClient(&plugin.ClientConfig{
		Managed:         true,
		HandshakeConfig: common.HandshakeConfig,
		// Plugins:         pluginMap,
		VersionedPlugins: map[int]plugin.PluginSet{
			version: pluginMap,
		},
		Cmd:              exec.Command(pluginPath),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC, plugin.ProtocolNetRPC},
		Logger:           logger,
		AutoMTLS:         true,
	})

	rpcClient, err := client.Client()
	if err != nil {
		return nil, err
	}

	raw, err := rpcClient.Dispense(kmsPluginName)
	if err != nil {
		return nil, err
	}
	// signerVerifier := raw.(*common.GRPCClient)
	// signerVerifier := raw.(*common.SignerVerifierRPC)
	signerVerifier := raw.(common.KMSGoPluginSignerVerifier)
	signerVerifier.SetState(&common.KMSGoPluginState{
		KeyResourceID: referenceStr,
		HashFunc:      crypto.SHA256,
	})

	// signerVerifier.SignerOpts = crypto.SHA256

	// signer, _, err := signerVerifier.CryptoSigner(ctx, func(err error) {
	// 	slog.Error(err.Error())
	// })
	// if err != nil {
	// 	panic(err)
	// }
	// slog.Info(fmt.Sprintf("%v", signer.Public()))

	return signerVerifier, nil
}

// getPluginPath returns the path of the plugin binary depending on whether common.PluginPathEnvKey is set,
// otherwise it returns common.DefaultPluginBinaryRelativePath.
func getPluginPath() string {
	if pluginPathEnvVal := os.Getenv(common.PluginPathEnvKey); pluginPathEnvVal != "" {
		return pluginPathEnvVal
	}
	return common.DefaultPluginBinaryRelativePath
}
