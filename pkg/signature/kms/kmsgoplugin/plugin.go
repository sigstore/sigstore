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
	"log"
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
	ReferenceScheme = "plugin://"
)

func init() {
	sigkms.AddProvider(ReferenceScheme, func(ctx context.Context, keyResourceID string, _ crypto.Hash, opts ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		return LoadSignerVerifier(ctx, keyResourceID, opts...)
	})
}

// LoadSignerVerifier loads a SignerVerifier that uses the plugin.
func LoadSignerVerifier(ctx context.Context, referenceStr string, opts ...signature.RPCOption) (*common.SignerVerifier, error) {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "kms-plugin",
		Output: os.Stdout,
		Level:  hclog.Warn,
	})
	kmsPluginName := "kms-plugin"
	var pluginMap = map[string]plugin.Plugin{
		kmsPluginName: &common.SignerVerifierPlugin{},
	}
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: common.HandshakeConfig,
		Plugins:         pluginMap,
		Cmd:             exec.Command("../mygreeterplugin/mygreeterplugin"),
		Logger:          logger,
	})
	defer client.Kill()

	rpcClient, err := client.Client()
	if err != nil {
		log.Fatal(err)
	}

	raw, err := rpcClient.Dispense(kmsPluginName)
	if err != nil {
		log.Fatal(err)
	}

	signerVerifier := raw.(common.SignerVerifier)
	return &signerVerifier, nil
}
