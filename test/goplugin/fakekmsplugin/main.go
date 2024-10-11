// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/sigstore/sigstore/pkg/signature/kms/fake"
	"github.com/sigstore/sigstore/pkg/signature/kms/kmsgoplugin/common"
)

// Here is a real implementation of Greeter
type SignerVerifier struct {
	*fake.SignerVerifier
	logger hclog.Logger
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Info,
		Output:     os.Stderr,
		JSONFormat: true,
	})

	fakeSV, err := fake.LoadSignerVerifier(context.TODO(), crypto.SHA256)
	if err != nil {
		panic(err)
	}
	signerVerifier := &SignerVerifier{
		fakeSV,
		logger,
	}

	// pluginMap is the map of plugins we can dispense.
	var pluginMap = map[string]plugin.Plugin{
		common.KMSPluginName: &common.SignerVerifierPlugin{Impl: signerVerifier},
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: common.HandshakeConfig,
		Plugins:         pluginMap,
		Logger:          logger,
	})
}
