// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/sigstore/sigstore/pkg/signature/kms/fake"
	"github.com/sigstore/sigstore/pkg/signature/kms/kmsgoplugin/common"
)

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

	// You can use the KeyResourceID
	logger.Info(
		"env",
		common.KeyResourceIDEnvKey, common.GetKeyResourceID(),
	)

	common.ServePlugin(fakeSV, logger)
}
