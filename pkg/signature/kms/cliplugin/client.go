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

// Package cliplugin implements the plugin functionality.
package cliplugin

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
)

const (
	// PluginBinaryPrefix is the prefix for all plugin binaries. e.g., sigstore-kms-my-hsm.
	PluginBinaryPrefix = "sigstore-kms-"
)

var (
	ErrorInputKeyResourceID = errors.New("parsing input key resource id")
)

// init registers the plugin system as a provider. It does not search for plugin programs.
// Users must import this package, e.g.,  `import _ "github.com/sigstore/sigstore/pkg/signature/kms/cliplugin"`
func init() {
	kms.AddProvider(kms.CLIPluginProviderKey, func(ctx context.Context, keyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (kms.SignerVerifier, error) {
		return LoadSignerVerifier(ctx, keyResourceID, hashFunc, opts...)
	})
}

// LoadSignerVerifier creates a PluginClient with these InitOptions.
func LoadSignerVerifier(ctx context.Context, inputKeyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (kms.SignerVerifier, error) {
	executable, keyResourceID, err := getPluginExecutableAndKeyResourceID(inputKeyResourceID)
	if err != nil {
		return nil, err
	}
	initOptions := &common.InitOptions{
		ProtocolVersion: common.ProtocolVersion,
		KeyResourceID:   keyResourceID,
		HashFunc:        hashFunc,
		// TODO: include extracted values from opts
	}
	if deadline, ok := ctx.Deadline(); ok {
		initOptions.CtxDeadline = &deadline
	}
	pluginClient := newPluginClient(executable, initOptions, makeCommand)
	return pluginClient, nil
}

func getPluginExecutableAndKeyResourceID(inputKeyResourceID string) (string, string, error) {
	parts := strings.SplitN(inputKeyResourceID, "://", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("%w: expected format: [plugin name]://[key ref], got: %s", ErrorInputKeyResourceID, inputKeyResourceID)
	}
	pluginName, keyResourceID := parts[0], parts[1]
	executable := PluginBinaryPrefix + pluginName
	return executable, keyResourceID, nil
}
