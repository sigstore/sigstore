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

// Package handler implements helper functions for plugins written in go. It will extract
// values from PluginArgs and pass them the a real SignerVerifier implementation, and then package
// responses into PluginResp.
package handler

import (
	"context"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// getRPCOptions builds the []signature.RPCOption from common.RPCOptions.
func getRPCOptions(commonOpts *common.RPCOptions) []signature.RPCOption {
	opts := []signature.RPCOption{}
	if commonOpts.CtxDeadline != nil {
		ctx, cancel := context.WithDeadline(context.TODO(), *commonOpts.CtxDeadline)
		defer cancel()
		opts = append(opts, options.WithContext(ctx))
	}
	if commonOpts.KeyVersion != nil {
		opts = append(opts, options.WithKeyVersion(*commonOpts.KeyVersion))
	}
	if commonOpts.RemoteVerification != nil {
		opts = append(opts, options.WithRemoteVerification(*commonOpts.RemoteVerification))
	}
	return opts
}

// getRPCOptions builds the []signature.MessageOption from common.MessageOptions.
func getMessageOptions(commonOpts *common.MessageOptions) []signature.MessageOption {
	opts := []signature.MessageOption{}
	if commonOpts.Digest != nil {
		opts = append(opts, options.WithDigest(*commonOpts.Digest))
	}
	if commonOpts.HashFunc != nil {
		opts = append(opts, options.WithCryptoSignerOpts(*commonOpts.HashFunc))
	}
	return opts
}

// getSignOptions builds the []]signature.SignOption from common.SignOptions.
func getSignOptions(commonOpts *common.SignOptions) []signature.SignOption {
	opts := []signature.SignOption{}
	for _, opt := range getRPCOptions(commonOpts.RPCOptions) {
		opts = append(opts, opt.(signature.SignOption))
	}
	for _, opt := range getMessageOptions(commonOpts.MessageOptions) {
		opts = append(opts, opt.(signature.SignOption))
	}
	return opts
}
