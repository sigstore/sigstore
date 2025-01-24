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

// Package encoding has helper functions for encoding and decoding some method arguments and return values.
package encoding

import (
	"context"
	"crypto"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// PackRPCOptions extracts properties of all of opts into struct ready for serializing.
func PackRPCOptions(opts []signature.RPCOption) *common.RPCOptions {
	ctx := context.Background()
	var keyVersion string
	var remoteVerification bool
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyKeyVersion(&keyVersion)
		opt.ApplyRemoteVerification(&remoteVerification)
	}
	var ctxDeadline *time.Time
	if deadline, ok := ctx.Deadline(); ok {
		ctxDeadline = &deadline
	}
	return &common.RPCOptions{
		CtxDeadline:        ctxDeadline,
		KeyVersion:         &keyVersion,
		RemoteVerification: &remoteVerification,
	}
}

// UnpackRPCOptions builds the []signature.RPCOption from common.RPCOptions.
func UnpackRPCOptions(commonOpts *common.RPCOptions) []signature.RPCOption {
	opts := []signature.RPCOption{}
	if commonOpts.CtxDeadline != nil {
		// no need fot his package to cancel the context early,
		// and users may still check if the deadline is exceeded with ctx.Err().
		ctx, _ := context.WithDeadline(context.Background(), *commonOpts.CtxDeadline)
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

// PackMessageOptions extracts properties of all of opts into struct ready for serializing.
func PackMessageOptions(opts []signature.MessageOption) *common.MessageOptions {
	var digest []byte
	var signerOpts crypto.SignerOpts
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}
	var hashFunc *crypto.Hash
	if signerOpts != nil {
		hf := signerOpts.HashFunc()
		hashFunc = &hf
	}
	return &common.MessageOptions{
		Digest:   &digest,
		HashFunc: hashFunc,
	}
}

// UnpackMessageOptions builds the []signature.MessageOption from common.MessageOptions.
func UnpackMessageOptions(commonOpts *common.MessageOptions) []signature.MessageOption {
	opts := []signature.MessageOption{}
	if commonOpts.Digest != nil {
		opts = append(opts, options.WithDigest(*commonOpts.Digest))
	}
	if commonOpts.HashFunc != nil {
		opts = append(opts, options.WithCryptoSignerOpts(*commonOpts.HashFunc))
	}
	return opts
}

// PackSignOptions extracts properties of all of opts into struct ready for serializing,
func PackSignOptions(opts []signature.SignOption) *common.SignOptions {
	rpcOpts := []signature.RPCOption{}
	for _, opt := range opts {
		rpcOpts = append(rpcOpts, opt)
	}
	messageOpts := []signature.MessageOption{}
	for _, opt := range opts {
		messageOpts = append(messageOpts, opt)
	}
	return &common.SignOptions{
		RPCOptions:     *PackRPCOptions(rpcOpts),
		MessageOptions: *PackMessageOptions(messageOpts),
	}
}

// UnpackSignOptions builds the []]signature.SignOption from common.SignOptions.
func UnpackSignOptions(commonOpts *common.SignOptions) []signature.SignOption {
	opts := []signature.SignOption{}
	for _, opt := range UnpackRPCOptions(&commonOpts.RPCOptions) {
		opts = append(opts, opt.(signature.SignOption))
	}
	for _, opt := range UnpackMessageOptions(&commonOpts.MessageOptions) {
		opts = append(opts, opt.(signature.SignOption))
	}
	return opts
}
