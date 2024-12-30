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

// Package handler implements helper functions for plugins written in go.
// It parses arguments  and return values to and from the supplied `SignerVerifier` implementation.
package handler

import (
	"context"
	"io"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
)

// TODO: Additonal methods to be implemented

// DefaultAlgorithm parses arguments and return values to and from the impl.
func DefaultAlgorithm(stdin io.Reader, args *common.DefaultAlgorithmArgs, impl kms.SignerVerifier) (*common.DefaultAlgorithmResp, error) {
	defaultAlgorithm := impl.DefaultAlgorithm()
	resp := &common.DefaultAlgorithmResp{
		DefaultAlgorithm: defaultAlgorithm,
	}
	return resp, nil
}

// CreateKey parses arguments and return values to and from the impl.
func CreateKey(stdin io.Reader, args *common.CreateKeyArgs, impl kms.SignerVerifier) (*common.CreateKeyResp, error) {
	ctx := context.TODO()
	if args.CtxDeadline != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, *args.CtxDeadline)
		defer cancel()
	}
	publicKey, err := impl.CreateKey(ctx, args.Algorithm)
	if err != nil {
		return nil, err
	}
	publicKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
	if err != nil {
		return nil, err
	}
	resp := &common.CreateKeyResp{
		PublicKeyPEM: publicKeyPEM,
	}
	return resp, nil
}

// SignMessage parses arguments and return values to and from the impl.
func SignMessage(stdin io.Reader, args *common.SignMessageArgs, impl kms.SignerVerifier) (*common.SignMessageResp, error) {
	opts := getSignOptions(args.SignOptions)
	signature, err := impl.SignMessage(stdin, opts...)
	if err != nil {
		return nil, err
	}
	resp := &common.SignMessageResp{
		Signature: signature,
	}
	return resp, nil
}
