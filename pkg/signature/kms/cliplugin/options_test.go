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

//go:build !signer_program
// +build !signer_program

package cliplugin

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// TestGetRPCOptions ensures that values are extracted from []signature.RPCOption.
func TestGetRPCOptions(t *testing.T) {
	t.Parallel()

	// test values.
	testContext, _ := context.WithDeadline(context.Background(), testContextDeadline)
	opts := []signature.RPCOption{
		options.WithContext(testContext),
		options.WithRemoteVerification(testRemoteVerification),
		options.WithKeyVersion(testKeyVersion),
	}

	// call getRPCOptions().
	rpcOptions := getRPCOptions(&testContext, opts)

	// we use another common.RPCOptions{} so we can conveniently compare all values with a single cmp.Diff().
	wantedRPCOptions := &common.RPCOptions{
		CtxDeadline:        &testContextDeadline,
		KeyVersion:         &testKeyVersion,
		RemoteVerification: &testRemoteVerification,
	}
	if diff := cmp.Diff(wantedRPCOptions, rpcOptions); diff != "" {
		t.Errorf("unexpected resp (-want +got):\n%s", diff)
	}
}

// TestGetMessageOptions ensures that values are extracted from []signature.MessageOption.
func TestGetMessageOptions(t *testing.T) {
	t.Parallel()

	// test values.
	opts := []signature.MessageOption{
		options.WithDigest(testDigest),
		options.WithCryptoSignerOpts(testHashFunction),
	}

	// call getRPCOptions().
	messageOptions := getMessageOptions(opts)

	// we use another common.MessageOptions{} so we can conveniently compare all values with a single cmp.Diff().
	wantedMessageOptions := &common.MessageOptions{
		Digest:   &testDigest,
		HashFunc: &testHashFunction,
	}
	if diff := cmp.Diff(wantedMessageOptions, messageOptions); diff != "" {
		t.Errorf("unexpected resp (-want +got):\n%s", diff)
	}
}

// TestGetMessageOptions ensures that values are extracted from []signature.MessageOption.
func TestGetSignOption(t *testing.T) {
	t.Parallel()

	// test values.
	testContext, _ := context.WithDeadline(context.Background(), testContextDeadline)
	opts := []signature.SignOption{
		options.WithContext(testContext),
		options.WithRemoteVerification(testRemoteVerification),
		options.WithKeyVersion(testKeyVersion),
		options.WithDigest(testDigest),
		options.WithCryptoSignerOpts(testHashFunction),
	}

	// call getRPCOptions().
	signOptions := getSignOptions(&testContext, opts)

	// we use another common.SignOption{} so we can conveniently compare all values with a single cmp.Diff().
	wantedSignOptions := &common.SignOptions{
		RPCOptions: &common.RPCOptions{
			CtxDeadline:        &testContextDeadline,
			KeyVersion:         &testKeyVersion,
			RemoteVerification: &testRemoteVerification,
		},
		MessageOptions: &common.MessageOptions{
			Digest:   &testDigest,
			HashFunc: &testHashFunction,
		},
	}
	if diff := cmp.Diff(wantedSignOptions, signOptions); diff != "" {
		t.Errorf("unexpected resp (-want +got):\n%s", diff)
	}
}
