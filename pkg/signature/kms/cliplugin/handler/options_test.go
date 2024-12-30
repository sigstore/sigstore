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

//go:build !signer_program
// +build !signer_program

package handler

import (
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
)

var (
	testContextDeadline    = time.Date(2025, 4, 1, 2, 47, 0, 0, time.UTC)
	testKeyVersion         = "my-key-version"
	testRemoteVerification = true
	testRPCOptions         = &common.RPCOptions{
		CtxDeadline:        &testContextDeadline,
		KeyVersion:         &testKeyVersion,
		RemoteVerification: &testRemoteVerification,
	}

	testDigest         = []byte("anyDigest")
	testHashFunc       = crypto.BLAKE2b_256
	testMessageOptions = &common.MessageOptions{
		Digest:   &testDigest,
		HashFunc: &testHashFunc,
	}

	testSignOptions = &common.SignOptions{
		RPCOptions:     testRPCOptions,
		MessageOptions: testMessageOptions,
	}
)

// TestGetRPCOptions ensures getRPCOptions can extract all of []signature.RPCOption.
func TestGetRPCOptions(t *testing.T) {
	t.Parallel()

	// call getRPCOptions().
	opts := getRPCOptions(testRPCOptions)

	// extract values from the []signature.RPCOption with the usual methods.
	ctx := context.Background()
	var keyVersion string
	var remoteVerification bool
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyKeyVersion(&keyVersion)
		opt.ApplyRemoteVerification(&remoteVerification)
	}

	// test equality.
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Error("expected a context deadline")
	}
	if diff := cmp.Diff(testContextDeadline, deadline); diff != "" {
		t.Errorf("unexpected deadline (-want +got): \n%s", diff)
	}
	if diff := cmp.Diff(testKeyVersion, keyVersion); diff != "" {
		t.Errorf("unexpected keyVersion (-want +got): \n%s", diff)
	}
	if diff := cmp.Diff(testRemoteVerification, remoteVerification); diff != "" {
		t.Errorf("unexpected remoteVerification (-want +got): \n%s", diff)
	}
}

// TestGetMessageOptions ensures getMessageCOptions can extract all of []signature.MessageOption.
func TestGetMessageOptions(t *testing.T) {
	t.Parallel()

	// call getMessageOptions().
	opts := getMessageOptions(testMessageOptions)

	// extract values from the []signature.RPCOption with the usual methods.
	digest := []byte{}
	var signerOpts crypto.SignerOpts
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	// test equality.
	if diff := cmp.Diff(testDigest, digest); diff != "" {
		t.Errorf("unexpected digest (-want +got): \n%s", diff)
	}
	if diff := cmp.Diff(testHashFunc, signerOpts.HashFunc()); diff != "" {
		t.Errorf("unexpected hashFunc (-want +got): \n%s", diff)
	}
}

// TestGetSignOptopns ensures getSignCOptions can extract all of []signature.SignOption.
func TestGetSignOptopns(t *testing.T) {
	t.Parallel()

	// call getSignOptions().
	opts := getSignOptions(testSignOptions)

	// extract values from the []signature.SignOption with the usual methods.
	ctx := context.Background()
	var keyVersion string
	var remoteVerification bool
	var digest []byte
	var signerOpts crypto.SignerOpts
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyKeyVersion(&keyVersion)
		opt.ApplyRemoteVerification(&remoteVerification)
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	// test equality.
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Error("expected a context deadline")
	}
	if diff := cmp.Diff(testContextDeadline, deadline); diff != "" {
		t.Errorf("unexpected deadline (-want +got): \n%s", diff)
	}
	if diff := cmp.Diff(testKeyVersion, keyVersion); diff != "" {
		t.Errorf("unexpected keyVersion (-want +got): \n%s", diff)
	}
	if diff := cmp.Diff(testRemoteVerification, remoteVerification); diff != "" {
		t.Errorf("unexpected remoteVerification (-want +got): \n%s", diff)
	}
	if diff := cmp.Diff(testDigest, digest); diff != "" {
		t.Errorf("unexpected digest (-want +got): \n%s", diff)
	}
	if diff := cmp.Diff(testHashFunc, signerOpts.HashFunc()); diff != "" {
		t.Errorf("unexpected hashFunc (-want +got): \n%s", diff)
	}
}
