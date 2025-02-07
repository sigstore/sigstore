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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/options"
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

	testPublicKeyOptions = &common.PublicKeyOptions{
		RPCOptions: *testRPCOptions,
	}
	testSignOptions = &common.SignOptions{
		RPCOptions:     *testRPCOptions,
		MessageOptions: *testMessageOptions,
	}
	testVerifyOptions = &common.VerifyOptions{
		RPCOptions:     *testRPCOptions,
		MessageOptions: *testMessageOptions,
	}
)

// TestPackRPCOptions ensures that values are extracted from []signature.RPCOption.
func TestPackRPCOptions(t *testing.T) {
	t.Parallel()

	// test values.
	testContext, cancel := context.WithDeadline(context.Background(), testContextDeadline)
	defer cancel()
	opts := []signature.RPCOption{
		options.WithContext(testContext),
		options.WithRemoteVerification(testRemoteVerification),
		options.WithKeyVersion(testKeyVersion),
	}

	rpcOptions := PackRPCOptions(opts)

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

// TestUnpackRPCOptions ensures we can extract all of []signature.RPCOption.
func TestUnpackRPCOptions(t *testing.T) {
	t.Parallel()

	opts := UnpackRPCOptions(testRPCOptions)

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

// TestPackMessageOptions ensures that values are extracted from []signature.MessageOption.
func TestPackMessageOptions(t *testing.T) {
	t.Parallel()

	// test values.
	opts := []signature.MessageOption{
		options.WithDigest(testDigest),
		options.WithCryptoSignerOpts(testHashFunc),
	}

	messageOptions := PackMessageOptions(opts)

	// we use another common.MessageOptions{} so we can conveniently compare all values with a single cmp.Diff().
	wantedMessageOptions := &common.MessageOptions{
		Digest:   &testDigest,
		HashFunc: &testHashFunc,
	}
	if diff := cmp.Diff(wantedMessageOptions, messageOptions); diff != "" {
		t.Errorf("unexpected resp (-want +got):\n%s", diff)
	}
}

// TestUnpackMessageOptions ensures we can extract all of []signature.MessageOption.
func TestUnpackMessageOptions(t *testing.T) {
	t.Parallel()

	opts := UnpackMessageOptions(testMessageOptions)

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

// TestPackPublicKeyOptions ensures that values are extracted from []signature.PublicKeyOption.
func TestPackPublicKeyOptions(t *testing.T) {
	t.Parallel()

	// test values.
	testContext, cancel := context.WithDeadline(context.Background(), testContextDeadline)
	defer cancel()
	opts := []signature.PublicKeyOption{
		options.WithContext(testContext),
		options.WithRemoteVerification(testRemoteVerification),
		options.WithKeyVersion(testKeyVersion),
	}

	publicKeyOptions := PackPublicKeyOptions(opts)

	// we use another common.PublicKeyOptions{} so we can conveniently compare all values with a single cmp.Diff().
	wantedPublicKeyOption := &common.PublicKeyOptions{
		RPCOptions: common.RPCOptions{
			CtxDeadline:        &testContextDeadline,
			KeyVersion:         &testKeyVersion,
			RemoteVerification: &testRemoteVerification,
		},
	}
	if diff := cmp.Diff(wantedPublicKeyOption, publicKeyOptions); diff != "" {
		t.Errorf("unexpected resp (-want +got):\n%s", diff)
	}
}

// TestUnpackPublicKeyOptions ensures we can extract all of []signature.PublicKeyOption.
func TestUnpackPublicKeyOptions(t *testing.T) {
	t.Parallel()

	opts := UnpackPublicKeyOptions(testPublicKeyOptions)

	// extract values from the []signature.PublicKeyOption with the usual methods.
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

// TestPackSignOptions ensures that values are extracted from []signature.SignOption.
func TestPackSignOptions(t *testing.T) {
	t.Parallel()

	// test values.
	testContext, cancel := context.WithDeadline(context.Background(), testContextDeadline)
	defer cancel()
	opts := []signature.SignOption{
		options.WithContext(testContext),
		options.WithRemoteVerification(testRemoteVerification),
		options.WithKeyVersion(testKeyVersion),
		options.WithDigest(testDigest),
		options.WithCryptoSignerOpts(testHashFunc),
	}

	signOptions := PackSignOptions(opts)

	// we use another common.SignOption{} so we can conveniently compare all values with a single cmp.Diff().
	wantedSignOptions := &common.SignOptions{
		RPCOptions: common.RPCOptions{
			CtxDeadline:        &testContextDeadline,
			KeyVersion:         &testKeyVersion,
			RemoteVerification: &testRemoteVerification,
		},
		MessageOptions: common.MessageOptions{
			Digest:   &testDigest,
			HashFunc: &testHashFunc,
		},
	}
	if diff := cmp.Diff(wantedSignOptions, signOptions); diff != "" {
		t.Errorf("unexpected resp (-want +got):\n%s", diff)
	}
}

// TestUnpackSignOptions ensures we can extract all of []signature.SignOption.
func TestUnpackSignOptions(t *testing.T) {
	t.Parallel()

	opts := UnpackSignOptions(testSignOptions)

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

// TestPackVerifyOptions ensures that values are extracted from []signature.VerifyOption.
func TestPackVerifyOptions(t *testing.T) {
	t.Parallel()

	// test values.
	testContext, cancel := context.WithDeadline(context.Background(), testContextDeadline)
	defer cancel()
	opts := []signature.VerifyOption{
		options.WithContext(testContext),
		options.WithRemoteVerification(testRemoteVerification),
		options.WithKeyVersion(testKeyVersion),
		options.WithDigest(testDigest),
		options.WithCryptoSignerOpts(testHashFunc),
	}

	verifyOptions := PackVerifyOptions(opts)

	// we use another common.VerifyOptions{} so we can conveniently compare all values with a single cmp.Diff().
	wantedSignOptions := &common.VerifyOptions{
		RPCOptions: common.RPCOptions{
			CtxDeadline:        &testContextDeadline,
			KeyVersion:         &testKeyVersion,
			RemoteVerification: &testRemoteVerification,
		},
		MessageOptions: common.MessageOptions{
			Digest:   &testDigest,
			HashFunc: &testHashFunc,
		},
	}
	if diff := cmp.Diff(wantedSignOptions, verifyOptions); diff != "" {
		t.Errorf("unexpected resp (-want +got):\n%s", diff)
	}
}

// TestUnpackVerifyOptions ensures we can extract all of []signature.VerifyOption.
func TestUnpackVerifyOptions(t *testing.T) {
	t.Parallel()

	opts := UnpackVerifyOptions(testVerifyOptions)

	// extract values from the []signature.VerifyOption with the usual methods.
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
