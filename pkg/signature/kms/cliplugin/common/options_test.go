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

// Package common defines the JSON schema for plugin arguments and return values.

//go:build !signer_program
// +build !signer_program

package common

import (
	"crypto"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

var (
	testCtxDeadline        = time.Date(2025, 4, 1, 2, 47, 0, 0, time.UTC)
	testKeyVersion         = "anyKeyVersion"
	testRemoteVerification = true
	testRPCOptions         = &RPCOptions{
		CtxDeadline:        &testCtxDeadline,
		KeyVersion:         &testKeyVersion,
		RemoteVerification: &testRemoteVerification,
	}

	testDigest         = []byte("anyDigest")
	testHashFunc       = crypto.BLAKE2b_256
	testMessageOptions = &MessageOptions{
		Digest:   &testDigest,
		HashFunc: &testHashFunc,
	}

	testSignOptions = &SignOptions{
		RPCOptions:     testRPCOptions,
		MessageOptions: testMessageOptions,
	}
)

// TestRPCOptions ensures that the values of the RPCOptions survive json encoding and decoding.
func TestRPCOptions(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(testRPCOptions)
	if err != nil {
		t.Errorf("encoding: %v", err)
	}

	var decodedObj RPCOptions
	if err := json.Unmarshal(encoded, &decodedObj); err != nil {
		t.Errorf("decoding error: %v", err)
	}

	if diff := cmp.Diff(testRPCOptions, &decodedObj); diff != "" {
		t.Errorf("unexpected resp (-want +got):\n%s", diff)
	}
}

// TestMessageOptions ensures that the values of the MessageOptions survive json encoding and decoding.
func TestMessageOptions(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(testMessageOptions)
	if err != nil {
		t.Errorf("encoding: %v", err)
	}

	var decodedObj MessageOptions
	if err := json.Unmarshal(encoded, &decodedObj); err != nil {
		t.Errorf("decoding error: %v", err)
	}

	if diff := cmp.Diff(testMessageOptions, &decodedObj); diff != "" {
		t.Errorf("unexpected resp (-want +got):\n%s", diff)
	}
}

// TestSignOptions ensures that the values of the SignOptions survive json encoding and decoding.
func TestSignOptions(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(testSignOptions)
	if err != nil {
		t.Errorf("encoding: %v", err)
	}

	var decodedObj SignOptions
	if err := json.Unmarshal(encoded, &decodedObj); err != nil {
		t.Errorf("decoding error: %v", err)
	}

	if diff := cmp.Diff(testSignOptions, &decodedObj); diff != "" {
		t.Errorf("unexpected resp (-want +got):\n%s", diff)
	}
}
